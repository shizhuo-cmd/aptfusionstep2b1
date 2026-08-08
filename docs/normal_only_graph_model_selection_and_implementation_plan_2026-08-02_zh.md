# Normal-Only 任务图模型选型与实施方案（2026-08-02）

## 1. 为什么现在要换模型

当前 normal-only 主线不是传统的监督式 GraphSAGE 分类器，而是：进程序列表征和安全语义统计 -> 正常任务图原型/局部异常分数 -> 良性验证分位阈值。它已经能在 CADETS 和 TRACE 上得到可用结果，但仍有三个结构性缺口：

1. 当前最终分数没有系统利用父进程到子进程的方向。
2. 进程表征主要来自 TAPAS 的 LSTM-GRU；它原本应通过预测下一事件向量获得，而此前的 checkpoint 和训练协议并不完全可审计。
3. 局部异常由 Top-K 节点分数聚合，尚不能区分“同样的节点集合但父子协作方式不同”的任务。

因此下一阶段不应直接再调阈值，也不应把旧式二分类 GraphSAGE 拉回 normal-only 主线；应增加一个仅从良性任务图学习的、方向感知的图表征与重建分支。

## 2. 已核验的候选模型与代码

| 候选 | 论文/代码 | 可借鉴部分 | 与当前任务的匹配度 | 决策 |
| --- | --- | --- | --- | --- |
| GraphMAE | [论文](https://arxiv.org/abs/2205.10803)，[官方代码](https://github.com/THUDM/GraphMAE) | 掩码节点特征重建、自监督 encoder/decoder、mini-batch 图训练 | 高：只需良性图，特征重建按节点/边线性扩展 | 主线 |
| Dir-GNN | [PyG DirGNNConv 文档](https://pytorch-geometric.readthedocs.io/en/latest/generated/torch_geometric.nn.conv.DirGNNConv.html)，[PyG 代码](https://github.com/pyg-team/pytorch_geometric) | 把入边和出边消息分开编码后再融合 | 高：直接对应进程父子边方向，项目已使用 PyG | GraphMAE 的编码器骨干 |
| GAD-NR | [PyGOD 实现](https://github.com/pygod-team/pygod/blob/main/pygod/detector/gadnr.py) | 邻域分布重建，避免直接重建完整邻接矩阵 | 中高：可作为方向图邻域重建的对照 | 第二条对照线 |
| DOMINANT | [PyGOD 实现](https://github.com/pygod-team/pygod/blob/main/pygod/detector/dominant.py) | 属性与结构重建双分数 | 中：思想有参考价值 | 不作为默认实现 |
| CoLA | [论文实现](https://github.com/TrustAGI-Lab/CoLA) | 节点-子图对比学习、局部异常分数 | 中：适合局部异常，但随机子图采样会增加任务图切分噪声 | 预留为后续消融 |
| Deep SVDD / 一类原型 | [PyGOD](https://github.com/pygod-team/pygod) | 仅正常数据的距离分数 | 低到中：不保留父子结构 | 维持为现有 KMeans/原型基线，不单独扩展 |

### 为什么不直接使用 DOMINANT

DOMINANT 的结构重建通常需要重建节点间邻接关系。CADETS 存在超大任务图，若把一个 `n` 节点任务的所有节点对作为候选，复杂度接近 `O(n^2)`，会让大根图成为训练和显存瓶颈。GraphMAE 的掩码特征重建以及 GAD-NR 的邻域分布重建可围绕实际边处理，更符合当前图规模分布。

### 为什么不用“无向化后直接套 GraphMAE”

进程边的语义是“父进程创建/派生子进程”。无向化会把启动链和回溯链混为同一种邻居。`DirGNNConv` 可以在每层分别聚合父方向和子方向的信息，再以可配置权重融合；这正好能检验方向信息是否真的有增益。

## 3. 建议主模型：Dir-GraphMAE-Normal

### 3.1 输入

每张任务图保持当前 module1 的节点和父 -> 子边，不重新切图。节点初始特征分三部分：

1. `42` 维 TAPAS LSTM-GRU 过程表示。优先使用论文参数对齐、仅由良性训练进程拟合的 checkpoint。
2. 当前安全语义统计特征。统计旁路保留为独立标准化通道，不能无条件拼接到序列表征。
3. 可选的下一事件预测误差。该误差必须先在良性验证集上校准，不能把攻击标签用于权重选择。

所有节点特征只用良性训练图拟合标准化器；验证集、测试集只能使用冻结的变换器。

### 3.2 方向编码器

采用两层 `DirGNNConv(GINConv)`，而不是自行实现一套方向传播。这里的 `DirGNNConv` 是方向包装器，`GINConv` 才是每个方向内的聚合算子：

```text
父节点 -> 当前节点的消息: incoming branch
当前节点 -> 子节点的消息: outgoing branch
两支表示按 alpha 融合 -> LayerNorm -> GELU -> Dropout
```

建议首轮固定隐藏维 `64`、两层、`alpha=0.5`、dropout `0.1`。`GINConv` 内部使用两层 MLP，使“父/子邻居多重集合”可与简单均值聚合区分；不在首轮同时调层数、宽度和复杂注意力，避免与任务切图、序列表征变化混淆。

### 3.3 GraphMAE 重建目标

训练时只从 normal-only 训练时间段的良性任务图采样：

1. 每张图随机掩码 `30%` 节点特征；掩码 token 由可学习向量替代。
2. Dir-GNN encoder 输出节点表示。
3. 轻量 MLP decoder 重建被掩码节点的原始标准化特征。
4. 损失仅计算被掩码节点的余弦/均方误差，不重建完整邻接矩阵。
5. 训练时按图批处理，按节点数加权但限制单张超大图占一个 batch 的比例。

与 GraphMAE 官方实现一致的核心是“掩码后重建节点属性”；本项目的改动仅是将 encoder 换成已开源的方向卷积，并将数据单位从单个引用图换为多个 PyG `Data` 任务图。

### 3.4 推理分数

单一重建误差容易受随机掩码影响。推理采用固定随机种子下的 `K=4` 组掩码并取均值，得到每个节点的重建误差。任务分数保持可解释：

```text
task_score =
  a * graph_embedding_distance_to_normal_prototypes
+ b * mean_topk(node_reconstruction_errors)
+ c * calibrated_next_event_error
```

其中：

- `graph_embedding_distance_to_normal_prototypes`：对 pooled 图表示做 KMeans 或 KNN 正常原型距离；复用现有正常建模接口。
- `mean_topk`：继续使用自适应 Top-K，`k=min(ceil(sqrt(node_count)), 16)`，避免大图由大量低风险节点稀释。
- `calibrated_next_event_error`：首轮设为 `c=0`，只作为诊断保存；只有其单独消融稳定增益后才加入。
- `a,b,c` 不能由攻击测试图调参，只能由良性验证分数的稳健尺度和预注册候选表确定。

阈值继续采用良性验证分位数（1%、2%、5% 各自单列），而非用已知攻击图选阈值。

## 4. 受控实验路线

### G0：复现锚点

保留当前最佳 normal-only 路线：论文参数对齐的 LSTM-GRU + 安全语义统计 + KMeans + 自适应 Top-K。CADETS、TRACE 分别独立拟合，均不运行 module0、不使用数据增强、不用攻击图训练。

### G1：只验证方向编码是否有价值

将当前节点特征送入两层 `DirGNNConv(GINConv)`，但不使用掩码重建；仅用 pooled 图表示加现有正常原型距离评分。主对照使用相同宽度的 `GINConv(to_undirected(edge_index))`，从而只检验“保留父子方向”是否有价值。若方向版有收益，再补一个 `DirGNNConv(SAGEConv)`，用于确认收益不是 GIN 聚合器替换造成的。

### G2：Dir-GraphMAE

在 G1 的方向编码器基础上加入掩码节点特征重建和局部重建误差。该阶段只改自监督目标，不改变切图、序列输入、统计定义或阈值协议。

### G3：GAD-NR 对照

参考 PyGOD GAD-NR 的邻域分布重建思想，把每个节点的父邻域和子邻域分别重建，比较它和 GraphMAE 的局部异常分数。若 G2 未改善而 G3 改善，说明问题更可能在“邻域结构”而不是节点特征缺失。

### G4：可选 CoLA 局部对照

仅在 G2/G3 仍存在“少数恶意节点埋在巨大良性图中”的漏报时实施。每个任务图内采样受方向约束的局部子图，进行节点-上下文对比；不跨任务随机拼接子图。

## 5. 固定实验协议

| 项目 | 固定要求 |
| --- | --- |
| 数据集 | CADETS 与 TRACE 都必须跑；结果分别报告，不混合训练或共用阈值 |
| 训练数据 | 仅正常训练时间段的良性任务图；攻击图不参与表征、重建器、原型或阈值训练 |
| 模块范围 | 只运行 module1/module2；严禁运行 module0 |
| 任务切图 | 首轮固定现有 fanout 配置，不把切图变化混入模型实验 |
| 数据增强 | 禁用。自监督特征掩码仅用于 GraphMAE 训练，不属于复制任务图的数据增强 |
| 评估 | Macro precision/recall/F1、PR-AUC、ROC-AUC、TP/FP/FN、每张误报/漏报任务图 |
| 校准 | 1%、2%、5% 良性验证 FPR 并列报告；不以攻击图选择阈值 |
| 失败处理 | artifact 根目录加 `_failed_`，保留日志和失败原因，不覆盖成功基线 |

## 6. 通过门槛与停止条件

G1/G2/G3 的某条路线要进入下一步，必须同时满足：

1. CADETS 与 TRACE 的 Macro F1 都不低于各自 G0 超过 `0.02`。
2. 两个数据集任一都不能出现 GT 召回下降，同时没有明确的误报收益。
3. 至少一个数据集的 TP/FP/FN 有可解释改善，且逐图审计能对应到父子链、异常节点或事件序列差异。
4. CADETS 超大图的单图显存和耗时不出现二次增长；若出现，停止该实现并转向 GAD-NR/局部采样。

如果 G1 已无收益，先停止复杂 GraphMAE 实施，回到输入/切图/校准问题；不要因为“模型更复杂”继续叠加层数。若 G1 有方向收益而 G2 无收益，则保留方向 encoder、放弃特征掩码重建。若 G2 有收益而 G3 无收益，则优先保留更简单的 Dir-GraphMAE。

## 7. 当前执行顺序

当前正在完成 TRACE 的 TAPAS 参数对齐训练步数复验，以确定可靠的过程表征基线。该复验结束后，按 `G0 -> G1 -> G2 -> G3` 顺序实施；每一步先在 CADETS、TRACE 两边完成 module1/module2 对照与逐图审计，再决定是否进入下一步。
