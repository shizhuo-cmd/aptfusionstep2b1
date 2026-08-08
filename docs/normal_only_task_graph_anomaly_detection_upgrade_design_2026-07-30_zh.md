# APT-Fusionstep2b1 良性样本任务图异常检测改造与实验方案

## 1. 文档目的

本文档用于长期保存 `APT-Fusionstep2b1` 良性样本任务图异常检测方向的完整上下文，避免后续因对话压缩、人员切换或实验间隔而丢失关键设计依据。

本文档包含：

- 当前代码真正实现了什么；
- 当前 TRACE 和 CADETS 实验暴露了什么问题；
- 为什么需要调整现有方案；
- 推荐的分阶段改造路线；
- 每个阶段的模型结构、输入、训练目标、异常分数和阈值策略；
- 可直接参考的论文、官方代码和许可证；
- 代码接入位置和建议配置项；
- 实验矩阵、验收指标和失败回退方式；
- 明确不建议直接采用的方案及原因。

本文档是设计与实施依据，不表示其中所有能力已经实现。每完成一个阶段，应在本文档的“实施记录”章节补充 commit、artifact、指标和结论。

## 目录

1. 文档目的
2. 参考材料
3. 当前代码基线
4. 当前实验结果与问题诊断
5. 总体改造原则
6. 分阶段实施路线
7. 推荐主模型
8. 开源模型与代码参考
9. 代码接入设计
10. 实验矩阵
11. 评估指标
12. 固定诊断产物
13. 成功与失败判定
14. 风险与应对
15. 明确不建议的做法
16. 推荐的最近实施顺序
17. 实施记录模板
18. 当前结论

## 2. 参考材料

本次设计综合参考以下两份本地文档：

- `D:\download\normal_only_process_task_subgraph_redesign_en.md`
- `D:\download\normal-only_process_task_subgraph_anomaly_detection_design.md`

两份文档的共同主张是：

- 训练过程只使用良性任务图；
- 保留现有进程历史行为表示；
- 用有向图模型学习父进程和子进程之间的正常关系；
- 通过掩码重建、下一行为预测或父子行为预测产生局部异常证据；
- 同时保留任务图级的全局异常距离；
- 只使用良性校准数据选择阈值；
- 最终同时输出图级判断和可定位到具体进程的异常证据。

本方案接受这些总体方向，但根据当前实际实验结果调整了实施优先级：

1. 先修阈值与评估协议；
2. 再增强现有表示上的异常评分；
3. 然后引入有向图自监督学习；
4. 最后加入跨任务关联。

原因是当前 TRACE 的异常排序已经很好，但阈值导致所有恶意图未触发告警。如果不先修校准，即使换成更复杂的图模型，也可能继续得到“排序很好但最终召回为 0”的结果。

## 3. 当前代码基线

### 3.1 代码版本

本文档编写时的本地代码基线：

- 仓库：`D:\daima\APT-Fusionstep2b1`
- Git commit：`e2c97a2`
- 当前未跟踪目录：`debug/remote_ops/out/`

本文档本身不修改任务图构造、任务图检测或攻击战术分析代码。

### 3.2 当前 normal-only 分支的真实结构

当前良性样本检测入口位于：

- `src/apt_fusion/task_detection/tapas_native_backend.py`
- 主要函数：`_run_normal_only_tc3()`
- 配置定义：`src/apt_fusion/config.py`

当前分支没有训练或调用 GraphSAGE，也没有调用 XGBoost。它使用 module1 已经生成的进程行为表示，构造两级原型距离：

#### 节点级正常原型

- 汇总良性训练任务图中的所有进程向量；
- 使用 `StandardScaler` 标准化；
- 使用 `MiniBatchKMeans` 拟合节点正常原型；
- 默认节点原型数为 32；
- 对每个进程，取它到最近正常原型的欧氏距离；
- 对每张任务图，取距离最大的 3 个进程并求平均，作为局部异常分数。

#### 图级正常原型

当前每张任务图的全局特征由以下部分直接拼接：

- 根进程向量；
- 所有进程向量均值；
- 所有进程向量逐维最大值；
- 节点数量的对数；
- 边数量的对数；
- 根节点是否位于第一个位置。

随后：

- 使用 `StandardScaler` 标准化；
- 使用 `MiniBatchKMeans` 拟合图级正常原型；
- 默认图原型数为 8；
- 到最近图原型的距离作为全局异常分数。

#### 分数融合

局部分数和全局分数分别使用良性验证集的中位数和 MAD 做稳健归一化。

当前最终分数为：

```text
最终分数 = 0.60 × 局部异常分数 + 0.40 × 全局异常分数
```

默认参数：

| 参数 | 当前值 |
|---|---:|
| 良性训练比例 | 0.70 |
| 良性验证比例 | 0.15 |
| 节点原型数 | 32 |
| 图级原型数 | 8 |
| 局部 Top-K | 3 |
| 全局分数权重 | 0.40 |
| 目标验证误报率 | 0.01 |

### 3.3 当前数据划分

当前划分方式是：

1. 将全部良性任务图按时间排序；
2. 最早 70% 用于训练；
3. 接下来 15% 用于分数归一化和阈值选择；
4. 剩余良性任务图用于最终评估；
5. 所有已知恶意任务图只放入最终评估；
6. 恶意图不参与训练；
7. 恶意图不参与阈值选择。

这一原则是正确的，应继续保留。

当前不足是：验证集只是一个连续但较小的时间片，没有进一步处理正常行为的时间漂移、任务类型差异和极端尾部样本。

## 4. 当前实验结果与问题诊断

本节数值来自 2026-07-30 的 TRACE/CADETS normal-only module1/module2 实验。云端运行与汇总目录为：

```text
/root/autodl-tmp/APT-Fusionstep2b1/debug/remote_ops/out/normal_only_trace_cadets_module12_20260730
```

这些数值用于工程决策。正式写入论文或汇报前，应从对应 artifact 的逐图结果重新生成一次汇总表，并记录 artifact 指纹，避免手工转录误差。

### 4.1 TRACE 当前结果

最近一次 normal-only TRACE 实验：

| 项目 | 数值 |
|---|---:|
| 总任务图 | 1,108 |
| 良性训练图 | 772 |
| 良性验证图 | 165 |
| 最终评估良性图 | 167 |
| 最终评估恶意图 | 4 |
| 阈值 | 约 7.736 |
| ROC-AUC | 约 0.997 |
| PR-AUC | 约 0.917 |
| 检出的恶意图 | 0 / 4 |

四张恶意图的最终分数约为：

```text
4.614
4.580
2.922
1.911
```

它们全部低于 7.736 的阈值。

这说明：

- 当前异常分数有很强的排序能力；
- 恶意图整体比大多数良性图更异常；
- 最终失败主要来自阈值过高；
- 不能简单得出“当前表示完全无效”或“必须立即换深模型”的结论。

TRACE 只有 165 张良性验证图。99% 分位数对应的尾部只有约 1.65 张图，因此一个极端良性样本就可能决定阈值。该阈值的统计稳定性不足。

### 4.2 CADETS 当前结果

最近一次 normal-only CADETS 实验：

| 项目 | 数值 |
|---|---:|
| 总任务图 | 5,247 |
| 良性训练图 | 3,669 |
| 良性验证图 | 786 |
| 最终评估良性图 | 787 |
| 最终评估恶意图 | 5 |
| 阈值 | 约 16.581 |
| ROC-AUC | 约 0.993 |
| PR-AUC | 约 0.527 |
| 检出的恶意图 | 3 / 5 |
| 误报良性图 | 8 |

CADETS 的排序仍然很好，但恶意图极少，PR-AUC 对少量误报非常敏感。当前结果说明：

- 模型具有一定任务图检测能力；
- 部分攻击图仍与正常任务原型距离较近；
- 一些良性任务因为规模、根进程或罕见行为而获得高分；
- 需要更好的局部异常定位和任务类型条件化；
- 不能只依赖统一的全局 KMeans 距离。

### 4.3 当前方法的结构性不足

#### 问题 A：没有学习进程父子关系

当前 normal-only 分支只对独立进程向量和手工聚合后的图向量做聚类。

它无法直接学习：

- 某类父进程通常派生什么子进程；
- 浏览器派生 shell 是否异常；
- 服务进程派生解释器是否异常；
- 临时目录中的执行程序由谁创建；
- 权限变化前后的父子行为是否一致；
- 同一个进程向量在不同父进程上下文中是否具有不同风险。

#### 问题 B：LSTM-GRU 的训练误差信息被丢弃

进程历史编码器原本通过预测下一事件学习正常行为，但当前任务图检测只使用最终进程表示，没有保留：

- 下一事件预测误差；
- 序列中最异常事件的位置；
- 短序列和长序列的置信度；
- 进程行为随时间变化的惊异程度。

这会损失一类非常直接、可解释的局部异常信号。

#### 问题 C：固定 Top-3 不适应图规模差异

对 5 个节点和 5,000 个节点的任务图都取 Top-3，会产生不同含义：

- 小图中 Top-3 几乎代表整张图；
- 大图中 Top-3 可能只代表极小比例；
- 一个异常节点可能被另外两个高噪声节点稀释；
- 大图中多个稀疏恶意节点也可能没有被充分统计。

#### 问题 D：KMeans 只表示中心，不表示局部密度

正常任务通常是多峰分布。即使使用多个 KMeans 中心，也存在：

- 不同簇方差不同；
- 稀疏簇和密集簇使用相同距离尺度；
- 两个正常簇之间的区域可能被错误视为正常；
- 长尾但合法的任务可能形成极端高分；
- 固定原型数未必适合不同数据集。

#### 问题 E：全局图表示主要是手工池化

根、均值、最大值和规模统计可以作为基线，但不能区分：

- 相同节点集合、不同父子结构；
- 相同均值、不同异常节点位置；
- 异常出现在根附近还是叶子节点；
- 一条连续攻击分支和多个互不相关的正常分支。

#### 问题 F：阈值没有处理时间漂移

正常系统行为会随软件版本、用户活动、日期和服务状态变化。

单一时间片上的统一 99% 分位数容易出现：

- 验证期中的一个极端样本抬高阈值；
- 测试期正常分布漂移造成误报；
- 某类正常任务在验证集中缺失；
- 不同根进程族的分数不可直接比较。

### 4.4 输入事件覆盖边界

当前 LSTM-GRU 并没有读取数据集中的全部事件类型。它接收的是经过白名单过滤和交互聚合后的事件摘要。

#### 事件扩展与 LSTM-GRU 重训约束

当前 checkpoint 是在既有白名单事件及其当时的事件编号、聚合规则下训练出来的。因此，**只在推理或 parser 阶段扩展事件类型、却不重新训练 LSTM-GRU，并不等于模型已经学会了新增行为**：新增事件会改变输入序列的长度、顺序和事件编号分布，进而改变后续隐藏状态和最终进程表示；这种变化属于输入分布偏移，不能直接解释为“模型识别到了新的攻击语义”。

据此，实验必须严格区分两类路线：

- `E1`：保留旧白名单 LSTM-GRU，不把新增事件送入其序列输入；新增事件只能通过独立的全事件统计旁路补充。这是兼容旧 checkpoint 的低风险对照。
- `E2/E3`：将新增事件纳入统一语义词表和保序压缩序列后，必须在相同输入定义下重新训练 LSTM-GRU；只有这类路线才能评价“扩大事件覆盖”对序列表示本身的收益。

因此，任何“扩展事件类型但不重训 LSTM-GRU”的结果都只能作为统计旁路或 parser 覆盖率实验，不能与重训后的扩展事件编码器作同一层面的模型能力比较。

相关代码位置：

- CADETS parser：`vendor/tapas/darpa.py` 的 `parser_cadets()`；
- FiveDirections parser：`vendor/tapas/darpa.py` 的 `parser_fivedirections()`；
- TRACE parser：`vendor/tapas/darpa.py` 的 `parser_trace()`；
- TC3 THEIA parser：`vendor/tapas/darpa.py` 的 `filters()`；
- E5 THEIA parser：`vendor/tapas/darpa.py` 的 `filters_theia_e5()`；
- LSTM-GRU 表示生成：`vendor/tapas/darpa.py` 的 `LSTM`、`get_node_vec()` 和 E5 向量生成段。

#### 当前事件白名单

CADETS、FiveDirections、TC3 THEIA 和 E5 THEIA 当前共享以下 10 类事件：

```text
EVENT_ACCEPT
EVENT_CONNECT
EVENT_EXECUTE
EVENT_EXIT
EVENT_READ
EVENT_RECVFROM
EVENT_RECVMSG
EVENT_SENDTO
EVENT_SENDMSG
EVENT_WRITE
```

TRACE 当前保留以下 11 类事件：

```text
EVENT_RENAME
EVENT_CONNECT
EVENT_EXECUTE
EVENT_EXIT
EVENT_READ
EVENT_RECVFROM
EVENT_RECVMSG
EVENT_SENDTO
EVENT_SENDMSG
EVENT_WRITE
EVENT_CREATE_OBJECT
```

这不只是覆盖率问题，还存在跨数据集语义编号冲突：

| 数值 ID | CADETS/FiveDirections/THEIA | TRACE |
|---:|---|---|
| 1 | `EVENT_ACCEPT` | `EVENT_RENAME` |
| 2 | `EVENT_CONNECT` | `EVENT_CONNECT` |
| 3 | `EVENT_EXECUTE` | `EVENT_EXECUTE` |
| 4 | `EVENT_EXIT` | `EVENT_EXIT` |
| 5 | `EVENT_READ` | `EVENT_READ` |
| 6 | `EVENT_RECVFROM` | `EVENT_RECVFROM` |
| 7 | `EVENT_RECVMSG` | `EVENT_RECVMSG` |
| 8 | `EVENT_SENDTO` | `EVENT_SENDTO` |
| 9 | `EVENT_SENDMSG` | `EVENT_SENDMSG` |
| 10 | `EVENT_WRITE` | `EVENT_WRITE` |
| 11 | 无 | `EVENT_CREATE_OBJECT` |

当前事件 ID 作为 6 维事件向量中的一个连续数值输入 LSTM-GRU。这样会产生两个问题：

- 离散事件类型被模型当成具有大小和距离关系的连续数值；
- 同一个 checkpoint 在不同数据集上可能把相同数值解释成不同事件。

因此，在统一事件词表前，不能把跨数据集 LSTM-GRU 表示视为严格一致的语义空间。

#### 当前输入不是逐条原始事件序列

parser 会先按以下键聚合：

```text
(事件类型, Subject UUID, Object UUID)
```

同一组合的重复事件被折叠为一个计数。字典保留的是该组合首次出现的大致顺序，但后续重复发生的准确时间顺序被压缩。

因此当前 LSTM-GRU 实际编码的是：

```text
筛选后的进程-对象交互摘要序列
```

而不是：

```text
完整、逐条、严格按时间排列的原始事件序列
```

后续文档中“下一事件预测”若复用当前输入，应准确称为：

```text
下一条保留交互摘要预测
```

只有在重建真实时间序列输入后，才能称为原始事件级下一事件预测。

#### E5 THEIA 的事件覆盖实例

根据当前 E5 THEIA 事件统计：

| 事件类型 | 数量 | 当前进入 LSTM-GRU |
|---|---:|---|
| `EVENT_READ` | 266,942,591 | 是 |
| `EVENT_WRITE` | 44,704,409 | 是 |
| `EVENT_OPEN` | 38,116,531 | 否 |
| `EVENT_RECVFROM` | 16,825,848 | 是 |
| `EVENT_MMAP` | 13,942,509 | 否 |
| `EVENT_MPROTECT` | 10,125,045 | 否 |
| `EVENT_RECVMSG` | 2,644,903 | 是 |
| `EVENT_EXIT` | 1,234,824 | 是 |
| `EVENT_CLONE` | 1,205,134 | 否 |
| `EVENT_EXECUTE` | 996,254 | 是 |
| `EVENT_OTHER` | 969,358 | 否 |
| `EVENT_SENDMSG` | 827,609 | 是 |
| `EVENT_SENDTO` | 256,953 | 是 |
| `EVENT_CONNECT` | 130,918 | 是 |
| `EVENT_CHANGE_PRINCIPAL` | 14,561 | 否 |
| `EVENT_UNLINK` | 5,991 | 否 |
| `EVENT_MODIFY_FILE_ATTRIBUTES` | 2,303 | 否 |
| `EVENT_CORRELATION` | 2,209 | 否 |
| `EVENT_SHM` | 530 | 否 |
| `EVENT_BOOT` | 5 | 否 |

按事件条数计算，当前白名单覆盖约：

```text
334,564,309 / 398,948,485 = 83.86%
```

被丢弃约：

```text
64,384,176 / 398,948,485 = 16.14%
```

但 83.86% 不能解释为语义覆盖充分，因为事件量主要由 `READ` 和 `WRITE` 主导。当前观察到的 20 类事件中只有 9 类实际进入模型，以下被过滤事件虽然数量较少，却可能具有更直接的安全含义：

| 事件 | 可能提供的安全语义 |
|---|---|
| `EVENT_OPEN` | 文件访问意图、后续读写前因 |
| `EVENT_MMAP` | 动态加载、文件映射、执行上下文 |
| `EVENT_MPROTECT` | 内存页权限变化、运行时代码行为 |
| `EVENT_CLONE` | 进程或线程派生 |
| `EVENT_CHANGE_PRINCIPAL` | 用户或权限主体变化 |
| `EVENT_UNLINK` | 文件删除、痕迹清理 |
| `EVENT_MODIFY_FILE_ATTRIBUTES` | 权限或属性修改，例如可执行权限变化 |
| `EVENT_SHM` | 共享内存与进程间通信 |
| `EVENT_CORRELATION` | 数据源提供的关联信息 |

其中 `OPEN`、`MMAP` 和 `MPROTECT` 数量很大，不能简单逐条加入而不控制序列长度；`CHANGE_PRINCIPAL`、`UNLINK`、`MODIFY_FILE_ATTRIBUTES` 数量较少，但安全价值可能较高，不能仅按频率决定是否保留。

#### 对 module1 和 module2 的影响

任务图父子结构主要来自 Subject 的 `parentSubject`，因此事件白名单通常不会直接决定父子边。

但它会显著影响节点表示：

- 只有过滤事件的进程可能得到全零历史向量；
- 只发生 `OPEN/MMAP/MPROTECT/UNLINK` 的进程在行为空间中可能近似无行为；
- 稀有但关键的权限变化和清理行为不会反映在任务图检测分数中；
- 两个真实行为不同、但保留事件相似的进程可能得到相近表示；
- module2 可能在进入后半段证据恢复前漏掉任务图。

在 ground truth 任务图直筛模式下，后半段仍可能从原始日志恢复这些事件；但在正常 module2 检测模式下，任务图必须先被选中，所以这一信息缺口会直接影响端到端召回。

#### 对后续 GraphMAE 的影响

GraphMAE 只能重建输入目标中存在的信息。

如果重建目标仍是当前白名单 LSTM-GRU 表示，那么：

- GraphMAE 可以学习父子上下文；
- 但无法凭空恢复被过滤事件；
- `UNLINK`、`CHANGE_PRINCIPAL`、`MPROTECT` 等行为仍不可见；
- 重建误差只能解释为“相对于白名单事件摘要是否异常”。

因此，掩码重建前必须明确输入版本，并至少增加事件覆盖旁路特征。

## 5. 总体改造原则

### 5.1 保持不变的部分

以下部分默认不因本轮改造而改变：

- module0 不参与本轮任务图检测实验；
- module1 继续提供任务图和进程历史表示；
- 训练和阈值选择只使用良性任务图；
- 已知恶意图只用于最终评估；
- 任务图构造和恶意任务图标注应独立于检测器；
- 每个实验必须保存逐图分数，而不只保存汇总指标；
- 攻击战术分析链路暂不因检测器改造而改变；
- 每个新模型都必须能输出具体异常进程及其得分。

### 5.2 不使用恶意标签调参

以下选择不能根据恶意测试图表现决定：

- 原型数；
- KNN 的 K；
- 掩码比例；
- 模型层数；
- Top-K 规则；
- 融合权重；
- 阈值；
- 训练停止轮次。

这些参数应通过良性训练损失、良性验证稳定性、正常簇稳定性、目标误报率和多个随机种子的一致性确定。

恶意标签只用于最终报告：

- ROC-AUC；
- PR-AUC；
- Recall；
- Precision；
- F1；
- MCC；
- Recall@固定良性误报率；
- 恶意图首次出现排名。

### 5.3 事件输入必须显式版本化

每个模型 checkpoint 必须保存：

- 原始事件类型集合；
- 保留事件类型集合；
- 统一语义类别映射；
- 未知事件处理方式；
- 是否按真实时间排序；
- 是否按进程-对象组合聚合；
- 聚合时间窗口；
- 每类事件的训练频率；
- 输入事件向量结构；
- 事件词表版本。

不同事件词表或不同编号映射的 checkpoint 不得静默混用。

### 5.4 不按事件频率简单决定安全价值

高频事件适合通过采样、计数或窗口聚合控制规模；低频高价值事件应保留独立语义。

建议将事件分成：

| 类别 | 示例 | 处理原则 |
|---|---|---|
| 高频基础交互 | `READ`、`WRITE`、`OPEN` | 窗口聚合、对数计数、保留顺序摘要 |
| 网络交互 | `CONNECT`、`ACCEPT`、`SEND*`、`RECV*` | 统一方向和端点语义 |
| 进程生命周期 | `CLONE`、`EXECUTE`、`EXIT` | 保留时间顺序和父子关联 |
| 权限与属性变化 | `CHANGE_PRINCIPAL`、`MODIFY_FILE_ATTRIBUTES` | 独立保留，不并入普通 OTHER |
| 内存执行相关 | `MMAP`、`MPROTECT`、`SHM` | 独立保留，可增加安全权重 |
| 清理与重命名 | `UNLINK`、`RENAME` | 独立保留对象和前后关系 |
| 未知或罕见事件 | `OTHER` 和新类型 | 记录原始类型或稳定哈希，避免全部混成一个数值 |

### 5.5 每一步采用 Core / Extended 双线对照

后续每个模型阶段都同时运行两条事件输入线：

| 实验线 | 含义 | 目的 |
|---|---|---|
| `Core` | 只使用当前 parser 已保留的核心事件类型 | 保持与当前方案相近，观察模型结构本身的收益 |
| `Extended` | 使用日志中更全面、统一语义且经过保序压缩的事件类型 | 观察扩大事件覆盖带来的额外收益 |

另保留一次不可覆盖的历史锚点：

| 实验线 | 含义 |
|---|---|
| `Legacy` | 当前事件白名单、当前数值编号、当前聚合方式和当前 checkpoint |

`Legacy` 只用于确认历史结果，不应与 `Extended` 直接归因比较，因为两者同时改变了事件集合、事件编码和模型训练。

真正公平的事件覆盖消融是：

```text
Core-V2 vs Extended-V2
```

两者必须保持：

- 相同的统一事件语义词表；
- 相同的 learned embedding 或 one-hot 事件编码；
- 相同的聚合窗口和保序规则；
- 相同的任务图；
- 相同的训练、验证、校准和测试任务 ID；
- 相同的模型结构和隐藏维度；
- 相同的随机种子；
- 相同的训练轮次和早停规则；
- 相同的目标良性误报率；
- 分别只用各自的良性校准分数确定阈值。

两条线唯一应有的主要差异是：

```text
Core-V2     只允许当前核心事件语义
Extended-V2 在同一编码框架下增加扩展事件语义
```

#### Core-V2 建议范围

使用当前各数据集已经保留的语义，但消除数值编号冲突：

```text
PROCESS_EXECUTE
PROCESS_EXIT
FILE_READ
FILE_WRITE
FILE_RENAME，仅 TRACE 当前包含
FILE_CREATE，仅 TRACE 当前包含
NET_CONNECT
NET_ACCEPT，数据集存在时
NET_SEND
NET_RECV
```

#### Extended-V2 建议增加

```text
PROCESS_CREATE
PRINCIPAL_CHANGE
FILE_OPEN
FILE_UNLINK
FILE_ATTRIBUTE_CHANGE
MEMORY_MAP
MEMORY_PROTECT
SHARED_MEMORY
CORRELATION
稳定处理后的 OTHER/未知类型
```

`Extended` 不等于把全部原始事件逐条无差别输入模型。高频事件仍需保序压缩，低频高价值事件应全部保留。

#### 每个阶段的双线命名

建议使用：

```text
N0-Legacy
N0-Core
N0-Extended

N1-Core
N1-Extended

N2-Core
N2-Extended

N3-Core
N3-Extended
```

其中：

- `N0-Legacy` 是历史实现；
- `N0-Core` 是统一编码后的核心事件基线；
- `N0-Extended` 是统一编码后的扩展事件基线；
- 后续 `N1/N2/N3...` 分别对应 KNN、序列误差、有向 GIN、GraphMAE 等阶段。

#### 双线归因方式

每一步同时计算：

```text
模型增益_Core =
    当前阶段 Core - 上一阶段 Core

模型增益_Extended =
    当前阶段 Extended - 上一阶段 Extended

事件覆盖增益 =
    当前阶段 Extended - 当前阶段 Core
```

这样可以区分：

- 收益来自模型变强；
- 收益来自事件类型变多；
- 两者存在互补；
- 扩展事件只增加噪声；
- 某个模型只能在完整事件上发挥作用。

#### 双线继续条件

- 两条线均保存，不因单次结果删除；
- 每条线至少运行 3 个相同种子；
- Extended 的固定 FPR 召回若提升，应检查是否来自 GT 进程的新增事件；
- Extended 的误报增加时，应定位具体新增事件类型；
- 任一数据集主要指标下降超过 0.05，应停止继续叠加改动并归因；
- 不允许根据恶意测试图为 Core 和 Extended 选择不同模型容量；
- 阈值可以分别校准，但目标良性 FPR 必须相同。

## 6. 分阶段实施路线

## 6.1 Phase 0：先修评估协议和阈值校准

### 目的

在不改变异常编码器和原始分数的情况下，确认 TRACE 的 0 召回是否主要由阈值失稳造成。

### 数据划分

建议将良性数据分成三个时间上连续且互不重叠的部分：

| 数据段 | 用途 |
|---|---|
| 良性训练段 | 拟合 scaler、KMeans、KNN 或神经网络 |
| 良性模型验证段 | 选择模型轮次和不依赖攻击标签的超参数 |
| 良性分数校准段 | 只用于分数归一化和阈值 |
| 最终评估段 | 剩余良性图和全部恶意图 |

如果数据量不足，可保留 70/15/15 的大比例结构，但把原验证段再分成模型验证与阈值校准，或使用多个连续时间块轮换校准。

### 校准方案 A：经验分位数

保留当前方法，但增加：

- 多个连续时间块分别计算分位数；
- 取各块阈值的中位数；
- 输出阈值置信区间；
- 输出每块预计每天误报数；
- 禁止单个样本决定最终阈值。

### 校准方案 B：经验 conformal p 值

对任意原始异常分数 `s`，使用良性校准分数计算：

```text
p = (1 + 校准集中分数大于等于 s 的数量) / (校准样本数 + 1)
```

当 `p` 小于指定显著性水平时触发异常。

优点：

- 可以用于任何现有异常分数；
- 不需要重新训练模型；
- 阈值含义比原始距离更清楚；
- 便于按任务类型分别校准；
- 便于后续做在线更新。

注意：

- 标准 conformal 方法依赖校准样本与测试良性样本近似可交换；
- 明显时间漂移时应采用滚动校准或加权校准；
- 校准集太小时，p 值分辨率有限；
- 不能用恶意测试图反向选择显著性水平。

### 校准方案 C：按任务族条件化

可以根据不含攻击标签的元数据划分正常任务族：

- 根进程路径；
- 根进程名称；
- 服务类、浏览器类、解释器类、系统维护类；
- 节点规模区间；
- 深度区间；
- 主机或数据集。

每类样本充足时独立校准；样本不足时退回全局校准。

建议采用层级回退：

```text
根进程族阈值
→ 任务类别阈值
→ 数据集全局阈值
```

### Phase 0 验收条件

- TRACE 不再出现“ROC-AUC 很高但全部恶意图低于一个极端阈值”而没有解释的情况；
- 输出固定良性 FPR 下的恶意召回；
- 输出每天误报数；
- 输出阈值由多少良性样本支撑；
- 输出最高分良性图的任务类型和异常来源；
- CADETS 的最终良性误报不明显增加。

## 6.2 Phase 1：KNN 正常样本库与下一事件预测误差

### 目的

在不引入新 GNN 的前提下，利用现有进程表示和序列训练目标提升异常分数。

### 1A：KNN 替代节点 KMeans

训练阶段保存良性训练进程表示作为正常记忆库。

节点异常分数可以选择：

```text
最近 1 个良性邻居距离
最近 K 个良性邻居平均距离
最近 K 个良性邻居距离的加权平均
```

建议初始比较：

```text
K = 1, 5, 10, 20
```

距离建议比较：

- 标准化后的欧氏距离；
- L2 归一化后的余弦距离。

如果正常进程数量很大，可采用 FAISS。

### 1B：KNN 替代图级 KMeans

对每张良性训练图保存：

```text
root + mean + max + structure
```

或后续 GNN 生成的图表示。

测试图到最近 K 个良性图的距离作为全局异常分数。

KNN 比 KMeans 更适合保留复杂的正常流形，但需要注意：

- 训练样本可能重复；
- 大量相似服务任务会主导近邻；
- 不同规模图需要先标准化；
- 应保存最近邻任务 ID，方便解释误报。

### 1C：加入下一事件预测误差

当前 checkpoint 推理只返回最终隐藏状态，虽然模型内部定义了线性预测层，但当前 `forward()` 没有把预测值和逐步误差返回给 module1/module2。因此，不能直接从现有 42 维进程向量反推出下一事件预测误差。

在修改前必须先区分两个版本。

#### 兼容版本：下一条保留交互摘要预测

继续使用当前白名单和聚合后的 6 维输入：

```text
同一进程的保留交互摘要
→ 预测下一条保留交互摘要
```

该版本可以验证序列误差是否有增益，但不能宣称覆盖全部原始事件。

需要：

- 在良性数据上重新训练或恢复与当前输入完全一致的预测头；
- 返回每一步预测值；
- 预测目标与输入错开一位；
- 不使用只有最终隐藏状态的现有推理接口冒充预测误差；
- checkpoint 保存白名单和跨数据集语义映射。

#### 完整版本：统一语义事件序列预测

先完成统一事件词表和事件表示，再训练：

```text
规范化后的同一进程事件序列
→ 预测下一事件语义类别、对象类别和关键属性
```

推荐输入拆分：

```text
event_type_embedding
+ object_type_embedding
+ direction_embedding
+ log1p(repeat_count)
+ time_gap_feature
+ selected_object_attributes
```

事件类型必须使用 one-hot 或 learned embedding，不再把 1、2、3 等类别 ID 当连续数值。

对每个进程保存：

- 平均预测误差；
- 最大预测误差；
- 末尾若干事件预测误差；
- 可选的高误差事件类型；
- 有效历史长度。
- 原始事件数；
- 保留事件数；
- 事件覆盖率；
- 被过滤高价值事件计数。

节点异常分数建议为：

```text
node_score =
    w_repr × representation_knn_distance
  + w_seq  × next_event_prediction_error
```

权重只能根据良性验证稳定性选择。第一轮建议做固定消融：

| 变体 | 表示距离权重 | 序列误差权重 |
|---|---:|---:|
| P1-A | 1.00 | 0.00 |
| P1-B | 0.75 | 0.25 |
| P1-C | 0.50 | 0.50 |
| P1-D | 0.25 | 0.75 |
| P1-E | 0.00 | 1.00 |

### 1D：增加完整事件统计旁路

这是在重训统一事件 LSTM-GRU 前最现实、风险最低的补救。

保留当前白名单 LSTM-GRU 作为兼容主干，同时为每个规范进程单遍流式统计全部原始事件：

```text
raw_event_count
retained_event_count
retention_ratio
log1p(count_by_semantic_family)
rare_security_event_flags
first_seen / last_seen / active_span
event_type_entropy
object_type_counts
```

安全相关独立计数至少包含：

```text
CLONE
OPEN
MMAP
MPROTECT
CHANGE_PRINCIPAL
UNLINK
MODIFY_FILE_ATTRIBUTES
SHM
RENAME
CREATE_OBJECT
```

旁路统计在应用线程到进程的 canonical 映射后生成，确保线程事件计入所属进程。

使用方式：

- 第一轮只接入 normal-only 节点 KNN；
- 第二轮作为有向 GIN 的附加节点输入；
- GraphMAE 中可同时重建进程行为表示和归一化事件统计；
- 不直接把高维稀疏计数与旧 LSTM 输入混合。

### 1E：统一语义事件词表

建议建立跨 TC3 和 E5 的稳定语义词表，例如：

```text
PROCESS_CREATE
PROCESS_EXECUTE
PROCESS_EXIT
PRINCIPAL_CHANGE
FILE_OPEN
FILE_READ
FILE_WRITE
FILE_CREATE
FILE_RENAME
FILE_UNLINK
FILE_ATTRIBUTE_CHANGE
MEMORY_MAP
MEMORY_PROTECT
SHARED_MEMORY
NET_CONNECT
NET_ACCEPT
NET_SEND
NET_RECV
CORRELATION
OTHER
```

原始事件映射示例：

```text
EVENT_CLONE                  → PROCESS_CREATE
EVENT_EXECUTE                → PROCESS_EXECUTE
EVENT_CHANGE_PRINCIPAL       → PRINCIPAL_CHANGE
EVENT_MODIFY_FILE_ATTRIBUTES → FILE_ATTRIBUTE_CHANGE
EVENT_SENDTO/EVENT_SENDMSG   → NET_SEND
EVENT_RECVFROM/EVENT_RECVMSG → NET_RECV
```

必须保存原始类型，统一类别只是模型输入，不应覆盖原始日志语义。

### 1F：高频事件压缩策略

不建议将近 4 亿条 E5 事件全部逐条输入 LSTM-GRU。建议按同一进程流式处理，并比较：

```text
连续相同语义和对象的 run-length 聚合
固定 1 秒或 5 秒窗口内聚合
保留首个、末个和计数
高频 READ/WRITE/OPEN 下采样
低频高价值事件全部保留
```

聚合记录至少包含：

```text
事件语义
对象类型
重复次数
首时间
末时间
与上一条摘要的时间差
```

这样既保留时间变化，又避免当前“全文件范围只按类型、进程、对象聚成一个计数”造成的顺序损失。

### 1G：动态局部 Top-K

比较以下规则：

```text
Top-1
Top-3
Top-5
Top-5%
Top-10%
Top-max(3, ceil(5% × N))，上限 20
```

推荐默认候选：

```text
K_local = min(20, max(3, ceil(0.05 × task_node_count)))
```

同时输出：

- Top-K 节点 ID；
- 每个节点的表示距离；
- 每个节点的序列误差；
- 节点路径、深度和父进程；
- 节点在 GT 名单中的状态，仅用于最终评估。

### Phase 1 验收条件

- TRACE 恶意图最终分数与高分良性图的间隔扩大；
- CADETS 3/5 的召回不下降；
- 误报图能够通过最近邻和异常进程解释；
- KNN 与 KMeans 的差异有逐图证据；
- 不依赖恶意标签选择 K 或融合权重。

## 6.3 Phase 2：有向 GIN 图编码器

### 目的

让检测器真正学习父进程和子进程之间的正常上下文，而不是只聚类独立进程向量。

### 为什么优先考虑 GIN

当前任务图是进程父子树或近似树结构。GIN 使用求和聚合和 MLP，对邻域多重集合具有较强区分能力，适合区分：

- 一个父进程派生多个不同子进程；
- 同一组进程以不同结构连接；
- 异常子进程出现在根附近或深层分支；
- 大量相似进程节点与少量不同节点的组合。

### 有向 GIN 的具体设计

对每一层分别维护两个方向：

```text
parent_to_child_edges = 原始父到子边
child_to_parent_edges = 原始边反向
```

分别计算：

```text
h_down = GIN_down(h, parent_to_child_edges)
h_up   = GIN_up(h, child_to_parent_edges)
```

融合方式第一版建议：

```text
h_next = MLP(concat(h_self, h_down, h_up))
```

也可做消融：

```text
sum(h_down, h_up)
concat(h_down, h_up)
gated_fusion(h_down, h_up)
```

建议初始结构：

| 参数 | 初始值 |
|---|---:|
| GIN 层数 | 2 |
| 隐藏维度 | 128 或与进程表示同维度 |
| 激活 | PReLU 或 ReLU |
| 归一化 | LayerNorm |
| 残差 | 开启 |
| Dropout | 0.0、0.1 做对照 |
| train_eps | True |

层数不宜过深，避免：

- 过平滑；
- 大图显存增长；
- 将局部恶意行为扩散到整张图；
- 任务切分边界附近的表示失真。

### 图级表示

第一版采用：

```text
graph_embedding = concat(root_embedding, mean_pool, max_pool)
```

可选增加：

- 按深度分层池化；
- 根的一跳子进程池化；
- 叶子节点池化；
- Top-K 异常节点池化。

第一轮不要同时加入过多池化方式，避免难以归因。

### Phase 2 异常评分

在还没有掩码重建时，可先使用：

```text
节点上下文表示到良性节点 KNN 的距离
图表示到良性图 KNN 或多原型的距离
```

这一阶段用于隔离验证“有向 GIN 编码器本身是否带来增益”。

## 6.4 Phase 3：有向 GraphMAE 掩码进程行为重建

### 目的

通过只使用良性任务图训练的自监督任务，学习“根据父进程、子进程和任务上下文，应当能恢复一个正常进程的行为表示”。

攻击进程如果与上下文不匹配，应产生较高重建误差。

### 教师表示

重建目标使用已经在良性进程历史上训练好的 LSTM-GRU 表示。

必须明确该教师表示的事件版本：

```text
legacy_core_events
extended_semantic_events
full_timeline_events
```

第一轮可以使用 `legacy_core_events` 验证图上下文模型，但必须同时接入完整事件统计旁路，并在报告中注明重建目标不包含全部事件。

推荐的正式版本使用：

```text
extended_semantic_events LSTM-GRU embedding
+ normalized full-event statistics
```

GraphMAE 可使用两个解码头：

```text
behavior_decoder → 重建进程序列行为表示
event_stats_decoder → 重建完整事件统计向量
```

联合损失：

```text
L_mask =
    lambda_behavior × SCE(behavior_hat, behavior_target)
  + lambda_stats    × Huber(stats_hat, stats_target)
```

这样即使高频事件经过压缩，模型仍能看到当前白名单遗漏的权限、内存、清理和属性变化信号。

初始阶段必须冻结 LSTM-GRU，原因是：

- 防止图模型和目标编码器共同收缩到相似向量；
- 保持不同实验的输入一致；
- 便于判断改进来自图上下文还是进程编码器；
- 避免重建任务发生表示坍缩。

后续可做慢更新教师或 EMA 教师，但不应作为第一版。

### 掩码策略

第一轮建议：

- 只遮盖进程行为向量，不删除节点；
- 默认遮盖 30% 节点；
- 优先遮盖非根节点；
- 小图至少遮盖 1 个节点；
- 不改变父子边；
- 不使用攻击标签；
- 每个 epoch 重新采样掩码。

消融比例：

```text
15%
30%
50%
```

不建议第一轮直接使用极高比例，因为任务图可能很小，且部分节点的上下文有限。

### 编码与解码

建议流程：

```text
原始进程表示
→ 随机节点替换为可学习 mask token
→ 2 层有向 GIN 编码
→ 线性桥接层
→ 1 层有向 GIN 或 MLP 解码
→ 重建被遮盖进程的原始表示
```

解码器不宜过强，否则可能：

- 对攻击行为也重建得很好；
- 只靠节点自身残留信息完成复制；
- 降低节点级异常差异。

### 重建损失

优先使用 GraphMAE 和 MAGIC 使用的缩放余弦误差：

```text
SCE(x_hat, x) = (1 - cosine(x_hat, x)) ^ alpha
```

建议：

```text
alpha = 2 或 3
```

原因：

- 进程表示方向通常比绝对模长更有意义；
- 对高误差节点给予更强梯度；
- 比普通均方误差更不容易被向量尺度主导。

### 是否重建图结构

第一版不建议照搬 MAGIC 的通用边重建。

原因：

- 当前任务图的边主要都是父子创建关系；
- 图结构由上游任务切分规则强烈决定；
- 重建边可能让模型学习任务切分痕迹；
- 攻击与良性图都应遵守基本父子结构；
- 边存在本身不一定是异常，父子行为组合才更关键。

替代做法是在 Phase 4 增加父进程预测子进程行为。

### 节点和图级异常分数

节点重建异常：

```text
reconstruction_score(v) =
    1 - cosine(reconstructed_embedding(v), target_embedding(v))
```

图的局部分数：

```text
local_score(G) =
    mean(top_dynamic_k(reconstruction_score(v)))
```

图的全局分数：

```text
global_score(G) =
    distance(graph_embedding(G), benign_graph_memory)
```

最终分数：

```text
score(G) =
    w_local  × calibrated_local_score
  + w_global × calibrated_global_score
  + w_seq    × calibrated_sequence_surprise
```

第一轮建议分别输出三项，不急于固定唯一融合权重。

### Phase 3 验收条件

- 良性验证重建误差稳定收敛；
- 不出现所有节点表示趋同；
- 恶意图中的 GT 进程或其邻近进程获得较高重建误差；
- 高分良性节点能够解释为罕见但合理的上下文；
- TRACE 和 CADETS 至少一个数据集相对 Phase 1 提升；
- 另一个数据集的固定 FPR 召回不明显下降；
- 不以恶意测试图选择 epoch。

## 6.5 Phase 4：父进程条件下的子进程行为预测

### 目的

直接学习正常情况下“什么父进程会派生什么子进程”，检测异常派生关系。

### 输入

建议第一版使用：

```text
父进程上下文表示
父进程原始行为表示
子进程深度
父子创建时间差
父进程子节点数量
```

### 目标

预测：

```text
子进程的冻结 LSTM-GRU 行为表示
```

边异常分数：

```text
edge_score(parent, child) =
    1 - cosine(predicted_child_embedding, actual_child_embedding)
```

### 适合检测的行为

- 浏览器派生 shell；
- 邮件客户端派生解释器；
- 服务进程派生临时 payload；
- 正常工具突然派生扫描或下载进程；
- 普通用户进程派生高权限进程；
- 清理程序由不相关进程启动；
- 失败攻击尝试产生的异常派生。

### 与掩码重建的关系

两者不是替代关系：

- 掩码重建使用完整邻域恢复节点；
- 父子预测专门约束父到子的行为合理性；
- 掩码重建更适合局部上下文异常；
- 父子预测更适合解释异常进程派生。

建议联合损失：

```text
L = lambda_mask × L_mask + lambda_child × L_child
```

第一轮比较：

| 变体 | lambda_mask | lambda_child |
|---|---:|---:|
| P4-A | 1.0 | 0.0 |
| P4-B | 1.0 | 0.25 |
| P4-C | 1.0 | 0.50 |
| P4-D | 1.0 | 1.00 |

## 6.6 Phase 5：跨任务图时间关联

### 目的

解决单张任务图证据较弱、攻击行为被任务切分拆散的问题。

### 关联条件

只使用可解释的共享证据：

- 相同规范进程；
- 父子进程延续；
- 相同文件对象；
- 相同网络端点；
- 相同临时执行对象；
- 时间相邻；
- 同一主机；
- 攻击战术分析阶段确认的桥接对象。

### 关联输出

将多个异常任务图组织成时间队列：

```text
异常前导任务
→ 下载或写入任务
→ 执行任务
→ 权限或发现任务
→ 外联或清理任务
```

这一阶段不应反向修改单图标签，而应产生独立的关联分数和证据链。

### 风险

- 过宽时间窗会把良性任务串联；
- 高频系统对象会形成错误桥接；
- 同一服务进程可能跨越很长时间；
- 必须限制每种对象的桥接能力；
- 应保留单图得分和关联后得分，方便归因。

## 7. 推荐主模型

推荐主模型名称：

```text
Versioned Semantic Event Encoder
+ Full-Event Statistics Side Channel
+ Frozen LSTM-GRU
+ Directed GIN
+ Masked Process Reconstruction
+ Dynamic Top-K Local Score
+ KNN/Multi-Prototype Global Score
+ Benign-Only Temporal Calibration
```

中文描述：

```text
统一并版本化事件语义
+ 完整事件统计旁路
+ 冻结进程历史编码器
+ 有向进程树编码
+ 掩码进程行为重建
+ 动态局部异常聚合
+ 多模态正常任务距离
+ 仅良性时间校准
```

### 推理流程

```text
原始日志
→ 全事件流式统计与统一语义映射
→ 压缩但保序的进程历史
→ LSTM-GRU 进程行为表示
→ 任务图
→ 有向 GIN 上下文表示
→ 节点重建误差
→ 下一事件预测误差
→ 图级正常距离
→ 良性校准
→ 图级告警 + 异常进程定位
```

### 输出要求

每张任务图至少输出：

```json
{
  "task_id": "task_xxxx",
  "task_score": 0.0,
  "threshold": 0.0,
  "conformal_p_value": 1.0,
  "local_reconstruction_score": 0.0,
  "sequence_surprise_score": 0.0,
  "global_memory_distance": 0.0,
  "event_vocabulary_version": "",
  "raw_event_count": 0,
  "retained_event_count": 0,
  "event_retention_ratio": 0.0,
  "nearest_benign_task_ids": [],
  "top_anomalous_processes": [],
  "calibration_group": "",
  "prediction": 0
}
```

每个高异常进程至少输出：

```json
{
  "process_id": "",
  "parent_process_id": "",
  "depth": 0,
  "reconstruction_error": 0.0,
  "next_event_error": 0.0,
  "parent_child_error": 0.0,
  "raw_event_count": 0,
  "retained_event_count": 0,
  "omitted_security_event_counts": {},
  "nearest_benign_process_ids": [],
  "process_path": "",
  "event_count": 0
}
```

## 8. 开源模型与代码参考

## 8.0 TAPAS

### 链接

- 论文页面：https://www.usenix.org/conference/usenixsecurity25/presentation/zhang-bo-tapas

### 与本方案的关系

当前 module1 的任务图、进程历史表示和原始 GraphSAGE 检测主线来自 TAPAS 设计。TAPAS 使用堆叠 LSTM-GRU 根据进程相关事件更新进程表示，并通过任务引导的进程图切分降低空间和时间冗余。

本次 normal-only 改造不应推翻这一上游结构，而应：

- 继续使用任务图作为检测单位；
- 继续使用进程历史表示作为节点输入；
- 恢复或保留下一事件预测误差；
- 将少量恶意图监督分类改成良性自监督异常检测；
- 在现有任务图上增加有向上下文学习。

### 当前限制

没有确认到可直接替换当前 vendor 代码的官方 TAPAS 开源仓库。因此，TAPAS 主要通过论文和当前项目已有实现进行核对。后续如果找到作者正式发布的 artifact，应先做代码来源、版本和许可证核验，再决定是否回移。

## 8.1 GraphMAE

### 链接

- 官方仓库：https://github.com/THUDM/GraphMAE
- PyTorch Geometric 分支：https://github.com/THUDM/GraphMAE/tree/pyg
- 论文：https://arxiv.org/abs/2205.10803
- PyG 模型目录：https://github.com/THUDM/GraphMAE/tree/pyg/graphmae/models

### 可直接参考的部分

- mask token；
- 随机节点属性遮盖；
- 编码器到解码器的桥接；
- 重掩码解码；
- SCE 损失；
- GIN 编码器和解码器；
- 图分类批处理；
- 自监督训练循环。

### 需要修改的部分

- 输入改为现有 LSTM-GRU 进程表示；
- 图边改为显式父到子和子到父两套；
- GIN 改成双方向聚合；
- 训练数据只使用良性任务图；
- 输出节点重建误差而不只是下游分类表示；
- 图级分数接 KNN 或多原型正常模型；
- 不直接使用通用公开数据集配置。

### 适配程度

高。当前项目已经使用 PyTorch Geometric，PyG 分支可作为主实现骨架。

### 许可证

仓库包含 LICENSE，正式复制代码前应再次核对具体许可证文本并在项目中保留原始版权和引用。

## 8.2 MAGIC

### 链接

- 官方仓库：https://github.com/FDUDSDE/MAGIC
- 论文页面：https://www.usenix.org/conference/usenixsecurity24/presentation/jia-zian
- 掩码自动编码器：https://github.com/FDUDSDE/MAGIC/blob/main/model/autoencoder.py
- SCE 损失：https://github.com/FDUDSDE/MAGIC/blob/main/model/loss_func.py
- 评估入口：https://github.com/FDUDSDE/MAGIC/blob/main/eval.py

### 模型特点

- 使用良性数据进行自监督图表示学习；
- 使用 GAT 编码器和解码器；
- 随机遮盖节点属性；
- 使用 SCE 重建损失；
- 同时进行节点属性和结构重建；
- 使用离群检测完成节点级和批次级检测；
- 提供概念漂移适配思路；
- 官方代码包含 TRACE、THEIA、CADETS 预处理数据说明。

### 可直接借鉴的部分

- 节点掩码实现；
- 可学习 mask token；
- 编码器多层隐藏表示拼接；
- SCE 损失；
- 异常表示和 KNN 检测衔接；
- 概念漂移后的记忆更新思路。

### 不建议直接照搬的部分

- MAGIC 使用 DGL，当前项目使用 PyG；
- MAGIC 针对完整溯源图，当前对象是进程任务图；
- MAGIC 的边重建针对多类型溯源关系；
- 当前父子树边主要由任务构造规则决定；
- 整套迁移会引入新的图框架和数据格式。

### 适配程度

算法参考价值高，代码直接复用程度中等。建议借鉴模型细节，不引入 DGL。

### 许可证

MIT。

## 8.3 GIN

### 链接

- 原作者代码：https://github.com/weihua916/powerful-gnns
- 论文：https://openreview.net/forum?id=ryGs6iA5Km
- PyG GINConv：https://pytorch-geometric.readthedocs.io/en/stable/generated/torch_geometric.nn.conv.GINConv.html

### 可直接参考的部分

- GIN 的求和聚合；
- 可训练 epsilon；
- MLP 更新结构；
- 图级 sum/mean pooling；
- PyG 的 `GINConv` 算子。

### 需要修改的部分

官方 GIN 默认不区分边方向。需要为父到子和子到父分别建立卷积层，再进行融合。

### 适配程度

高。`GINConv` 可直接作为当前 PyG 代码中的基础算子。

## 8.4 ORTHRUS

### 链接

- 官方仓库：https://github.com/ubc-provenance/orthrus
- USENIX 论文：https://www.usenix.org/conference/usenixsecurity25/presentation/jiang-baoxiang

### 可借鉴的部分

- 正常时间关系学习；
- 节点或边级异常证据；
- 异常证据到攻击场景重建；
- 良性训练与异常检测解耦；
- 预训练权重和完整实验配置管理。

### 不适合直接迁移的原因

- ORTHRUS 面向完整系统溯源图；
- 使用事件交互和数据库流水线；
- 图粒度与当前进程任务图不同；
- 整套运行依赖 PostgreSQL、Docker 和其自己的数据构造；
- 直接替换会绕开当前 module1 任务切分。

### 适配程度

低至中。适合借鉴时间预测、异常归因和攻击重建，不适合作为直接替换模型。

### 许可证

Apache-2.0。

### 可复现性注意

ORTHRUS 官方仓库说明，原实验因缺少 `PYTHONHASHSEED` 对 Gensim Word2Vec 的影响而不能完全逐数复现。我们的实验必须统一保存：

- Python seed；
- NumPy seed；
- PyTorch seed；
- CUDA 确定性设置；
- `PYTHONHASHSEED`；
- 数据顺序指纹。

## 8.5 KAIROS

### 链接

- 官方仓库：https://github.com/ubc-provenance/kairos
- 论文介绍：https://spg.cs.ubc.ca/publication/2024-sp/

### 可借鉴的部分

- 正常行为预测产生异常分数；
- 按时间窗口组织异常行为；
- 将异常实体和窗口串成攻击调查队列；
- 从大量异常事件中恢复较小攻击场景。

### 不适合直接迁移的原因

- KAIROS 是事件级全系统溯源检测；
- 当前检测单位是进程任务图；
- 直接迁移会改变输入粒度、训练目标和后续攻击战术分析接口。

### 适配程度

模型直接复用程度低，后处理关联思想价值高。

## 8.6 Deep SVDD

### 链接

- 官方参考实现：https://github.com/lukasruff/Deep-SVDD-PyTorch
- ICML 论文：https://proceedings.mlr.press/v80/ruff18a.html

### 可借鉴的部分

- 只使用正常样本训练；
- 将正常表示压缩到中心附近；
- 使用到中心的距离作为异常分数；
- 可作为单中心一类学习基线。

### 不建议作为主模型的原因

当前正常任务明显多模态：

- 浏览器任务；
- 服务任务；
- 系统维护任务；
- shell 和解释器任务；
- 文件处理任务；
- 网络任务。

单一超球中心容易：

- 把多个合法任务族之间的空间判成异常；
- 压缩表示多样性；
- 对任务类型分布变化敏感。

Deep SVDD 应作为论文消融基线，而不是默认主线。若要扩展，可尝试多中心 SVDD 或任务族条件化 SVDD。

## 8.7 FAISS

### 链接

- 官方仓库：https://github.com/facebookresearch/faiss

### 用途

- 节点正常记忆库的快速 KNN；
- 图级正常记忆库的快速 KNN；
- 支持欧氏距离、内积和归一化后的余弦近邻；
- 数据量大时可使用 GPU。

### 适配程度

高，但第一轮样本量不大时可先用 scikit-learn `NearestNeighbors`，确认有效后再引入 FAISS。

## 8.8 Tree-LSTM / Tree-GRU

### 链接

- Stanford Tree-LSTM：https://github.com/stanfordnlp/treelstm

### 可借鉴的部分

- 显式按树结构从叶子到根聚合；
- 适合建模父子层次关系；
- 可以构造双向 Tree-GRU；
- 父子预测语义自然。

### 当前限制

- 参考代码较旧，主要是 Torch7；
- 当前 PyG 批处理需要自定义树拓扑执行；
- 不规则大树的批处理成本高；
- 任务图不一定都是严格树；
- 实现和调试成本高于有向 GIN。

### 适配程度

中。建议作为有向 GIN 稳定后的第二主架构，不作为第一轮改造。

## 8.9 Conformal 异常校准

### 链接

- Conformal kNN Anomaly Detector：https://proceedings.mlr.press/v60/ishimtsev17a.html

### 可借鉴的部分

- 将任意模型产生的原始异常分数转换为基于良性校准集排名的 p 值；
- 不要求改变底层异常模型；
- 可用于非平稳数据流的滚动校准设计；
- 可以让阈值具有比“距离大于某个经验值”更明确的统计解释。

### 需要修改的部分

参考论文主要讨论单变量数据流，而当前对象是任务图异常分数。因此我们只借鉴校准层：

- 底层分数仍由 KMeans、KNN、GraphMAE 或联合模型生成；
- 校准单位改为任务图；
- 按时间块、根进程族或任务族维护良性分数；
- 分组样本不足时回退到数据集全局校准；
- 报告 p 值分辨率和校准样本数量。

### 适配程度

高。它是模型无关的后处理，可优先作用于当前 KMeans 基线，不需要等待新 GNN 完成。

## 9. 代码接入设计

## 9.1 建议新增文件

建议避免继续把所有逻辑堆入 `tapas_native_backend.py`，新增：

```text
src/apt_fusion/task_detection/normal_only/
    __init__.py
    split.py
    calibration.py
    memory_bank.py
    scoring.py
    directed_gin.py
    masked_reconstruction.py
    child_prediction.py
    trainer.py
    artifacts.py
```

职责：

| 文件 | 职责 |
|---|---|
| `split.py` | 良性时间划分和数据泄漏检查 |
| `calibration.py` | 分位数、conformal、分组校准 |
| `memory_bank.py` | KMeans、KNN、FAISS、多原型 |
| `scoring.py` | 节点、局部、全局和融合分数 |
| `directed_gin.py` | 双方向 GIN 编码器 |
| `masked_reconstruction.py` | 掩码、解码和 SCE 损失 |
| `child_prediction.py` | 父进程条件下的子进程预测 |
| `trainer.py` | 良性自监督训练和早停 |
| `artifacts.py` | 模型、分数、配置和诊断产物 |

`tapas_native_backend.py` 只保留：

- bundle 读取；
- 配置解析；
- 调用 normal-only runner；
- 将结果转换为 module2 统一输出格式。

## 9.2 建议新增 detector mode

保留当前模式作为不可覆盖的基线：

```text
normal_only_multimodal_prototype
```

新增：

```text
normal_only_knn
normal_only_sequence_knn
normal_only_directed_gin
normal_only_graphmae
normal_only_graphmae_child
```

不要直接改变 `normal_only` 的含义而不记录版本。可以通过子模式或显式配置选择，确保历史实验可复现。

## 9.3 建议新增配置

```yaml
task_normal_only_calibration_mode: empirical_quantile
task_normal_only_calibration_group: global
task_normal_only_calibration_alpha: 0.01
task_normal_only_calibration_block_count: 3

task_normal_only_memory_mode: kmeans
task_normal_only_node_knn_k: 5
task_normal_only_graph_knn_k: 5
task_normal_only_distance: cosine

task_normal_only_local_pool_mode: dynamic_top_fraction
task_normal_only_local_top_fraction: 0.05
task_normal_only_local_top_min: 3
task_normal_only_local_top_max: 20

task_normal_only_sequence_surprise_enabled: false
task_normal_only_sequence_weight: 0.0

task_normal_only_event_vocabulary_version: legacy_tc3_core_v1
task_normal_only_event_input_mode: legacy_aggregate
task_normal_only_full_event_stats_enabled: true
task_normal_only_event_type_encoding: learned_embedding
task_normal_only_event_aggregation_mode: run_length
task_normal_only_event_aggregation_window_seconds: 1
task_normal_only_keep_rare_security_events: true

task_normal_only_gnn_type: directed_gin
task_normal_only_gnn_layers: 2
task_normal_only_gnn_hidden_dim: 128
task_normal_only_gnn_dropout: 0.0
task_normal_only_gnn_train_eps: true
task_normal_only_gnn_fusion: concat

task_normal_only_mask_enabled: false
task_normal_only_mask_rate: 0.30
task_normal_only_mask_non_root_only: true
task_normal_only_sce_alpha: 2.0

task_normal_only_child_prediction_enabled: false
task_normal_only_child_loss_weight: 0.5
```

所有配置必须写入模型 checkpoint 和实验 summary。

## 9.4 checkpoint 内容

checkpoint 至少保存：

- 模型结构版本；
- Git commit；
- 完整配置；
- 随机种子；
- 数据集；
- module1 bundle 指纹；
- 事件词表版本；
- 原始到统一事件语义映射；
- 事件聚合与采样配置；
- 各事件类型的原始数、保留数和覆盖率；
- 训练任务 ID；
- 验证任务 ID；
- 校准任务 ID；
- scaler；
- KMeans/KNN/FAISS 索引；
- GNN 权重；
- decoder 权重；
- 阈值；
- 分组阈值；
- 分数中心和尺度；
- 训练损失历史；
- 最佳 epoch；
- 依赖版本。

## 10. 实验矩阵

## 10.1 基础矩阵

除 `N0-Legacy` 外，下表每个阶段都必须分别运行 `-Core` 和 `-Extended` 两个事件输入版本。例如 `N4-Core` 与 `N4-Extended`。两条线使用相同任务图、数据划分、模型容量、随机种子和目标良性误报率。

| 实验 ID | 编码器 | 局部分数 | 全局分数 | 校准 |
|---|---|---|---|---|
| N0 | 无新增 GNN | 节点 KMeans Top-3 | 图 KMeans | 单一 99% 分位数 |
| N0-C | 无新增 GNN | 同 N0 | 同 N0 | 时间块/Conformal |
| N1 | 无新增 GNN | 节点 KNN 动态 Top-K | 图 KNN | 时间块/Conformal |
| N2 | 无新增 GNN | KNN + 序列误差 | 图 KNN | 时间块/Conformal |
| N3 | 有向 GIN | 上下文 KNN | 图表示 KNN | 时间块/Conformal |
| N4 | 有向 GraphMAE | 重建误差 Top-K | 图表示多原型/KNN | 时间块/Conformal |
| N5 | 有向 GraphMAE | 重建 + 子进程预测 | 图表示多原型/KNN | 时间块/Conformal |
| N6 | N5 | 同 N5 | 同 N5 + 跨任务关联 | 时间块/Conformal |

## 10.2 必做消融

### 事件输入消融

| 实验 ID | 事件输入 | 是否重训 LSTM-GRU | 目的 |
|---|---|---:|---|
| E0 | 当前数据集各自白名单和现有编号 | 否 | 历史兼容基线 |
| E1 | E0 + 全事件统计旁路 | 否 | 验证遗漏事件是否能以低风险方式补充 |
| E2 | 统一语义词表 + 压缩保序序列 | 是 | 消除跨数据集编号冲突并扩大语义覆盖 |
| E3 | E2 + 全事件统计旁路 | 是 | 推荐完整输入 |
| E4 | 全部原始事件逐条输入 | 是 | 仅作小规模上限对照，不作为默认主线 |

每个事件输入实验必须报告：

- 原始事件类型数；
- 保留事件类型数；
- 原始事件条数；
- 输入摘要条数；
- 总体保留比例；
- 各语义类别保留比例；
- 零历史向量进程数量；
- 只有过滤事件的进程数量；
- GT 进程的事件覆盖情况；
- 解析时间和峰值内存。

### 校准消融

- 单一分位数；
- 多时间块分位数；
- 全局 conformal；
- 按根进程族 conformal；
- 滚动校准。

### 正常模型消融

- 单 KMeans；
- 多 KMeans；
- KNN；
- 对角协方差 GMM；
- Deep SVDD；
- 多中心 Deep SVDD，可选。

### 图结构消融

- 不使用边；
- 无向 GraphSAGE；
- 无向 GIN；
- 只用父到子 GIN；
- 只用子到父 GIN；
- 双向 GIN。

### 自监督目标消融

- 只用下一事件预测误差；
- 只用掩码重建；
- 只用父子预测；
- 掩码重建 + 父子预测；
- 掩码重建 + 序列误差；
- 三者联合。

### 局部聚合消融

- mean；
- max；
- Top-1；
- Top-3；
- Top-5；
- Top-5%；
- 动态 Top-K。

### 全局分数消融

- 无全局分数；
- root；
- mean；
- max；
- root + mean + max；
- 学习图表示 + KNN；
- 学习图表示 + 多原型。

## 10.3 随机性要求

每个需要训练的实验至少运行 3 个种子：

```text
seed = 17, 173, 2027
```

论文最终结果建议 5 个种子。

必须报告：

- 均值；
- 标准差；
- 每个种子的恶意图分数；
- 每个种子的误报任务 ID；
- 阈值波动；
- 最佳与最差种子的差异原因。

## 11. 评估指标

## 11.1 图级检测指标

必须报告：

- ROC-AUC；
- PR-AUC；
- Precision；
- Recall；
- F1；
- MCC；
- Accuracy，仅作补充；
- Recall@0.1% 良性 FPR；
- Recall@0.5% 良性 FPR；
- Recall@1% 良性 FPR；
- 每天误报告警数；
- 恶意图排名；
- Top-N 命中率。

在恶意图极少时，不能只看 Accuracy。

## 11.2 校准指标

必须报告：

- 校准样本数；
- 阈值；
- 阈值所在的经验分位点；
- 最小可分辨 conformal p 值；
- 校准期预计误报数；
- 测试期实际误报数；
- 不同时间块阈值范围；
- 不同任务族阈值范围；
- 阈值是否被单个极端样本控制。

## 11.3 节点定位指标

如果 GT 能映射到进程节点，报告：

- GT 进程进入 Top-1、Top-3、Top-5 的比例；
- GT 进程的平均排名；
- GT 进程一跳邻居的覆盖率；
- 高分节点是否位于攻击链上；
- 高分良性节点的人工归因。

如果 GT 包含对象 UUID，应先通过原始事件映射到关联进程，再评估节点定位，不能直接把对象 UUID 当进程 UUID。

## 11.4 运行成本

报告：

- module1 读取时间；
- 训练时间；
- 单图推理时间；
- 峰值 CPU 内存；
- 峰值 GPU 显存；
- checkpoint 大小；
- KNN 记忆库大小；
- 大图和小图的推理时间差异。

## 11.5 事件覆盖指标

必须按数据集和进程分别统计：

- 原始事件总数；
- 原始事件类型数；
- 白名单保留事件数；
- 压缩后序列条目数；
- 事件条数保留率；
- 事件类型保留率；
- 每类安全相关事件的保留率；
- 无任何保留历史的进程数；
- 有原始行为但最终为零向量的进程数；
- GT 进程原始事件和保留事件的差异；
- 不同事件词表下同一进程表示的变化。

事件条数保留率和安全语义覆盖率必须分开报告。不能因为高频 `READ` 被保留，就得出整体语义覆盖充分的结论。

## 12. 固定诊断产物

每个实验目录至少包含：

```text
config_resolved.json
data_split.json
dataset_fingerprint.json
event_vocabulary.json
event_coverage_by_dataset.json
event_coverage_by_process.json
training_history.json
calibration_summary.json
task_scores.json
node_scores.json
nearest_benign_neighbors.json
metrics_summary.json
false_positive_autopsy.json
false_negative_autopsy.json
step_decision_summary.json
model_checkpoint.pt
```

### `false_positive_autopsy.json`

每个误报至少记录：

- task_id；
- 根进程；
- 节点数；
- 边数；
- 时间范围；
- 最终分数；
- 局部分数；
- 全局分数；
- 序列误差；
- Top 异常进程；
- 最近良性任务；
- 是否由规模导致；
- 是否由未知任务族导致；
- 是否由时间漂移导致；
- 是否由任务切分异常导致。

### `false_negative_autopsy.json`

每个漏报至少记录：

- 恶意任务图 ID；
- GT 进程；
- GT 进程节点分数；
- GT 进程排名；
- 父子关系分数；
- 序列误差；
- 重建误差；
- 图级距离；
- 被哪个阈值挡掉；
- 是表示失败、聚合失败还是校准失败。

## 13. 成功与失败判定

## 13.1 Phase 0 成功

- TRACE 在固定 1% 良性 FPR 下不再为 0 召回；
- 或明确证明排序虽高但可接受误报率下仍无法召回；
- CADETS 误报没有失控；
- 阈值不由单个样本决定。

## 13.2 Phase 1 成功

- 相比 N0-C，至少一个数据集 PR-AUC 或固定 FPR 召回提升；
- 另一个数据集下降不超过 0.05；
- 误报任务有最近邻解释；
- 局部异常节点更接近 GT 进程。

## 13.3 Phase 3 成功

- 掩码重建在良性验证集稳定；
- 节点定位优于 KNN 基线；
- 图级 PR-AUC 或固定 FPR 召回提升；
- 不出现明显表示坍缩；
- 大图不会因均值池化完全淹没稀疏异常。

## 13.4 失败产物规则

失败实验：

- artifact 名称必须带 `_failed_`；
- 保留关键日志和失败 summary；
- 删除无诊断价值的大型中间缓存；
- 不覆盖成功基线；
- `step_decision_summary.json` 写明失败阶段；
- 记录失败是代码错误、资源错误、数据错误还是模型无收益。

## 14. 风险与应对

| 风险 | 表现 | 应对 |
|---|---|---|
| 阈值仍不稳定 | 不同时间块差异很大 | 滚动校准、分任务族校准、报告每天误报数 |
| 表示坍缩 | 所有节点重建误差很低且表示相似 | 冻结教师、减弱解码器、监控表示方差 |
| 大图稀释异常 | mean pooling 下恶意图接近良性 | 动态 Top-K、max、局部重建分数 |
| 小图掩码过强 | 遮盖后无足够上下文 | 小图至少保留根和一个邻居 |
| 正常任务多峰 | 单中心误报高 | KNN、多原型、任务族条件化 |
| 任务切分噪声 | 图结构反映切分规则 | 第一版不做边重建，保留切图诊断 |
| 数据漂移 | 新日期大量误报 | 滚动记忆库、只吸收高置信良性样本 |
| 攻击污染记忆库 | 异常被加入正常库 | 延迟更新、人工确认、严格低分更新 |
| 跨数据集不稳定 | TRACE 好而 CADETS 差 | 共享模型结构，独立 scaler、记忆库和阈值 |
| 计算成本过高 | 大图训练显存不足 | 2 层 GIN、图批大小自适应、节点采样诊断 |

## 15. 明确不建议的做法

### 不建议直接用恶意图选择阈值

这会破坏良性样本检测的实验设定，并高估未知攻击检测能力。

### 不建议一开始同时更换所有组件

如果同时改：

- LSTM-GRU；
- GNN；
- 图切分；
- Top-K；
- 全局距离；
- 阈值；

最终无法判断收益来自哪里。

### 不建议直接把 MAGIC 整套 DGL 流程接入

当前项目已经使用 PyG。引入第二套图框架会增加：

- 依赖冲突；
- 数据复制；
- GPU 内存占用；
- artifact 格式差异；
- 调试成本。

### 不建议第一版重建任务图边

进程父子边主要反映任务构造和切分。重建边可能强化切图偏差，不一定强化攻击检测。

### 不建议只报告 ROC-AUC

TRACE 当前已经证明，ROC-AUC 很高仍可能在实际阈值下 0 召回。必须同时报告 PR-AUC、固定 FPR 召回、误报数和阈值。

### 不建议把所有数据集混用一个阈值

不同数据集：

- 日志来源不同；
- 任务图规模不同；
- 正常任务类型不同；
- 进程表示分布不同。

可以共享模型结构，但默认应独立训练或至少独立校准。

## 16. 推荐的最近实施顺序

### Step A0：冻结并审计事件输入

在更换模型前，先对 TRACE 和 CADETS 生成：

- 原始事件类型和数量；
- 当前白名单；
- 跨数据集事件编号对照；
- 每个进程原始事件数和保留事件数；
- 零历史向量进程；
- GT 进程遗漏的事件；
- 只发生过滤事件的进程；
- 当前 6 维输入每一维的准确语义。

这一阶段不修改模型，用于建立可解释输入基线。

### Step A：冻结当前基线

保存：

- TRACE 当前模型；
- CADETS 当前模型；
- 完整逐图分数；
- 验证分数分布；
- 最高分良性图；
- 所有恶意图分数；
- 数据划分 ID。

### Step B：只改校准

在相同原始分数上比较：

- 当前 99% 分位数；
- 多时间块分位数；
- 全局 conformal；
- 任务族 conformal。

不重跑 module1。

### Step C：KNN 对照

复用同一 module1 bundle：

- 节点 KMeans → 节点 KNN；
- 图 KMeans → 图 KNN；
- 固定 Top-3 → 动态 Top-K。

### Step D：接入序列误差

当前代码已经确认不能从现有推理输出直接得到逐进程预测误差。需要：

- 保留现有进程表示；
- 先跑 E1，即现有表示加全事件统计旁路；
- 再建立统一语义词表；
- 增加只在良性进程历史上训练的下一交互摘要或下一语义事件预测头；
- 输出逐进程序列异常分数；
- 不修改任务图构造。

### Step E：实现有向 GIN

先只做图上下文编码和 KNN，不做掩码重建，以隔离编码器收益。

### Step F：实现 GraphMAE 掩码重建

以 GraphMAE PyG 分支为骨架：

- 接入当前 `Data`；
- 添加双方向 GIN；
- 冻结进程教师表示；
- 输出节点重建误差；
- 接入动态 Top-K。

### Step G：父子预测

只在掩码重建稳定后加入。

### Step H：跨任务关联

只在单图检测和节点定位稳定后加入。

## 17. 实施记录模板

每完成一步，在这里追加：

```text
日期：
步骤：
Git commit：
代码基线：
数据集：
module1 artifact：
module2 artifact：
改动内容：
实验目的：
训练/验证/校准/测试数量：
阈值：
TRACE 指标：
CADETS 指标：
节点定位结果：
误报变化：
漏报变化：
成功或失败：
原因：
是否进入下一步：
```

## 18. 当前结论

2026-07-31 的 CADETS 事件覆盖统计旁路三路线实验已完成，完整记录见 [cadets_event_coverage_normal_only_experiment_2026-07-31_zh.md](cadets_event_coverage_normal_only_experiment_2026-07-31_zh.md)。结果支持保留核心事件统计旁路；扩展事件统计未在当前模型下带来额外固定阈值收益。

当前最重要的判断不是“GraphSAGE 不够好”，而是：

1. 当前 normal-only 分支根本没有使用 GraphSAGE；
2. 当前进程表示已经具有较好的异常排序信息；
3. TRACE 首要问题是良性验证尾部过小导致的阈值失稳；
4. CADETS 说明单纯 KMeans 原型不足以覆盖复杂正常任务；
5. 当前方法没有使用父子进程上下文；
6. 当前方法丢弃了 LSTM-GRU 下一事件预测误差；
7. 固定 Top-3 对图规模变化不稳健；
8. 深层改造最适合采用 GraphMAE PyG + 有向 GIN；
9. MAGIC 适合参考掩码重建和异常检测细节，但不适合整套迁移；
10. ORTHRUS 和 KAIROS 适合参考时间预测、归因和跨任务关联；
11. Deep SVDD 应作为消融基线，不应替代多模态正常模型；
12. 所有阶段都必须先保证良性校准协议正确，才能解释模型收益。
13. 当前 LSTM-GRU 只编码数据集白名单事件，不代表完整系统行为；
14. TRACE 与其他数据集的事件编号存在语义冲突，旧 checkpoint 不能被视为统一事件语义模型；
15. 当前 parser 会聚合重复的进程-对象交互，现有输入不是逐条原始事件时间序列；
16. GraphMAE 无法恢复输入中不存在的事件，必须增加全事件统计旁路，并逐步训练统一语义事件编码器。

推荐主线最终形态：

```text
良性进程历史训练
→ 统一并版本化事件语义
→ 全事件统计旁路
→ 冻结 LSTM-GRU
→ 有向 GIN 学习父子上下文
→ 掩码进程表示重建
→ 下一事件预测误差
→ 父子行为预测误差
→ 动态 Top-K 局部异常
→ KNN/多原型全局异常
→ 良性时间校准
→ 图级告警与进程级定位
→ 可选跨任务攻击关联
```

这条路线既保留当前方案已经有效的进程表示和任务图接口，又逐步补上阈值、局部行为、父子上下文和多模态正常分布建模的缺口，能够通过逐阶段消融明确判断每项改动是否真正有效。

## 补充记录：2026-08-02 统一语义序列 E1/E2/E3 实验

本轮没有运行 module0。三条路线都使用相同的正常样本时间切分、2% 良性验证分位阈值、KMeans 全局正常模型和自适应局部 Top-K（上限 16），只比较输入表示：

- E1：原有 LSTM-GRU 过程表示，加安全语义统计旁路。
- E2：把日志事件映射为 15 类稳定语义摘要，在良性训练进程上以“预测下一类摘要”为目标重新训练 LSTM-GRU；不使用统计旁路。
- E3：复用 E2 的冻结语义序列编码器，再加入与 E1 完全相同的统计旁路。

| 数据集 | 路线 | Macro Precision | Macro Recall | Macro F1 | TP / FP / FN | PR-AUC |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| CADETS | E1 | 0.6471 | 0.9924 | 0.7234 | 5 / 12 / 0 | 0.6962 |
| CADETS | E2 | 0.6046 | 0.8905 | 0.6615 | 4 / 15 / 1 | 0.2078 |
| CADETS | E3 | 0.6532 | 0.8943 | 0.7190 | 4 / 9 / 1 | 0.3154 |
| TRACE | E1 | 0.9970 | 0.8750 | 0.9271 | 3 / 0 / 1 | 1.0000 |
| TRACE | E2 | 0.4883 | 0.5000 | 0.4941 | 0 / 0 / 4 | 0.7955 |
| TRACE | E3 | 0.9941 | 0.7500 | 0.8304 | 2 / 0 / 2 | 1.0000 |

结论：E2 在两个数据集上都明显退化；E3 能减少 CADETS 误报（12 降至 9），但漏掉 1 张恶意图，且 TRACE 从 3/4 降为 2/4。因而没有任何语义序列路线同时优于 E1，不能进入“冻结语义编码器 + 有向 GIN”对照阶段。本轮保留统一语义词表、良性序列预训练接口和预测误差诊断产物，后续应先改善序列摘要的时序保真度或把预测误差作为受控旁路特征，再重新评估图编码器。

### TAPAS 原始 LSTM-GRU 训练核对与重跑规范

TAPAS 原文的离线目标是：以某进程当前的过程表示预测该进程下一条事件的嵌入向量；其报告的表示生成模型超参数为学习率 `0.1`、学习率衰减因子 `0.1`、衰减率 `500`。当前主线此前仅加载已有 `stackedlstm_tc.pt`，并未在本轮 TRACE/CADETS 日志上训练。此前的辅助重训练脚本虽已采用“下一条事件向量”目标，但使用 `1e-3` 的学习率、`AdamW`、早停，且没有 500 次更新的衰减，因此不能称为原文参数对齐实验。

本轮重跑将使用与 TAPAS 运行时完全兼容的 6 维事件嵌入和同一 LSTMCell-GRUCell 结构：输入 `x[t]`，预测归一化后的 `x[t+1]`，仅以非填充位置的均方误差训练。原文没有说明优化器及“500”的计量单位；实现中明确采用 Adam，并把衰减率解释为每 500 次参数更新执行一次 `StepLR(gamma=0.1)`，使该假设可复现、可审计。为保持 normal-only 检测实验不利用攻击标签训练表示模型，训练进程限定为模块 2 正常训练时间段内的良性任务图节点；检测器仍使用完全相同的 module1/module2 配置，且不运行 module0。

### 2026-08-02 论文参数对齐重训练结果

所有路线都重新运行 module1/module2，未运行 module0，未使用任务图复制式数据增强。分类器、切图、安全语义统计、正常原型模型、Top-K 规则和 2% 良性验证阈值保持不变；唯一实验变量是过程表示 checkpoint。

| 数据集 | 表示 checkpoint | 训练更新/衰减 | TP / FP / FN | Macro Precision | Macro Recall | Macro F1 | PR-AUC |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| CADETS | 随附旧 checkpoint | 无本轮训练 | 5 / 12 / 0 | 0.6471 | 0.9924 | 0.7234 | 0.6962 |
| CADETS | 论文参数对齐重训练 | 1,500 / 3 次 | 5 / 12 / 0 | 0.6471 | 0.9924 | 0.7234 | 0.6696 |
| TRACE | 随附旧 checkpoint | 无本轮训练 | 3 / 0 / 1 | 0.9970 | 0.8750 | 0.9271 | 1.0000 |
| TRACE | 对齐重训练，24 epoch | 552 / 1 次 | 4 / 1 / 0 | 0.9000 | 0.9970 | 0.9429 | 1.0000 |
| TRACE | 对齐重训练，直到 1,500 更新 | 1,500 / 3 次 | 4 / 0 / 0 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |

CADETS 训练使用 149,533 条符合良性训练任务节点集合的过程历史，其中 134,580 条用于序列训练、14,953 条用于序列验证；3 个 epoch 内达到 1,500 次更新。TRACE 对应为 6,524 / 5,872 / 652 条历史；因每个 epoch 的 batch 较少，需 66 个 epoch 才达到 1,500 次更新。两个数据集的学习率轨迹均为 `0.1 -> 0.01 -> 0.001 -> 0.0001`。

结论：原文目标和超参数对齐本身对 TRACE 有明确收益，且收益在完整 1,500-step 日程后消除了此前的 1 张误报；CADETS 的任务级检出不变，PR-AUC 略降，因此不能把它宣称为跨数据集统一提升。后续方向图模型实验将把“论文参数对齐过程表示 + 安全语义统计”列为 G0 候选基线，但必须保持 CADETS、TRACE 独立训练和独立阈值，并至少补做不同随机种子复验后才作为最终默认模型。

边界说明：这一轮对齐的是训练目标、模型接口和学习率日程，不是“逐条原始审计事件”的完全复现。当前 TAPAS parser 仍会合并重复的进程-对象-事件组合，因此输入历史保留了交互类别和首次出现顺序，但会丢失同一组合的重复次数与精确间隔。若后续要验证原文所说的“丰富事件序列细节”，应另建流式原始事件序列抽取器，并将其作为独立输入消融，不能与本轮 checkpoint 直接混称。

## 19. 2026-07-31 CADETS 第二轮验证结论

第二轮没有直接引入更重的图模型，而是先验证了三个影响正常样本检测稳定性的设计：更贴近攻击语义的动作统计、随任务图规模自适应的局部异常聚合，以及 KMeans 与 KNN 两种全局正常模型。完整结果见 [cadets_event_coverage_normal_only_experiment_2026-07-31_zh.md](cadets_event_coverage_normal_only_experiment_2026-07-31_zh.md)。

结论是：安全语义统计配合自适应 Top-K 和 KMeans 已在不使用攻击图训练、且 5 张攻击图全部留作最终测试的条件下取得本轮最佳结果：5/5 检出、5 张误报正常图、Macro F1 为 0.8317。后续在此基线上再引入有向图编码、掩码重建或父子上下文，避免同时改变过多环节而无法判断收益来源。KNN 的 PR-AUC 更高但分数尺度不稳且固定阈值误报更多，暂保留为后续集成对照而非默认方案。
