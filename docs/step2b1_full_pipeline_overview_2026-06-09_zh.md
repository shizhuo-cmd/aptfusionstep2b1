# APT-Fusionstep2b1 当前全流程总览

本文档用于总结 `D:\daima\APT-Fusionstep2b1` 当前代码版本的完整处理链，目标是给后续 PPT 制作提供一份“从原始日志到最终评估”的总说明。  
时间边界以本地工作区 `2026-06-09` 的当前代码为准，包含此前为 TRACE 做过的 `truth-gap`、`family 保留`、`tactics-only`、`no ATT&CK prior` 等能力，但这些能力是否启用取决于具体配置文件。

## 1. 一句话总览

`APT-Fusionstep2b1` 当前是一条“先做任务图检测，再围绕可疑任务恢复局部证据，再把局部证据压缩成候选攻击链，最后让规则+大模型输出 ATT&CK 战术/技术”的流水线。

整体主线可以概括为：

```text
原始日志
-> module0 轻预处理
-> module1 构建任务图与进程嵌入
-> module2 检测可疑任务图
-> module3 围绕可疑任务回查原始日志，恢复局部证据图
-> module4 对局部证据图做语义压缩、轻标签、对象版本跟踪
-> module5 在压缩后的证据图上构造 CandidatePath
-> module6 基于 CandidatePath 生成 claims，再映射到 ATT&CK
-> evaluation 评估命中窗口、战术、技术与噪声
```

## 2. 主流程分层理解

从功能上看，这条流水线可以分成 4 层：

1. `任务图检测层`
   先把全量原始日志切成任务图，再判断哪些任务图更像恶意图。
2. `局部证据恢复层`
   不再盲目看全日志，而是围绕可疑任务图去原始日志里回查相关进程、对象和事件。
3. `攻击链构造层`
   对回查出的局部证据做压缩、打标签、建桥接，再构造成少量候选攻击链。
4. `攻击语义解释层`
   把候选链转成 dossier 和 claims，再映射成 ATT&CK 战术/技术，最后评估。

这 4 层分别解决的问题是：

| 层级 | 解决的问题 |
| --- | --- |
| 任务图检测层 | 全量日志太大，先把可疑范围缩小到少量任务图 |
| 局部证据恢复层 | 模块2只有“这张图可疑”，但没有足够事件细节，需要回日志补全 |
| 攻击链构造层 | 原始事件太碎，必须压缩和整理成模型可理解的链条 |
| 攻击语义解释层 | 证据链本身不等于 ATT&CK，需要再做攻击语义归纳和映射 |

## 3. 代码中的实际运行入口

当前 CLI 里与这条主线相关的 stage 主要有：

| stage | 作用 |
| --- | --- |
| `module0` | 原始日志轻预处理 |
| `module1` | 任务图构建 |
| `module2` | 任务图恶意检测 |
| `module3_evidence` | 局部证据恢复 |
| `module4_compact` | 语义压缩 |
| `module5_paths` | 候选链构造 |
| `module6_reason` | claims + ATT&CK 输出 |
| `full_path_reason` | 贯通执行模块0到模块6 |

需要注意两点：

1. 真正的“攻击链推理主线”核心是 `module3 -> module4 -> module5 -> module6`。
2. `module0` 并不是 `module1` 的强依赖；`module1` 当前主要还是直接从原始日志走 TAPAS/TAPAS vendor 逻辑构建任务图，`module0` 更像一个通用预处理与 RDF sidecar。

## 4. 输入数据与总体配置

当前项目最重要的几类输入是：

| 输入 | 含义 |
| --- | --- |
| `source_logs` | 原始 DARPA/TRACE/CADets/Theia 等日志目录或文件 |
| `module1` 产物 | 每个进程的 embedding、任务图切分结果、分割边 |
| `module2` 产物 | 每个任务图的恶意分数、可疑任务清单、rich meta、attribution |
| 规则文件 | 事件归一化规则、语义标签规则、ATT&CK KB 检索规则 |
| 评估 GT | 窗口级攻击真值、战术/技术真值 |

当前项目常见的数据流是：

```text
source_logs
-> module1 artifacts
-> module2 suspicious task artifacts
-> module3 local evidence artifacts
-> module4 compact artifacts
-> module5 candidate path artifacts
-> module6 report artifacts
-> evaluation artifacts
```

## 5. Module0：轻预处理

### 5.1 目标

`module0_preprocess.py` 的目标是把原始 CDM 日志做一个轻量抽取，产出统一的事件流和 RDF sidecar，方便后续做图数据库或调试。

### 5.2 做了什么

它会扫描原始日志中的：

- `Event`
- `Subject`

并抽取一些最基础字段，例如：

- 事件类型
- 时间戳
- subject uuid
- object uuid

然后写出：

- `module0/process_events.jsonl`
- `module0/rdf_stream.nt`

如果配置了 GraphDB 地址，还可以把 RDF triples 批量推送到 GraphDB。

### 5.3 方法特点

这个模块的方法很轻：

- 不是做完整语义恢复
- 不是做标签推理
- 主要是做“统一格式化”和“可被图工具消费的 sidecar”

### 5.4 在当前主线里的位置

它在当前 `step2b1` 里不是攻击推理核心。  
核心检测和链条恢复并不依赖 `module0` 的 RDF 结果，而是主要依赖 `module1/module2` 和之后对原始日志的二次扫描。

## 6. Module1：任务图构建

### 6.1 目标

`module1` 的目标是把全量日志切成“任务图”，并为图中的进程节点生成表示向量。  
这是整个系统的第一道“缩小搜索空间”的步骤。

### 6.2 用了什么方法

当前 `step2b1` 的 `module1` 主要复用 TAPAS 的原生构图逻辑，代码入口在：

- `src/apt_fusion/task_detection/module1_online_graph.py`
- `src/apt_fusion/task_detection/tapas_native_backend.py`
- `vendor/tapas/darpa.py`

对 TC3 类数据集，核心流程大体是：

1. 解析原始日志
2. 按 TAPAS 的 subject/process 逻辑构建基础进程图
3. 对进程关系做切分，形成任务图
4. 为图中进程节点计算 embedding
5. 导出任务图结构和进程 embedding

### 6.3 数据处理细节

对于 TRACE/CADets/Theia 这类 DARPA TC3 风格数据，`module1` 做的事情包括：

| 处理 | 作用 |
| --- | --- |
| `parser_trace(...)` / 对应 host parser | 从原始日志解析进程和边 |
| `encode_trace(...)` | 编码成模型可用的图表示 |
| `cut_task(...)` | 把全局图切成多个任务图 |
| `decompose(...)` | 输出图分解结果与节点向量 |

任务图切分时，当前代码支持：

- 基于子进程数量阈值的切分
- 基于连通性或组件规则的切分

这就是之前你反复提到的“子进程数大于 2 就分割”等规则所在位置。

### 6.4 OCR-style 统计特征增强

当前 `step2b1` 的 `module1` 还支持对每个进程补充一组 OCR-style 统计特征，来源于：

- `src/apt_fusion/task_detection/ocr_stat_features.py`

这些统计特征是重新扫一遍原始日志后，为每个进程计算出来的，典型包括：

- 执行类事件次数
- 文件读写次数
- 网络收发次数
- 平均空闲时间
- 最大/最小空闲时间
- 累积活跃时间
- 生命周期长度

在当前代码默认配置下，这些统计特征**不会再拼到 GraphSAGE 节点向量里**。  
默认策略已经改成：

- `GraphSAGE` 主干只吃进程表示向量，也就是 sequence/process embedding
- OCR-style 统计特征单独保留，专门给 `module2` 的图统计 late-fusion sidecar 使用

只有在显式打开 `graphsage_append_ocr_stat_features=true` 时，统计特征才会重新拼到 GraphSAGE 的节点向量后面。

虽然默认不再拼到 GraphSAGE 节点向量里，但这些统计特征仍然会保存在 `module1` 的 native bundle 与 summary 元信息中，供 `module2` 的图统计 late-fusion sidecar 直接读取。

### 6.5 输出

`module1` 当前核心输出有：

| 文件 | 含义 |
| --- | --- |
| `process_embeddings.csv` | 每个进程给 GraphSAGE 使用的 embedding 向量，默认是 sequence/process embedding |
| `task_subgraphs.json` | 任务图列表及其节点、边 |
| `process_segmentation_edges.csv` | 任务切分边信息 |
| `tapas_native_graphs.pt` | 模型直接可用的图对象 |
| `tapas_native_module1_summary.json` | 模块1汇总信息 |

### 6.6 这一层解决了什么问题

如果不做 `module1`，后面所有工作都要直接面对全量原始日志，范围太大。  
`module1` 的作用就是先把“全局行为世界”切成很多局部任务图，给后面的恶意图检测做基础。

## 7. Module2：任务图恶意检测

### 7.1 目标

`module2` 的目标是对 `module1` 产出的任务图打分，筛出疑似恶意任务图。  
这是后续 path reasoning 的入口筛选器。

### 7.2 主体方法

当前 `step2b1` 的 `module2` 主体是：

- GraphSAGE 图分类分数
- 可选的图统计 sidecar 分类器
- 最后做 late fusion

也就是说，它不是单一模型，而是“图神经网络主分数 + 统计模型补充分数”的结构。

### 7.3 GraphSAGE 在哪里用

GraphSAGE 是 `module2` 里的主模型。  
它负责读取 `module1` 形成的图数据，对每张任务图输出恶意概率。

可以把它理解为：

- 输入：任务图结构 + 节点 embedding
- 输出：这张任务图像不像恶意图

在当前默认配置下，这里的“节点 embedding”指的是**仅 sequence/process embedding**，不再默认混入 OCR-style 统计特征。  
也就是说，`GraphSAGE` 主干现在默认看的是“进程表示”，不是“进程表示 + 统计特征拼接向量”。

### 7.4 XGBoost 在哪里用

XGBoost 不在 `module1`，也不在 `module5/6`。  
它在 `module2` 的图统计 sidecar 里使用。

它读的是图级统计量，而不是原始事件序列。  
当前默认策略下，OCR-style 统计特征就是专门给这条 sidecar 支路使用的。  
如果启用了 graph stat late fusion，那么流程是：

1. GraphSAGE 给出一份概率
2. 图统计 sidecar 分类器给出另一份概率
3. 按 `task_graph_stat_fusion_weight` 做融合

sidecar 优先用：

- `XGBClassifier`

如果环境里没有 xgboost，才会退化到：

- `HistGradientBoostingClassifier`

### 7.5 图统计 sidecar 看什么

sidecar 看的是任务图级别或节点统计汇总，不是完整的因果链。  
它更像一个“补充判别器”，用于弥补纯 GraphSAGE 可能漏掉的图统计异常。  
当前默认实现中，统计特征只在这条补充分支里发挥作用，而不再默认进入 GraphSAGE 主干。

### 7.6 输出

`module2` 的核心输出包括：

| 文件 | 含义 |
| --- | --- |
| `process_scores.csv` | 进程级优先级导出 |
| `suspicious_tasks.json` | 可疑任务图清单 |
| `task_meta_rich.json` | 图级 rich metadata |
| `task_attribution.json` | 任务内 top process / top edge 归因 |
| `run_0_raised_alarms.csv` | 兼容式告警导出 |
| `task_thresholds.json` | 阈值信息 |

### 7.7 `task_meta_rich` 和 `task_attribution` 的意义

这两个 sidecar 对后面的 `module3` 很重要：

- `task_meta_rich` 给出了任务图的 richer 结构信息
- `task_attribution` 给出了任务内“更值得关注”的进程和边

后面 `module3` 恢复证据时，会把它们当作回查的先验。

### 7.8 这一层解决了什么问题

它把上千上万张任务图缩到少量可疑图。  
如果没有这一步，后面的事件级证据恢复和链条构造成本会非常高。

## 8. Module3：围绕可疑任务回查原始日志，恢复局部证据图

### 8.1 目标

`module3_evidence_recover.py` 的目标是：  
围绕 `module2` 认定的可疑任务，回到原始日志里把这个任务相关的真实事件、进程、对象重新恢复出来，形成“任务内局部证据图”。

### 8.2 为什么需要这一步

`module2` 只知道“这张任务图有问题”，但还没有足够事件级语义去让后续做攻击链分析。  
所以 `module3` 要把任务图重新连接回原始日志，恢复出：

- 哪些进程真的做了什么
- 它们读写了哪些对象
- 哪些网络连接、文件对象、父子进程链和该任务有关

### 8.3 方法概括

这一步不是直接吃全量日志，而是“围绕种子任务做局部回查”。

主要做法是：

1. 从 `suspicious_tasks.json` 里取出可疑任务
2. 结合 `task_meta_rich` 和 `task_attribution` 建立 task priors
3. 用 task 里的进程、边、边界节点做 seed frontier
4. 回扫原始日志
5. 把和这些 seed 有关的事件抽出来
6. 做统一归一化，产出 `NormalizedEvent`
7. 构造成任务内局部证据图

### 8.4 它恢复了哪些信息

每条被保留的原始事件会被标准化成一个 `NormalizedEvent`，典型字段包括：

- 归一化事件类型
- 时间戳
- 进程 guid / 进程名 / 可执行文件 / 命令行
- 父进程 guid
- 对象 key / 对象名 / 对象类型
- 网络四元组
- 系统调用方向
- 语义流向

### 8.5 任务内局部证据图是什么

`module3` 最关键的输出是 `TaskLocalEvidenceGraph`。  
它不是全局事件图，而是一个“围绕当前任务图的局部因果证据图”。

里面主要有：

| 组成部分 | 含义 |
| --- | --- |
| `process_nodes` | 本任务相关的进程节点 |
| `object_nodes` | 本任务相关的文件、网络、pipe 等对象节点 |
| `event_edges` | 连接进程和对象的事件边 |
| `anchor_processes` | 作为回查锚点的进程 |
| `boundary_node_ids` | 任务边界节点 |
| `cross_task_link_refs` | 与别的任务图可能相关的跨任务引用 |

### 8.6 输出

每个任务会输出：

| 文件 | 含义 |
| --- | --- |
| `normalized_events/<task>.jsonl` | 归一化事件流 |
| `entity_index/<task>.json` | 任务内实体索引 |
| `process_event_index/<task>.json` | 进程到事件的索引 |
| `object_event_index/<task>.json` | 对象到事件的索引 |
| `task_evidence_frontier/<task>.json` | 回查前沿 |
| `task_local_evidence_graph/<task>.json` | 局部证据图 |

全局还会输出：

- `task_index.json`
- `priors_by_task.json`
- `id_mapping.json`
- `summary.json`

### 8.7 这一层解决了什么问题

`module3` 解决的是“有可疑图，但没有细证据”的问题。  
它把图级可疑任务重新落回事件级证据世界，为后面的标签和链条恢复打基础。

## 9. Module4：局部证据压缩、轻标签、对象版本跟踪

### 9.1 目标

`module4_semantic_compact.py` 的目标是把 `module3` 恢复出来的事件流做语义压缩，并维护后续路径推理需要的状态。

这一步是从“很多原子事件”过渡到“可推理的语义单位”。

### 9.2 这一步为什么关键

从原始日志回查出来的事件通常很多，而且有大量重复语义。  
如果直接用这些事件去搜索攻击链：

- 噪声会很大
- 路径会爆炸
- 大模型也难以理解

所以这一步要做：

- 去冗余
- 轻量打标签
- 对象版本跟踪
- 访问关系记录
- 事件分段聚合

### 9.3 核心方法 1：Semantic Skipping

这里实现了一种轻量的语义压缩机制。  
同一种进程、同一种对象、同一语义模式下反复出现的事件，会被认为是语义重复，从而被跳过。

但不是所有重复都能跳过。  
下面这些情况通常会被强制保留：

- 触发关键标签的事件
- 外部网络接收
- 执行、加载、映射关键对象
- 写入会改变对象版本的事件

这一步的目标是：

- 保留“语义转折点”
- 压掉“重复噪声”

### 9.4 核心方法 2：轻标签体系

`module4` 会为进程和对象打一些轻量标签，这些标签不是最终 ATT&CK，而是后续候选链构造的中间语义支撑。

当前常见标签包括：

#### 进程上下文标签

| 标签 | 含义 |
| --- | --- |
| `P_WEB_CTX` | 进程处在 Web 相关上下文 |
| `P_REMOTE_CTX` | 进程处在远程交互上下文 |
| `P_NET_CTX` | 进程有明显网络上下文 |
| `P_UNTRUSTED_CTX` | 进程处在不可信执行上下文 |

#### 对象语义标签

| 标签 | 含义 |
| --- | --- |
| `O_NET_EXTERNAL` | 外部网络对象 |
| `O_FILE_TEMP` | 临时文件 |
| `O_CREDENTIAL` | 凭据相关对象 |
| `O_HISTORY` | 历史/命令历史类对象 |
| `O_BUSINESS_DATA` | 业务数据对象 |
| `O_PERSISTENCE` | 持久化相关对象 |
| `O_PRIV_CONFIG` | 提权/敏感配置对象 |
| `O_FILE_UPLOADED` | 上传文件 |
| `O_FILE_NONEXIST` | 不存在或可疑新出现文件 |
| `O_FILE_DOWNLOADED` | 下载得到的文件 |

这些标签的作用不是直接输出攻击结论，而是给后续 `module5` 提供桥接、打分和 family 判断依据。

### 9.5 核心方法 3：对象版本跟踪

`module4` 会维护 `ObjectVersion`。  
也就是同一个对象在多次写入、改名、执行之后，会被看成不同语义阶段的版本。

这样做的原因是：

- 同一个文件对象在不同时间可能语义不同
- 攻击链常常依赖“谁写了这个对象、谁后来又执行/读取了这个对象”

对象版本跟踪是 `module5` 做 bridge edge 的关键前提。

### 9.6 核心方法 4：Label Provenance

`label_provenance` 记录“一个标签为什么会出现”。  
也就是：

- 哪条事件触发了这个标签
- 它来自哪个实体或哪个版本对象
- 它是初始打上的，还是继承/传播得到的

后面路径打分、family 标注、Holmes claim 恢复都会用到这些 provenance 信息。

### 9.7 输出

每个任务会输出：

| 文件 | 含义 |
| --- | --- |
| `retained_events/<task>.jsonl` | 压缩后保留的事件 |
| `access_records/<task>.jsonl` | 对象访问记录 |
| `episodes/<task>.json` | 时间桶级 episode 聚合 |
| `process_states_prepath/<task>.json` | 路径构造前的进程状态 |
| `object_states/<task>.json` | 对象状态 |
| `object_versions/<task>.json` | 对象版本状态 |
| `label_provenance/<task>.jsonl` | 标签来源记录 |

全局输出：

- `task_index.json`
- `compact_summary.json`

### 9.8 这一层解决了什么问题

它解决的是“事件太碎、对象关系不清、标签依据不透明”的问题。  
从这一层开始，系统拥有了真正可供链条推理消费的中间表示。

## 10. Module5：构造 CandidatePath

### 10.1 目标

`module5_path_finder.py` 的目标是从 `module4` 的压缩证据中恢复出少量“足够像攻击链”的候选链条，也就是 `CandidatePath`。

这是整个 `step2b1` 里最关键的一层之一，因为它决定后面的 LLM 能看到什么。

### 10.2 当前版本的总体思路

当前 `step2b1` 不是直接把整张证据图喂给大模型，而是先构造成少量 `CandidatePath`。  
这条路径保留了 `microstep2b` 的主骨架，但已经加入了当前这轮做的 truth-gap 和 family-preservation 增强。

总体流程可以概括为：

```text
process/object states + retained events + label provenance
-> 完整路径标签补全
-> 状态传播
-> bridge edge 构建
-> 搜索 CandidatePath
-> 候选链打分
-> support/lineage/family 补强
-> precursor rescue
-> family-preserved 选路
-> provenance-aware 重排
```

### 10.3 CandidatePath 是什么

`CandidatePath` 可以理解为一条“面向攻击解释的压缩链条”。  
它不是原始事件列表，也不是整张任务图，而是一条高度筛选后的攻击候选链。

它通常包含：

- 一组核心进程链
- 若干 bridge edges
- 路径中的支撑事件
- 路径涉及的关键对象
- 阶段覆盖信息
- 风险得分
- family 标签
- precursor/followup 事件集合

### 10.4 核心方法 1：Bridge Edge

`bridge_builder.py` 会尝试通过“对象版本的生产者/消费者关系”把原本不直接相邻的进程串起来。

典型逻辑是：

- 某进程写了一个可疑文件
- 另一个进程稍后执行、读取、加载这个文件
- 那么两者之间就可以建立 bridge

当前常见允许做 bridge 的对象标签包括：

- `O_FILE_TEMP`
- `O_FILE_DOWNLOADED`
- `O_FILE_UPLOADED`
- `O_SUSPECT_WRITTEN_EXECUTABLE`
- `O_ARCHIVE`
- `O_PERSISTENCE`
- `O_PRIV_CONFIG`

这一步的作用是把“通过文件/对象传播的攻击链”拼起来，而不只看父子进程。

### 10.5 核心方法 2：路径搜索

`search_candidate_paths()` 会在：

- 父子进程边
- bridge edges

组成的空间里搜索候选链。

候选链不是随便一条路径都保留，它通常需要满足一定的阶段/标签覆盖要求，才会进入后续打分。

### 10.6 核心方法 3：路径打分

`score_candidate_paths()` 会对每条候选链计算风险分数。  
当前分数大致来自：

- 标签分
- 标签组合分
- 阶段覆盖分
- bridge 分
- prior 分
- 惩罚项

也就是说，系统会优先保留那些：

- 标签更丰富
- 结构更连贯
- 对象传播关系更强
- 与任务先验更吻合

的路径。

### 10.7 当前版本新增的 family 概念

为了解决之前候选链只保住“尾巴”，丢掉“前因链”的问题，当前版本给 `CandidatePath` 新增了 `family_tags`。

这里的 family 不是 ATT&CK 技术，也不是论文原生概念，而是当前工程里用来描述“真实攻击链段类型”的诊断标签。

当前常见 family 包括：

| family tag | 含义 |
| --- | --- |
| `initial_or_drop_exec` | 初始投递或落地执行链段 |
| `attachment_or_tcexec_exec` | 附件执行或 `tcexec` 类执行链段 |
| `callback_c2` | 回连/C2 通信链段 |
| `scan_discovery` | 扫描/探测链段 |
| `cleanup_delete` | 清理/删除链段 |
| `short_lived_precursor` | 短命前因链段 |
| `mail_browser_context_tail` | 邮件/浏览器/文件读取尾巴链段 |

这些 family 的引入动机是：

- 原先纯分数 top-k 容易只保住长尾、频繁、稳定的后续行为
- 但真实攻击往往还包括短命、稀疏、前因性的关键链段
- 所以当前代码显式要求在候选集里保留不同 family 的代表路径

### 10.8 当前版本新增的 precursor rescue

这是当前 `step2b1` 为了解决 `0546` 这类“前因短、尾巴长”任务而加的补强。

当正常的候选搜索没有保住 `short_lived_precursor` 类路径时，系统会尝试在证据图中额外恢复一条：

- 同父终端
- 短时间桶内密集出现
- marker 丰富

的短命 precursor path。

这条 path 不是靠 GT 直接生成，而是必须来自当前局部证据图中已有的进程、事件和对象关系。

### 10.9 当前版本新增的 support / lineage / Holmes 字段

为了让后面的 `module6` 不再只看到一个抽象路径，当前 `CandidatePath` 又新增了这些字段：

| 字段 | 作用 |
| --- | --- |
| `precursor_event_ids` | 明确指出前因事件 |
| `followup_event_ids` | 明确指出后续结果事件 |
| `network_support_summary` | 汇总网络支撑 |
| `object_lineage_summary` | 汇总对象谱系支撑 |
| `holmes_matched_atoms` | 命中的 Holmes 风格原子 |
| `missed_truth_like_hints` | 诊断性“像是漏了真值中的哪类链段” |

这些字段的核心动机是：

- 提升 dossier 的解释力
- 让大模型更容易看见“前因 + 后果”
- 让 Holmes-style claim 生成更稳

### 10.10 输出

`module5` 会输出：

| 文件 | 含义 |
| --- | --- |
| `bridge_edges/*.json` | 进程间桥接关系 |
| `candidate_paths/*.json` | 候选链 JSON |
| `candidate_paths/*.md` | 候选链 markdown dossier |
| `summary.json` | 模块5总体汇总 |
| `process_summary.json` | 进程层面汇总 |
| `object_summary.json` | 对象层面汇总 |

### 10.11 这一层解决了什么问题

它解决的是“局部证据图太散，不适合直接做攻击解释”的问题。  
通过 `CandidatePath`，后续 `module6` 可以只看少量高价值链条，而不是整张原始局部图。

## 11. Module6：claims 生成与 ATT&CK 映射

### 11.1 目标

`module6_attack_reason.py` 的目标是把 `CandidatePath` 转成攻击语义输出。  
当前输出既可以是完整 ATT&CK 战术+技术，也支持只输出战术。

### 11.2 总体两段式思路

当前 `module6` 大致分两步：

1. 从 dossier 中抽取 Holmes 风格的攻击行为 claims
2. 再把 claims 映射到 ATT&CK

也就是说，它不是直接从原始事件映射 ATT&CK，而是先做一层中间攻击语义抽象。

### 11.3 什么是 dossier

dossier 可以理解为“给大模型看的路径摘要文档”。  
它把 `CandidatePath` 中最重要的信息整理成一份结构化输入。

当前 dossier 里通常会包含：

- 路径基本信息
- 核心进程链
- 关键对象
- 支撑事件
- 阶段覆盖
- 风险说明
- 当前版本新增的：
  - `PRECURSOR`
  - `FOLLOWUP`
  - `NETWORK_SUPPORT`
  - `OBJECT_LINEAGE`
  - `FAMILY_TAGS`

### 11.4 Holmes-style claims 是什么

这里的 claim 可以理解为“比 ATT&CK 更细一点、但又比原始日志更抽象一点的攻击行为陈述”。

例如它会尝试表达：

- 可疑文件执行
- C2 通信
- 扫描探测
- 附件触发执行
- 可疑对象删除

之类的行为原子。

当前 `module6` 里 claims 的来源有两部分：

1. 大模型从 dossier 中抽取
2. `build_holmes_claim_graph()` 和 `_fallback_claims()` 根据 dossier 和 Holmes atom 规则做补全

最后再合并、校验。

### 11.5 为什么要有 Holmes-style 中间层

直接从链条跳到 ATT&CK 容易不稳定。  
中间加一层 claims 的动机是：

- 先把“行为事实”说清楚
- 再映射成 ATT&CK 概念
- 降低大模型直接输出 ATT&CK 时的漂移

### 11.6 ATT&CK 候选检索

系统不会一上来就让大模型在完整 ATT&CK 知识库里自由发挥。  
它会先用 `attack_kb.py` 从 ATT&CK KB 里检索一批候选，再让后续映射只在候选集合里进行。

候选检索使用的上下文包括：

- action families
- behavior types
- claim terms
- command lexemes
- object semantics
- os hint

当前常用是：

- 稀疏 TF-IDF 检索
- 再加一些兼容性 bonus

如果开启向量检索，也可以加 dense score，但当前很多实验配置里默认不开。

### 11.7 claim-level ATT&CK prior

当前代码支持一层 ATT&CK 先验，也就是 `claim_attack_hints` 这一类逻辑。  
它的意思是：

- 某些 claim 会偏好某些 tactic/technique
- 系统可以在 ATT&CK 候选检索和映射时做一些注入、偏好、抑制或补回

后来之所以做 `no_attack_priors` 实验，就是为了验证这层先验是不是会把结果带偏。

当前代码支持：

- `claim_attack_prior_mode=full`
- `claim_attack_prior_mode=disabled`

当设为 `disabled` 时，相关先验链会被整体关闭，而不是只删掉 prompt 里的文字。

### 11.8 tactics-only 模式

当前代码还支持只输出 ATT&CK 战术，不追求技术。  
相关开关是：

- `attack_mapping_scope=full | tactics_only`
- `tactic_mapping_mode=deterministic | llm`

其中：

#### `tactics_only + deterministic`

- 不走第二段 ATT&CK mapping LLM
- 直接根据 Holmes atom/behavior type 的 tactic 对应关系输出战术

#### `tactics_only + llm`

- 仍保留大模型映射
- 但 prompt 里只给 tactic candidates
- 不允许输出 technique

这条能力就是我们之前做 `deterministic_tactics_only` 和 `llm_tactics_only` 对照实验时用到的。

### 11.9 最终输出

`module6` 当前会为每条候选链生成：

| 文件 | 含义 |
| --- | --- |
| `reports/*.report.json` | 最终攻击报告 |
| `dossiers/*.json` | dossier 结构化输入 |
| `markdown/*.md` | 人读版 markdown 报告 |
| `llm_inputs/*.json` | 送给模型的输入记录 |
| `claim_graphs/*.json` | claims 图 |
| `claim_graphs/*.md` | claims 图 markdown |

另外还有：

- `report_index.json`
- `summary.json`

### 11.10 这一层解决了什么问题

它解决的是“有候选攻击链，但还没有统一的攻击语义解释”的问题。  
最终 ATT&CK 输出、报告输出、战术/技术评估都依赖这一层。

## 12. Evaluation：如何评估结果

### 12.1 目标

`evaluation/path_reason_eval.py` 的目标是评估：

- 系统有没有命中正确攻击窗口
- 有没有命中正确战术/技术
- 有没有在非攻击窗口产生太多高风险噪声

### 12.2 当前主要指标

当前常见指标包括：

| 指标 | 含义 |
| --- | --- |
| `confirmed_window_recall` | 命中确认攻击窗口的召回 |
| `strict_window_recall` | 严格窗口召回 |
| `high_risk_window_recall` | 高风险窗口召回 |
| `off_window_high_risk_rate` | 非攻击窗口高风险噪声率 |
| `strict_tactic_recall_macro` | 战术宏平均召回 |
| `strict_tactic_precision_macro` | 战术宏平均精度 |
| `strict_technique_recall_macro` | 技术宏平均召回 |
| `broad_technique_recall_macro` | 放宽口径的技术召回 |

### 12.3 tactics-only 时怎么评估

当配置为 `attack_mapping_scope=tactics_only` 时，评估器会切到战术优先口径：

- 不再因为没有 technique 而报 warning
- 重点看 tactic recall / tactic precision

这也是我们后面只追求“先把战术打准”的实验基础。

### 12.4 输出

评估器会生成：

- `metrics_summary.json`
- `window_level_metrics.json`
- `path_assignment.json`
- `tactic_comparison.json`
- `tactic_diff_by_task.json`
- `candidate_tactic_coverage_by_task.json`
- `technique_comparison.json`

## 13. 当前版本相对早期 `microstep2b` 的主要增强点

当前 `APT-Fusionstep2b1` 相比更早的 `microstep2b`，在链条与解释层主要增强了这些点：

| 增强点 | 目的 |
| --- | --- |
| `family_tags` | 不只按分数保链，还按链段类型保链 |
| `precursor_rescue` | 防止短命前因链被长尾行为淹没 |
| `network_support_summary` | 更稳地保留 C2/回连支撑 |
| `object_lineage_summary` | 更稳地保留文件传播与执行谱系 |
| `holmes_matched_atoms` | 强化 Holmes 风格行为原子支撑 |
| `tactics_only` | 当技术过难时先稳住战术层 |
| `claim_attack_prior_mode=disabled` | 排查 ATT&CK 先验是否把结果拉偏 |

这些增强的共同动机是：

- 让候选链更接近真实攻击链段
- 让 dossier 不只剩“尾巴”
- 让 claims 更稳定
- 让 ATT&CK 映射更少被先验误导

## 14. 当前版本里几个容易混淆的名词

### 14.1 任务图

任务图是 `module1/module2` 世界里的对象。  
它是从全局进程图切出来的一张局部图，用来做“恶意图检测”。

### 14.2 局部证据图

局部证据图是 `module3` 恢复出来的任务内事件图。  
它比任务图更贴近原始日志，包含进程、对象和事件。

### 14.3 CandidatePath

CandidatePath 是 `module5` 从局部证据图中进一步抽出来的攻击候选链。  
它比局部证据图更稀疏、更面向攻击解释。

### 14.4 dossier

dossier 是给 `module6` 或大模型看的“候选链摘要文档”。

### 14.5 claim

claim 是比 ATT&CK 更接近行为事实的中间攻击陈述。  
可以把它理解成“系统认为这条链上发生了哪些攻击行为原子”。

### 14.6 ATT&CK candidate

这是从 ATT&CK KB 检索出来的一小批可能相关的战术/技术，用来限制后续映射空间。

### 14.7 family tag

这是当前工程为了保链和做 truth-gap 诊断引入的链段类型标签。  
它不是 ATT&CK，也不是 Holmes 论文里的标准术语。

## 15. 当前全流程的优点

当前这条主线的优点主要有：

1. 不直接在全量日志上推理，而是逐层缩小范围。
2. `module3` 能从图级可疑任务重新回到事件级证据。
3. `module4` 提供了对象版本、标签来源、语义去重这些很关键的中间结构。
4. `module5` 不是盲搜，而是带有对象桥接、family 保留和 precursor rescue。
5. `module6` 不是直接让模型自由生成 ATT&CK，而是先经 claims 和 ATT&CK candidates 做约束。
6. 当前代码已经支持把“只看战术”和“战术+技术”拆开分析。

## 16. 当前全流程的主要局限

当前版本也有一些明确局限：

1. 上游 `module1/module2` 如果任务图没切好，后面恢复证据的范围就会先天受限。
2. `module3` 是围绕可疑任务回查日志，不是直接在全局事件图上做完备恢复，所以仍可能漏前因分支。
3. `module4` 的轻标签体系是工程标签，不等于论文标准攻击阶段。
4. `module5` 的 CandidatePath 仍然是一种压缩表达，可能把复杂攻击链折叠得过度简化。
5. `module6` 的 claims 质量仍然高度依赖 dossier 的保真度。
6. ATT&CK 先验、候选检索和最终映射之间仍可能互相牵引，造成战术/技术偏移。

## 17. 推荐的 PPT 拆页方式

如果要做 PPT，建议按下面的顺序拆页：

### 第 1 页：项目目标

- 输入是什么
- 输出是什么
- 为什么不能直接用全量日志做 ATT&CK 判断

### 第 2 页：整体流程总图

- `module0 -> module6 -> evaluation`
- 突出 4 个层次：任务检测、证据恢复、链条构造、攻击解释

### 第 3 页：Module1 任务图构建

- TAPAS 构图
- 任务切分
- 进程 embedding
- OCR-style 统计特征

### 第 4 页：Module2 恶意图检测

- GraphSAGE 主模型
- XGBoost 图统计 sidecar
- late fusion
- 输出 suspicious tasks

### 第 5 页：Module3 局部证据恢复

- 围绕可疑任务回查原始日志
- 构建局部证据图
- 为什么这一步是图到事件的桥梁

### 第 6 页：Module4 语义压缩与轻标签

- semantic skipping
- 轻标签
- 对象版本
- label provenance

### 第 7 页：Module5 候选链构造

- bridge edge
- 路径搜索
- 路径打分
- family 保留
- precursor rescue

### 第 8 页：Module6 攻击语义解释

- dossier
- Holmes claims
- ATT&CK candidates
- tactics-only / full mapping

### 第 9 页：评估

- 窗口命中
- 战术/技术召回
- off-window 噪声

### 第 10 页：当前增强点与问题

- 相比旧 `microstep2b` 多了什么
- 现在最可能卡在哪里

## 18. 一页式结论

当前 `APT-Fusionstep2b1` 的本质不是“直接从日志输出 ATT&CK”，而是：

1. 先用任务图检测把范围缩小。
2. 再从原始日志恢复任务内局部证据。
3. 再用语义压缩和对象版本把证据整理成可推理状态。
4. 再构造成少量候选攻击链。
5. 最后通过 Holmes-style claims 和 ATT&CK 候选约束输出战术/技术。

它的核心价值在于“分层缩小范围 + 保留对象传播和前因链信息”，  
它的核心挑战在于“前因链是否能被保住，以及 claims 到 ATT&CK 的解释是否稳定”。
