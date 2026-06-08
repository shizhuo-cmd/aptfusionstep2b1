# 2026-05-07 完整方案交接文档（中文整理版）

## 说明

本文是对 [complete_scheme_handoff_2026-05-07.md](/D:/daima/APT-Fusion/docs/complete_scheme_handoff_2026-05-07.md) 的中文整理版，目的是把当时围绕你提供的融合思路所形成的“完整版方案”完整保存下来，便于后续回查、对照和汇报。

这份文档反映的是 **2026-05-07 当时确定的完整方案**，不是我们目前最新推荐的重设计版本。它更接近“当时已经实现和计划实现的整条主线如何被理解与描述”。

---

## 创新摘要

当时的 APT-Fusion 方案已经不再是一个纯 TAPAS 检测器，也不是一个纯 OCR-APT 风格的大模型调查器。它的核心创新，是把 **TAPAS 的任务图检测能力** 放在前半段，再围绕每个可疑任务重建 **结构化证据层**，最后让大模型基于 **evidence bundle** 而不是原始日志或图张量做推理。

换句话说，这条链路把以下几层显式串了起来：

```text
低层进程关系
-> 任务图检测
-> 证据索引
-> IOC 候选
-> 行为 claims
-> ATT&CK tactic/technique
-> 跨任务 campaign 聚合
```

它的价值不只是“模块更多”，而是让：

- 低层图结构
- 原始事件证据
- IOC
- 语义行为 claims
- ATT&CK 技战术
- 跨任务攻击故事线

之间形成了逐层可回溯的连接。相比直接自由生成的大模型摘要，它更可验证；相比纯图分类器，它又更有语义表达能力。

---

## 1. 当时的完整流水线

当时实际生效、并被视为完整方案主线的流程是：

```text
module1
-> module2
-> module3_index
-> module3_bundle
-> module4_reason
-> module5_campaign
```

仓库里虽然还保留旧的 `module3_local` 和早期 `module4` 路径，但当时真正用于攻击技战术分析的，是上面这条 indexed / bundled / reasoned 主线。

### 1.1 Module 1：TAPAS-native 任务图导出

职责：

- 用 TAPAS 风格的数据集解析器读取原始日志
- 将每个进程的历史行为编码成序列向量
- 从父子进程关系中切出 task relations
- 把关系图分解成任务图
- 可选叠加 OCR 风格的进程统计特征
- 导出后续检测需要的原生图载荷

主要输出：

- `process_embeddings.csv`
- `task_subgraphs.json`
- `process_segmentation_edges.csv`
- `tapas_native_graphs.pt`
- `tapas_native_module1_summary.json`

需要明确的事实：

- 最终任务图本质上是 **仅由进程节点构成的图**
- 图节点是进程行为向量
- 图边是父子进程任务边
- 文件、网络流、原始事件不会以图节点形式直接保留在训练图里

### 1.2 Module 2：TAPAS-native 检测与任务 sidecar 导出

职责：

- 读取 `tapas_native_graphs.pt`
- 可选对恶意任务图做增强
- 训练或加载 TAPAS GraphSAGE
- 可选通过 XGBoost late fusion 融合 OCR 风格统计特征
- 对任务图打分并导出 suspicious tasks
- 导出后续调查阶段必需的 sidecar 数据

核心输出：

- `task_scores.csv`
- `task_subgraph_summary.json`
- `tapas_native_model.pt`
- `suspicious_tasks.json`
- `process_scores.csv`
- `run_0_raised_alarms.csv`
- `task_meta_rich.json`
- `task_attribution.json`

需要明确的事实：

- `suspicious_tasks.json` 是任务级检测的主输出
- `task_meta_rich.json` 与 `task_attribution.json` 不是装饰性文件，而是后续推理链的一部分
- 对于增强任务 `task_xxxx_augNNN`，可以回退到基础任务图生成 sidecar

### 1.3 Module 3 Index：证据索引

职责：

- 读取 module2 导出的 suspicious tasks
- 加载任务 sidecars
- 重扫原始日志
- 把任务相关证据写入本地 SQLite 证据索引

主要输出：

- `module3_index/evidence_index.sqlite`
- `module3_index/task_index.json`
- `module3_index/summary.json`

这个索引中会保存：

- task rows
- task processes
- 节点信息
- 原始事件
- task-event 映射
- 可选全文检索条目

这一层的意义在于：后面的调查流程不需要每次都回扫整份原始数据。

### 1.4 Module 3 Bundle：任务证据包

职责：

- 从证据索引中读取任务级证据
- 选择并压缩关键事件
- 构造 episodes
- 收集 IOC candidates
- 打包成一个 task bundle

主要输出：

- `module3_bundle/bundles/bundle_*.json`
- `module3_bundle/markdown/bundle_*.md`
- `module3_bundle/bundle_index.json`
- `module3_bundle/summary.json`

bundle 中通常包含：

- task identifiers 和 task scores
- process IDs
- task detection summary
- task meta sidecars
- task attribution sidecars
- selected events
- episodes
- IOC candidates
- retrieval statistics

这一层是图检测链和 LLM 推理链之间最关键的桥。

### 1.5 Module 4 Reason：任务级 LLM 推理

职责：

- 读取 bundle JSON
- 构造紧凑的 LLM context
- 执行第一阶段抽取
- 校验 claims 和 IOCs
- 加载本地 ATT&CK KB 候选
- 执行第二阶段 ATT&CK 映射
- 校验映射结果
- 写出任务报告

主要输出：

- `module4_reason/reports/task_report_*.json`
- `module4_reason/markdown/task_report_*.md`
- `module4_reason/report_index.json`
- `module4_reason/summary.json`

当时实现的是两阶段推理：

1. 抽取阶段：
   - `summary`
   - `claims`
   - `iocs`
   - `gaps`

2. 映射阶段：
   - `attack_mappings`
   - `gaps`

需要明确的事实：

- claims 和 IOCs 虽然由 LLM 产出，但不会被无条件相信
- 它们会被真实 `event_id` / `episode_id` 回证
- 本地 ATT&CK STIX 会先缩小候选范围，再交给映射阶段
- 当 LLM 输出过度保守时，系统会用 fallback 补齐缺失的 summary / claims / IOCs
- 单任务超时或失败不会再拖死整个批次

### 1.6 Module 5 Campaign：跨任务聚合

职责：

- 读取任务报告
- 计算任务间相似度
- 聚类相关任务
- 写出 campaign 级输出

主要输出：

- `module5_campaign/clusters/cluster_*.json`
- `module5_campaign/markdown/cluster_*.md`
- `module5_campaign/cluster_index.json`
- `module5_campaign/pair_scores.json`
- `module5_campaign/summary.json`
- `module5_campaign/global_campaign_report.md`

需要明确的事实：

- 这一层当时仍是规则驱动聚类，不是完整的 LLM campaign storyteller
- 相似度主要依赖：
  - 共享 IOC
  - 共享 ATT&CK ID
  - 共享进程 ID
  - 时间接近性

---

## 2. 方案真正强调的威胁语义主线

这版方案真正强调的语义升级链是：

```text
task graph
-> evidence bundle
-> claims
-> ATT&CK mappings
-> campaign clusters
```

这意味着方法并不止步于：

- 哪个 IOC 出现过
- 哪个任务分数高

而是把低层证据逐层提升为高层语义结构：

- task graph：指出哪些进程属于同一个可疑单元
- bundle：指出围绕该单元最关键的事件、episodes 和 IOC
- claims：指出这些证据意味着什么行为
- ATT&CK mappings：指出这些行为属于哪类技战术
- campaign clustering：指出哪些任务报告属于同一条攻击故事线

这是它相较于以下两类系统的主要语义优势：

- 纯 TAPAS 风格图分类
- 纯文档式 LLM 总结

---

## 3. 任务图分割：代码真实做了什么

这个问题当时专门查得很细，所以需要单独保留。

### 3.1 代码真实情况

当时代码 **并没有完整实现** TAPAS 论文伪代码里那套阈值分割逻辑。

代码真正做的是：

1. 抽取父子进程关系
2. 清洗不一致的父子分配
3. 把任务边记成 `child -> parent`
4. 对关系图做弱连通分量分解
5. 丢掉空边组件和单节点组件

所以真实分割规则更接近：

```text
父子边清洗
-> 连通分量分解
```

### 3.2 没有实现什么

论文算法中的这些机制，当时确认都没有完整落地：

- `tgid` merge
- `ChildNum`
- `Listseg`
- `children > 2`
- ancestry 级联更新

在检查：

- `TAPAS_release`
- `TAPAS-artifact`
- `vendor/tapas`

之后，当时确认：用于 `trace / cadets / fivedirections / theia / optc` 的实际代码路径里，都没有完整的 `children > 2` 阈值分割实现。

`theia` 的旧路径里有一点 `tgid`-merge 的影子，但完整的 `ChildNum / Listseg / ancestry` 逻辑也缺失。

### 3.3 结论

所以当时更诚实的表述应当是：

```text
当前实现是一个基于清洗后的父子关系和连通分量分解的简化 TAPAS 风格任务图分割
```

而不是说它完整复刻了论文里的阈值分割伪代码。

---

## 4. 一个真实训练/测试任务图到底长什么样

训练和测试里用的任务图，不是混合多实体类型的 provenance graph。

它本质上是一个仅由进程节点构成的图，大致形态是：

```json
{
  "nodes": [process_feature_vector, ...],
  "edges": [[src_index, dst_index], ...],
  "label": 0_or_1,
  "attacknum": integer
}
```

随后再转成 PyG 的：

```python
Data(x=x, edge_index=edge_index, y=y)
```

含义是：

- `x`：节点特征矩阵
- `edge_index`：图边
- `y`：图标签

### 4.1 一个很重要的身份细节

裸的图张量里不直接存人类可读的 `process_id`。

它依赖位置映射：

```text
node_ids[j] <-> graph["nodes"][j]
```

APT-Fusion 当时专门保留了这个映射关系，通过：

- `selected_graph_metas[*]["node_ids"]`

来支撑后面的可解释性和报告生成。

### 4.2 这意味着什么

LLM 后面并不会直接看到 `Data(x, edge_index, y)`。  
它最终看到的是 bundle 里的结构化证据对象。

这个区别非常重要：

- 检测器学习的是数值化图结构
- LLM 推理的是重构后的证据和语义摘要

---

## 5. LLM 后面真正看到的材料是什么

LLM 并不直接看训练图张量。

它实际看到的是 task evidence bundle，里面包含：

- task IDs 和 scores
- process IDs
- task detection summary
- task meta sidecar
- task attribution sidecar
- IOC candidates
- selected events
- episodes

所以 LLM 面向的是：

**结构化 JSON 证据包**

而不是：

**训练用的图张量**

---

## 6. IOC 策略：当时的实现与完整设想

### 6.1 当时的实际实现

当时 IOC 处理链路是：

```text
events
-> 正则/规则抽取 ioc_candidates
-> LLM 输出 iocs
-> 程序化校验
-> 若为空则 fallback
```

这意味着：

- `ioc_candidates` 不是 LLM 直接生成的
- LLM 的作用更像是在证据上下文中筛选、提炼“值得报告的 IOC”
- 最终 IOC 依然受证据存在性约束

### 6.2 它为什么和 OCR-APT 不一样

OCR-APT 更像：

```text
documentized subgraph
-> LLM 抽 IOC 列表
-> 事后过滤幻觉
```

APT-Fusion 当时更像：

```text
structured evidence
-> deterministic IOC candidates
-> LLM semantic selection
-> validation
```

这种做法提高了可控性和可验证性，但如果抽取层太保守，也会牺牲 IOC recall。

### 6.3 当时完整设想中的更丰富 IOC 流程

当时讨论过的目标版本其实比现状更丰富：

```text
structured evidence
-> deterministic IOC extraction
-> normalization / deduplication
-> local TI / rule enrichment
-> LLM IOC and claim refinement
-> validation
-> IOC-driven second-pass context expansion
-> final all_iocs + report_iocs
```

这个完整版本在当时还没有完全实现。

---

## 7. ATT&CK 知识集成

当时方案已经明确集成了本地 ATT&CK 知识库（STIX）。

它主要用于：

- tactic / technique 候选缩小
- 在 `module4_reason` 中提高 ATT&CK 映射稳定性

需要明确的一点是：

- 这是 **ATT&CK knowledge support**
- 它不是完整意义上的外部 IOC 威胁情报增强系统
- 也不是 MISP 或 OpenCTI 那类 TI 平台替代品

---

## 8. 当时已经确认过的重要修复与本地偏差

这些都是当时调试后确认过、值得保留在文档里的项目侧改动。

### 8.1 Trace parser 父进程回填修复

对 `trace` 解析器做过一个两阶段修复：

1. 先收集所有 `subject UUID -> cid`
2. 再统一解析 `parent UUID -> parent cid`

这样可以避免：

- 父进程在日志后面才出现时
- 被错误记成 `Unknow`

这一改动会直接影响 `trace` 的 module1 结果，所以 parser 变化后需要从 `module1` 重新跑。

### 8.2 Trace augmentation bonus

当时加入过一个 `trace` 专属 augmentation bonus，使恶意图增强倍数大致变成：

```text
count // 2000 + bonus
```

这是项目侧本地修改，不属于原始 TAPAS。

### 8.3 增强任务 sidecar 修复

当时修过一个问题：

- 检测结果里可能出现 `task_xxxx_augNNN`
- 但下游 sidecar 生成不到对应增强任务

修复方式是：

- sidecar 回退到基础任务图生成
- 同时仍保留增强任务 ID

### 8.4 Module4 reason 健壮性增强

当时在 reasoning 阶段加入了：

- summary / claims / IOCs 缺失时的 deterministic fallback
- 空输出时 support rate 的修正
- 单任务失败不终止整批

这些都属于项目侧稳健性增强，不是最早版本原生就有的。

---

## 9. 当时已知但不能夸大的缺口

以下几点在当时就应该被如实承认：

1. 论文里完整的阈值分割逻辑没有实现。
2. 当前 IOC 流程仍比目标设计简化。
3. Campaign 总结仍主要是规则聚类，不是完整 LLM 故事化总结。
4. LLM 后半链路虽然是结构化、证据感知的，但仍然很依赖 bundle 质量，也受 timeout 影响。

---

## 10. 当时对外最安全的简述

如果要给外部一个准确、简短、不夸大的描述，当时最安全的说法是：

> APT-Fusion 当前将 TAPAS-native 任务图检测与结构化证据加大模型调查流水线结合起来。前半段检测可疑进程任务图，后半段围绕任务重建证据 bundle，提取经过验证的 claims 和 IOCs，在本地 ATT&CK 知识支持下做技战术映射，并进一步把相关任务报告聚成 campaign 级结果。当前任务图分割实现基于清洗后的父子进程关系与连通分量分解，而不是 TAPAS 论文中完整的阈值分割伪代码。

---

## 附注

如果要继续回看“当时方案之后又补了什么”，最相关的后续专项设计文档是：

- [core_task_relevance_filter_design_2026-05-08.md](/D:/daima/APT-Fusion/docs/core_task_relevance_filter_design_2026-05-08.md)

它不是这份完整方案本体，而是后续围绕 bundle 证据筛选、`20/20/6` 收紧、GT-hit trace 推理稳定性做的专项补充。
