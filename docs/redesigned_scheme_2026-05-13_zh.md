# 重设计方案（2026-05-13，中文整理版）

## 定位

本文是在现有 APT-Fusion 实现方向基础上的一次重设计，优化目标只看三件事：

1. 检测质量，
2. 基于证据约束的 ATT&CK 分析质量，
3. 在大规模审计流上的工程可行性。

这份方案**明确不以“尽量少改代码”为目标**。

这次重设计主要参考了：

- 本地研究笔记 [deep-research-report.md](/D:/download/deep-research-report.md)，
- 近期 provenance graph 压缩与切分研究，
- 近期基于 provenance 的威胁检测与攻击场景重建研究，
- 以及当前 APT-Fusion trace 流水线中已经观察到的一系列失败模式。

---

## 当前方案的问题

当前实现有六个结构性问题：

1. **任务图切得太早，而且切得太机械。**
   - 检测和调查共用同一套切分后的图对象。
   - 结果要么出现大量碎片化小任务，要么出现边界节点汇聚的大型骨架任务。

2. **给 LLM 的证据选择仍然很弱。**
   - `core_events` 和 `filtered_events` 比直接喂原始事件好，但最后的 `20/20/6` 仍然只是截断。
   - 少量重复网络事件依然可能占满整个 bundle。

3. **ATT&CK 候选检索过浅。**
   - query terms 会被 IP 片段、端口号和泛词污染。
   - 于是 ATT&CK candidates 虽然“有”，但经常语义不贴题。

4. **ATT&CK 映射阶段约束不够。**
   - 模型仍然有太大自由度去幻觉或乱配 tactic/technique。
   - 约束一加重，召回又会直接掉到接近 0。

5. **阶段分析和 ATT&CK 分析的顺序不对。**
   - 之前 trace 阶段逻辑会虚高 phase coverage。
   - 后来完全自由 ATT&CK 后，又暴露出 raw ATT&CK 质量很差。

6. **LLM 在某些地方介入太早，在另一些地方介入太晚。**
   - 太早：直接把噪声很重的证据映射到 ATT&CK。
   - 太晚：在 ATT&CK 候选映射前，没有足够强的语义重排层。

---

## 新设计原则

新方案应当遵循五条原则：

1. **先在进程/组件层做检测，再在证据层做调查。**
2. **不要让任务图分割直接决定调查单元。**
3. **在任何 LLM 推理之前，先做精确检索 + 稀疏检索 + 语义检索的混合召回。**
4. **把 ATT&CK 映射视为“受约束的证据对齐”，而不是自由文本生成。**
5. **把 APT 阶段视为下游解释层，而不是 prompt 里的先验目标。**

---

## 新的端到端架构

```text
raw audit stream
-> normalized event store
-> online process-state encoder
-> process/edge anomaly scoring
-> alert seed selection
-> alert-centric component builder
-> evidence retrieval and denoising
-> claim extraction
-> ATT&CK candidate retrieval + reranking
-> constrained ATT&CK alignment
-> stage graph inference
-> cross-alert campaign correlation
```

---

## 第 1 层：数据与存储

主路径上**不要使用 GraphDB**。

建议使用以下四层存储结构：

1. **append-only 规范化事件表**
   - 每条 event 一行
   - 包含 host、timestamp、subject、object、action、规范化文本字段、原始引用

2. **实体/进程状态表**
   - 记录每个进程的当前隐藏状态
   - 滚动计数器、最近动作、近期对象交互摘要

3. **邻接与时序索引**
   - process -> children
   - process -> touched files
   - process -> touched network endpoints
   - endpoint/file/process -> recent events

4. **调查检索层**
   - 针对规范化事件描述和 minute-level episode summary 建稀疏词法索引
   - 针对 minute-level evidence chunk 和 claim-like summary 建向量索引
   - 提供 host、时间窗、实体类型、动作族等 metadata filter

这样既能保持热路径简洁，也保留足够的结构用于 provenance 风格调查。

---

## 第 2 层：检测不应以任务图分割作为主要单元

当前架构把 task graph 放到系统中心的位置过早了。

新设计应当明确拆分：

1. **在线打分单元** = process / edge / micro-component
2. **调查单元** = alert-centric evidence component

### 2.1 在线打分

建议并行使用三类检测器：

1. **process-state detector**
   - 把每个进程编码成时间状态向量
   - 对偏离良性行为轨迹的突变打分

2. **typed edge anomaly detector**
   - 分别给 process-file、process-flow、process-process 交互打分
   - OCR-APT 那种“类型特定建模”的价值，应主要落在这里

3. **micro-component classifier**
   - 围绕可疑进程构造一个小型时序组件
   - 判断这个局部组件是否更像恶意

最后对三路得分做校准融合，而不是把所有判断压在单一 graph score 上。

### 2.2 从 TAPAS 保留什么

建议保留：

- 进程历史编码，
- 低成本在线进程状态更新，
- 父子进程结构作为一种结构信号源。

不建议保留：

- 把“基于父子关系导出的 task graph”继续作为后续调查的唯一核心对象。

---

## 第 3 层：先告警，再围绕告警构建组件，而不是先全局切图

这是整套重设计里最大的架构变化。

不要再先把整套数据硬切成任务图，再赌这些切出来的图刚好就是正确调查单元。

应该改成：

1. 先检测可疑进程/边，
2. 把它们作为 **alert seeds**，
3. 再围绕这些 seeds 构建调查组件。

### 3.1 组件构建器

对于每个 alert seed：

1. 收集：
   - 最近的可疑祖先进程，
   - 子代执行链，
   - 触达文件，
   - 出入网络对象，
   - 跨实体桥接进程，
   - seed 周围受限时间窗。

2. 对局部节点和边按以下因素打分：
   - 时间接近性，
   - 异常贡献度，
   - 因果路径重要性，
   - 稀有性，
   - 可疑动作类型。

3. 产出一个 **可重叠的 alert-centric component**
   - 允许组件重叠，
   - 不必先强制做全局唯一划分。

这一步借鉴的是 provenance partitioning 研究里有价值的部分，但避免了我们当前“先全局切图，后调查”带来的失败模式。

---

## 第 4 层：证据包构建必须按 lane 分配，而不是简单 top-N 截断

当前的 `20/20/6` 策略应当被替换。

不要再用“全局事件排名 + 截断”的方式。

应改成构建一个带语义通道的 **evidence packet**：

1. **execution lane**
   - exec / fork / load / open-create-exec 链

2. **file/persistence lane**
   - write / rename / truncate / permission / path modification

3. **network/C2 lane**
   - connect / send / recv 及 endpoint clustering

4. **recon lane**
   - 枚举命令、进程列表、网络探测、文件发现

5. **pivot lane**
   - 把可疑进程与可疑文件/端点串起来的桥接事件

每个 lane 都给固定配额。

例如：

```text
execution: 8 events
file/persistence: 8 events
network/C2: 8 events
recon: 6 events
pivot/path evidence: 6 events
```

然后再生成：

- lane summaries，
- cross-lane evidence links，
- minute-level episode summaries。

这比让端口密集型 bundle 独占 prompt 预算要强得多。

---

## 第 5 层：ATT&CK 候选检索必须成为一个真正的检索子系统

新的 ATT&CK 子系统应分三步：

### 5.1 查询生成

**不要**再拿这些原始噪声去直接查 ATT&CK：

- 端口号，
- IP 片段，
- 泛化 token 噪声。

ATT&CK query 应当只从以下四类语义里构造：

1. 规范化动作族
   - execution、write、load、connect、enumerate、schedule、modify

2. 命令词
   - 可执行文件名、shell 调用、LOLBins、脚本解释器

3. 对象语义
   - startup file、shell config、cron-like artifact、remote endpoint、archive artifact

4. 已抽出的 claims
   - 这应当是 ATT&CK 检索中价值最高的输入

### 5.2 候选检索

基于本地 STIX 文件：

- 对 tactic 和 technique 的名称、描述建立稀疏词法索引，
- 对同样条目建立向量索引，
- 用 hybrid search 召回 top candidates，
- 再用一个 evidence-aware reranker 对候选重排。

重排器应优先考虑：

- action-family compatibility，
- object-type compatibility，
- operating-system compatibility，
- 与 evidence packet 的时间一致性。

### 5.3 候选输出

模型**不应该**看到整份 STIX。

它只应该看到一个紧凑候选表，例如：

```text
candidate_id | tactic | technique | short evidence fit note
```

规模控制在：

- top 5-10 techniques
- top 5 tactics

就足够了。

---

## 第 6 层：把 claim extraction 和 ATT&CK mapping 拆开

当前方案让模型太早跳到 ATT&CK。

建议改成两步：

### Step A：claim extraction

输入：

- evidence packet
- lane summaries

输出：

- atomic claims
- 每条 claim 都要有 event evidence
- 每条 claim 只对应一种行为类型

典型 claim type 例如：

- remote connection establishment
- suspicious interpreter execution
- shell configuration modification
- file discovery behavior
- process spawning chain

### Step B：ATT&CK alignment

输入：

- claims
- ATT&CK candidates

输出：

- tactic name
- technique name（可为空）
- evidence claim ids
- confidence

关键约束：

- 模型**只输出名称**，
- ID 由本地 ATT&CK KB 在生成后回填，
- technique-tactic 兼容性由代码强制检查，
- 不支持的映射直接丢弃。

这比现在“模型自由生成 tactic + technique + ID”稳健得多。

---

## 第 7 层：阶段推断应放在下游，并以图结构和时序为基础

不要在映射阶段就强迫模型按目标 phase 集合去思考。

应该改成：

1. 先推 ATT&CK，
2. 再把 ATT&CK 与证据顺序映成一个 **APT stage graph**。

对于 trace 评估标签，可以继续使用类似：

- Initial Compromise
- Internal Reconnaissance
- Command and Control
- Maintain Persistence

但这些阶段应当在 **ATT&CK 对齐之后**、**证据时序整理之后** 再生成。

阶段推断模块可以利用：

- ATT&CK tactic set，
- claim order，
- event timestamps，
- lane co-occurrence，
- host-local causal path order。

这样可以避免我们已经看到的两个极端：

- 被 prompt 强行抬高阶段覆盖率，
- 去掉阶段先验后又变成零阶段输出。

---

## 第 8 层：跨 alert 的 campaign 关联

当前设计在单任务报告这里停得太早了。

更强的方案应当围绕以下信号做跨 alert 关联：

- shared endpoint clusters，
- shared executable or file artifacts，
- repeated command lexemes，
- shared ATT&CK claims，
- temporal proximity。

campaign 层应该输出：

1. alert clusters，
2. campaign-level ATT&CK graph，
3. campaign-level stage progression，
4. host-to-host pivot hints。

---

## 最可行的模型栈

如果只看性能、效果和可行性，最合适的技术栈是：

1. **小/中型学习型检测器** 做在线打分，
2. **稀疏检索 + 向量检索的混合检索层** 做证据召回，
3. **中等尺寸本地 instruct model** 做 claim 和 ATT&CK 推理，
4. **严格的代码侧验证** 兜底模型输出。

明确不建议：

- 把 LLM 当主检测器，
- 把整份 STIX 文件直接塞进 prompt，
- 只靠 prompt 文字约束来保证 ATT&CK 正确性。

---

## 为什么这版设计应当优于当前方案

相较于现在的实现，这版重设计更强的原因在于：

1. 检测不再被脆弱的全局 task-graph segmentation 卡死；
2. evidence packet 通过 lane 平衡，而不是简单 top-N 截断；
3. ATT&CK 检索由行为语义驱动，不再被原始噪声 token 污染；
4. ATT&CK 映射由本地 KB 结构约束，而不是自由文本生成；
5. APT 阶段标签变成下游解释产物，而不是 prompt 先验；
6. 不引入 GraphDB 到热路径的前提下，恢复了 campaign 级上下文。

---

## 推荐实现顺序

虽然这份文档不以低迁移成本为目标，但最合理的建设顺序仍然是：

1. 重写 ATT&CK candidate retrieval，
2. 重写 evidence packet construction，
3. 拆开 claim extraction 与 ATT&CK alignment，
4. 用 alert-centric components 替换“先全局切图、后调查”，
5. 增加 campaign correlation，
6. 最后才在必要时重审 detector architecture。

---

## 参考资料

- 本地研究笔记：[deep-research-report.md](/D:/download/deep-research-report.md)
- A multi-source log semantic analysis-based attack investigation approach (Computers & Security, 2025): [https://doi.org/10.1016/j.cose.2024.104303](https://doi.org/10.1016/j.cose.2024.104303)
- PDCleaner: A multi-view collaborative data compression method for provenance graph-based APT detection systems (Computers & Security, 2025): [https://doi.org/10.1016/j.cose.2025.104359](https://doi.org/10.1016/j.cose.2025.104359)
- FineGCP: Fine-grained dependency graph community partitioning for attack investigation (Computers & Security, 2025): [https://doi.org/10.1016/j.cose.2024.104311](https://doi.org/10.1016/j.cose.2024.104311)
- MGDA: A provenance graph-based framework for threat detection and attack scenario reconstruction (Computer Networks, 2025/2026 issue): [https://doi.org/10.1016/j.comnet.2025.111806](https://doi.org/10.1016/j.comnet.2025.111806)
- A dynamic provenance graph-based detector for advanced persistent threats (Expert Systems with Applications, 2025): [https://doi.org/10.1016/j.eswa.2024.125877](https://doi.org/10.1016/j.eswa.2024.125877)
- Angus: efficient active learning strategies for provenance based intrusion detection (Cybersecurity, 2025): [https://doi.org/10.1186/s42400-024-00311-y](https://doi.org/10.1186/s42400-024-00311-y)
