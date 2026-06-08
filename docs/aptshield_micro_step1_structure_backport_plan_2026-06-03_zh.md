# APT-Fusion 微小步第一阶段施工单：仅回补证据结构，不改变主成链逻辑

## 0. 文档定位

这份文档是给**另一个执行窗口**直接照着改代码用的施工单，不是讨论稿。

本次只做一个**很小幅度**的改动包，目标是：

1. 从“第一步修改之前”的干净基线出发；
2. 只把第一步里**结构上有价值**的部分搬回来；
3. **绝对不**把之前导致误报放大的运行逻辑带回来；
4. 让后续更大的第二步改造有稳定地基。

这次改完后，系统仍然应该是：

- 旧的 `path_search.py` 决定候选链；
- 旧的 `path_scoring.py` 决定主排序；
- 旧的 `module6_reason` 继续消费 `CandidatePath dossier`；
- 只是 dossier 和 sidecar artifact 比以前更厚、更可追溯。

一句话总结：

**这次不是“改检测器”，而是“补证据骨架”。**

---

## 1. 为什么这次必须收得很小

之前那版“第一步增强”出现过明显负优化，典型现象是：

- 原本不出链的 task 开始出很多链；
- 但这些链并没有更接近真实攻击窗口；
- 高风险窗外误报明显增加；
- `task_0546` 这种图会被长寿命终端/bash 上下文误抬成高风险链。

根因不是结构件本身有问题，而是当时把这些结构件和**放宽成链/放宽评分**的逻辑一起接进去了。

所以这次必须明确：

- 可以回补结构；
- 不可以回补“会改变主成链行为”的逻辑。

如果另一个窗口在实现时违反这个原则，这次修改就算失败。

---

## 2. 本次只做什么，不做什么

## 2.1 本次只做这 5 件事

1. 在 schema 里补回新的证据结构定义；
2. 在 `module3_evidence_recover.py` 里额外输出任务局部证据索引和任务局部证据图；
3. 在 `module4_semantic_compact.py` 里额外输出对象版本和标签来源记录；
4. 在 `module5_path_finder.py` 里给**已经生成好的** `CandidatePath` 补支撑字段；
5. 在 `path_report.py` 里把这些支撑字段展示出来。

## 2.2 本次明确禁止做的事

1. 不改 `search_candidate_paths()` 的搜索逻辑；
2. 不改 `score_candidate_paths()` 的排序逻辑；
3. 不新增更激进的状态传播；
4. 不让 `TaskLocalEvidenceGraph` 直接参与主成链；
5. 不让 `ObjectVersion` 直接参与主成链；
6. 不让 `LabelProvenance` 直接参与主成链；
7. 不改 `module6_reason` 的主输入结构；
8. 不为了某一张图写特判；
9. 不改 evaluator；
10. 不新增任何“如果标签更多就更容易成链”的门槛放宽逻辑。

如果某个实现步骤触碰了上面任意一条，本次施工就偏题了。

---

## 3. 本次改动的总目标

改完之后，系统应当满足下面这句话：

**即使候选链的数量和排序几乎不变，我们也新增了更完整的证据侧写能力。**

换成更具体的话：

- `module5` 输出的候选链数量应该基本由旧逻辑决定；
- 但每条候选链后面应该多出：
  - 任务局部证据图侧写；
  - 对象版本侧写；
  - 标签来源记录；
  - path 支撑事件、支撑对象、支撑关系摘要。

所以这次的成功标准不是“指标涨了”，而是：

1. 行为不明显恶化；
2. 新证据结构真实落盘；
3. 后续第二步能以这些 sidecar 为基础继续改。

---

## 4. 这次要引入的名词，全部用中文理解

## 4.1 `TaskLocalEvidenceGraph`

中文名：**任务局部证据图**

含义：

- 不是全局攻击图；
- 也不是新的主搜索图；
- 它只是“某个 task 回查日志后，整理出来的一张局部证据结构图”。

它的作用：

1. 告诉我们这个 task 里有哪些进程节点；
2. 告诉我们这个 task 里有哪些对象节点；
3. 告诉我们这些节点通过哪些事件相连；
4. 为后续第二步做 provenance-first 或 graph-check 提供地基。

这次只要求：

- 能生成；
- 能落盘；
- 字段稳定；
- 不要求参与主搜索。

## 4.2 `ObjectVersion`

中文名：**对象版本**

含义：

- 一个文件或对象不再只被看成一个静态点；
- 它可以在不同时间点有不同版本。

例如：

- 某文件第一次创建时是版本 0；
- 被写入 payload 后变成版本 1；
- 被改权限后变成版本 2；
- 被执行时指向某个具体版本。

这次只要求：

- 能记录版本推进；
- 能记录每个版本的大致时间范围；
- 能记录哪些进程写过、读过、执行过该版本；
- 不要求直接参与主成链。

## 4.3 `LabelProvenanceRecord`

中文名：**标签来源记录**

含义：

- 任何一个标签，不再只是“最终出现在集合里”；
- 而要能知道它是：
  - 由哪条事件触发；
  - 由哪条规则触发；
  - 挂在哪个实体上。

这次只要求：

- 先覆盖轻标签；
- 先覆盖 `FORK/CLONE` 下的基本继承；
- 先把 provenance 结构落盘；
- 不要求这次就把所有传播都完整串成可逆攻击链。

## 4.4 `support_event_ids`

中文名：**支撑事件 ID 列表**

含义：

- 这条候选链是由哪些关键事件支撑的。

注意：

- 它不是新的成链依据；
- 它只是给已有 path 补证据解释层。

## 4.5 `support_object_keys`

中文名：**支撑对象键列表**

含义：

- 这条候选链和哪些关键对象直接有关。

## 4.6 `support_relations`

中文名：**支撑关系摘要**

含义：

- 用简短字符串概括这条 path 的关键证据关系；
- 例如“哪个进程通过哪个对象与另一个进程关联”。

## 4.7 `chain_kind`

中文名：**链条阶段摘要**

含义：

- 把 `stage_coverage` 压缩成一个短名字；
- 仅用于 dossier 展示；
- 不作为新的评分或筛选依据。

---

## 5. 施工范围：必须修改哪些文件

这次只允许改下面 7 个文件：

1. `D:/daima/APT-Fusion/src/apt_fusion/path_reason/path_schemas.py`
2. `D:/daima/APT-Fusion/src/apt_fusion/path_reason/label_provenance.py`（新增）
3. `D:/daima/APT-Fusion/src/apt_fusion/path_reason/module3_evidence_recover.py`
4. `D:/daima/APT-Fusion/src/apt_fusion/path_reason/module4_semantic_compact.py`
5. `D:/daima/APT-Fusion/src/apt_fusion/path_reason/module5_path_finder.py`
6. `D:/daima/APT-Fusion/src/apt_fusion/path_reason/path_report.py`
7. `D:/daima/APT-Fusion/tests/test_label_provenance.py`（新增）

这次不要改：

- `path_search.py`
- `path_scoring.py`
- `path_propagator.py`
- `module6_attack_reason.py`
- `path_reason_eval.py`

这是硬约束。

---

## 6. 文件级施工单

## 6.1 修改 `path_schemas.py`

### 6.1.1 改动目标

把后续需要的结构定义先补齐，但不改变原有类的主语义。

### 6.1.2 必须新增的 dataclass

必须新增这 3 个 dataclass：

1. `TaskLocalEvidenceGraph`
2. `ObjectVersion`
3. `LabelProvenanceRecord`

### 6.1.3 `TaskLocalEvidenceGraph` 字段要求

至少包含下面字段：

- `task_id: str`
- `process_nodes: list[str]`
- `object_nodes: list[str]`
- `event_edges: list[dict[str, Any]]`
- `anchor_processes: list[str]`
- `boundary_node_ids: list[str]`
- `cross_task_link_refs: list[dict[str, Any]]`

要求：

- 提供 `to_dict()` 和 `from_dict()`
- 序列化后字段名保持稳定

### 6.1.4 `ObjectVersion` 字段要求

至少包含：

- `task_id: str`
- `object_key: str`
- `version_id: str`
- `created_by_event_id: str | None`
- `first_time: datetime | None`
- `last_time: datetime | None`
- `labels: set[str]`
- `writer_processes: set[str]`
- `reader_processes: set[str]`
- `executor_processes: set[str]`

要求：

- 提供 `to_dict()` 和 `from_dict()`
- `labels`、`writer_processes`、`reader_processes`、`executor_processes` 序列化成排序后的列表

### 6.1.5 `LabelProvenanceRecord` 字段要求

至少包含：

- `label_id: str`
- `task_id: str`
- `label: str`
- `label_type: str`
- `holder_entity_type: str`
- `holder_entity_id: str`
- `created_at: datetime | None`
- `source_entity_type: str | None`
- `source_entity_id: str | None`
- `source_type: str`
- `event_id: str | None`
- `event_type: str | None`
- `rule_id: str`
- `context_id: str | None`
- `prev_label_ids: list[str]`
- `segment_id: str | None`

要求：

- 提供 `to_dict()` 和 `from_dict()`
- `prev_label_ids` 保留顺序

### 6.1.6 必须扩展的现有类

#### `ProcessState`

新增字段：

- `context_ids: set[str] = field(default_factory=set)`
- `label_ids: list[str] = field(default_factory=list)`

目的：

- 让进程状态能挂上下文；
- 让进程状态能指向 provenance record。

#### `ObjectState`

新增字段：

- `current_version_id: str = ""`
- `context_ids: set[str] = field(default_factory=set)`
- `label_ids: list[str] = field(default_factory=list)`

目的：

- 让对象状态能指向当前版本；
- 让对象状态也能挂 provenance record。

#### `CandidatePath`

新增字段：

- `support_event_ids: list[str] = field(default_factory=list)`
- `support_object_keys: list[str] = field(default_factory=list)`
- `support_relations: list[str] = field(default_factory=list)`
- `context_ids: list[str] = field(default_factory=list)`
- `chain_kind: str = ""`

目的：

- 不改变 path 的主身份；
- 只增强它的解释层。

### 6.1.7 严禁的实现方式

不要在 `CandidatePath` 里新增会影响旧构造逻辑的必填字段。  
所有新增字段都必须有默认值，保证旧 `CandidatePath.from_dict()` 仍可兼容读取老产物。

---

## 6.2 新增 `label_provenance.py`

### 6.2.1 改动目标

新增一个轻量 provenance 管理器，但只作为工具层，不接管主逻辑。

### 6.2.2 必须新增的类

新增 `LabelProvenanceBuilder`

### 6.2.3 必须提供的方法

至少提供下面方法：

1. `new_segment_id() -> str`
2. `label_ids_for(holder_entity_type: str, holder_entity_id: str) -> list[str]`
3. `add(...) -> str`
4. `get(label_id: str) -> LabelProvenanceRecord | None`
5. `records_by_event(event_id: str) -> list[LabelProvenanceRecord]`
6. `trace_back(label_id: str) -> list[LabelProvenanceRecord]`

### 6.2.4 每个方法的目的

#### `new_segment_id()`

目的：

- 给一组相关 provenance record 分配同一传播段 ID；
- 为后续第二步做链段管理预留接口。

#### `label_ids_for(...)`

目的：

- 快速查某个实体已经挂了哪些 provenance label。

#### `add(...)`

目的：

- 新增一条 provenance record；
- 同时更新内部索引。

#### `records_by_event(...)`

目的：

- 从事件反查“这条事件打了哪些标签”。

#### `trace_back(...)`

目的：

- 从一个终端 label 沿 `prev_label_ids` 反向追一段标签谱系。

### 6.2.5 严禁的实现方式

不要在这里做复杂图算法。  
这里只允许做：

- 存储
- 建索引
- 简单递归回溯

不要在这个文件里写任何会影响 path 搜索结果的逻辑。

---

## 6.3 修改 `module3_evidence_recover.py`

### 6.3.1 改动目标

在不改变现有 `normalized_events` 主输出的前提下，补一套任务局部证据索引与任务局部证据图。

### 6.3.2 允许修改的函数

只修改：

- `run_module3_evidence(...)`

允许新增 helper，但不要改 `_normalized_event_from_match(...)` 的主语义。

### 6.3.3 必须新增的产物目录

新增 5 个目录：

1. `entity_index`
2. `process_event_index`
3. `object_event_index`
4. `task_evidence_frontier`
5. `task_local_evidence_graph`

都挂在 `cfg.module3_evidence_dir` 下。

### 6.3.4 每个目录的内容要求

#### `entity_index/<task>.json`

要求：

- 按 task 保存一个 JSON
- 至少包含：
  - `processes`
  - `objects`

目的：

- 为后续快速查看“task 里有哪些实体”服务。

#### `process_event_index/<task>.json`

要求：

- 键是 `process_guid`
- 值是该进程相关的 `event_id` 列表

目的：

- 后续无需全扫 retained/normalized events 就能定位进程相关事件。

#### `object_event_index/<task>.json`

要求：

- 键是 `object_key`
- 值是该对象相关的 `event_id` 列表

目的：

- 为对象版本和对象因果分析打底。

#### `task_evidence_frontier/<task>.json`

要求：

- 至少包含：
  - `anchor_processes`
  - `boundary_node_ids`
  - `cross_task_link_refs`

目的：

- 保留任务边界和跨任务连接信息。

#### `task_local_evidence_graph/<task>.json`

要求：

- 序列化 `TaskLocalEvidenceGraph`

目的：

- 保存任务局部证据结构图。

### 6.3.5 具体实现要求

在 `run_module3_evidence(...)` 里：

1. 保持原来的 `normalized_events` 输出不变；
2. 在 task 级事件列表确定后，再整理 sidecar；
3. sidecar 的生成只能读取本 task 的 `NormalizedEvent` 列表，不要回头重扫全量日志第二遍；
4. task index 行里要补这些新路径字段；
5. `summary.json` 里也要补这些目录路径。

### 6.3.6 动机和目的

动机：

- 后续如果要做 provenance-first 或 graph-check，没有任务局部证据结构就只能继续硬扫事件流。

目的：

- 先把 task 级证据骨架稳定落盘；
- 但本次不让它参与主成链，所以不会放大误报。

---

## 6.4 修改 `module4_semantic_compact.py`

### 6.4.1 改动目标

在原有轻标签和 semantic skip 逻辑上，额外补：

1. 对象版本；
2. 标签来源记录。

### 6.4.2 允许修改的函数

允许新增 helper，建议新增：

1. `_label_type(label: str) -> str`
2. `_record_label(...)`
3. `_update_object_versions(...)`

不允许修改 `should_skip_semantically(...)` 的算法语义。  
不允许引入新的会显著扩大 retained events 的 force keep 规则。

### 6.4.3 必须新增的产物目录

新增：

1. `object_versions`
2. `label_provenance`

都挂在 `cfg.module4_compact_dir` 下。

### 6.4.4 `_apply_light_prelabels(...)` 的修改要求

当前它返回的是 `set[str]`。  
这次必须改成返回：

- `list[tuple[str, str, str]]`

含义分别是：

1. `entity_type`
2. `label`
3. `rule_id`

要求：

- `entity_type` 只允许是 `process` 或 `object`
- `rule_id` 必须是稳定字符串，不能临时拼描述句

动机：

- provenance 不是只知道“打了哪个标签”，还必须知道“由哪条规则打的”。

### 6.4.5 `_record_label(...)` 的实现要求

职责：

1. 生成一条 `LabelProvenanceRecord`
2. 把 `label_id` 挂到进程或对象状态
3. 如有 `context_id`，同步挂到实体状态

必须支持输入：

- `task_id`
- `holder_entity_type`
- `holder_entity_id`
- `label`
- `rule_id`
- `event`
- `source_entity_type`
- `source_entity_id`
- `context_id`
- `prev_label_ids`
- `segment_id`

要求：

- 轻标签触发必须调用它；
- `FORK/CLONE` 下子进程继承父状态标签时，也必须调用它；
- 如果某标签已在当前实体上存在，可以不重复加状态标签，但 provenance record 是否去重必须保持稳定；推荐：**同一事件同一规则同一标签只记一条**。

### 6.4.6 `_update_object_versions(...)` 的实现要求

版本推进事件集合固定为：

- `WRITE`
- `CREATE`
- `TRUNCATE`
- `RENAME`
- `DELETE`
- `CHMOD`
- `CHOWN`

规则要求：

1. 对象第一次出现时创建版本 `v0001`
2. 遇到推进事件时切换到新版本
3. 读事件记到当前版本的 `reader_processes`
4. 写事件记到当前版本的 `writer_processes`
5. `EXEC/LOAD/MMAP` 记到当前版本的 `executor_processes`

必须注意：

**本次不要因为对象版本推进而改变 retained/skip 的主判定。**

换句话说：

- 版本信息只是 sidecar；
- 不要借此新增 “version_advanced 就必须 retained” 的逻辑。

### 6.4.7 `run_module4_compact(...)` 的接线要求

必须新增：

- `object_versions_by_object`
- `provenance_builder`

然后在事件处理循环中：

1. 保持原有轻标签/semantic skip 主流程顺序；
2. 在轻标签触发后记录 provenance；
3. 在 `FORK/CLONE` 基本继承后记录 provenance；
4. 调用 `_update_object_versions(...)` 更新对象版本；
5. 最后把：
   - `object_versions/<task>.json`
   - `label_provenance/<task>.jsonl`
   落盘

### 6.4.8 动机和目的

动机：

- 当前系统只有“标签结果”，没有“标签来路”；
- 当前系统只有“对象状态”，没有“对象演化过程”。

目的：

- 为下一步更强的链条回溯准备 sidecar；
- 但这次不改变主行为。

---

## 6.5 修改 `module5_path_finder.py`

### 6.5.1 改动目标

在**不改变主 path 搜索和主排序**的前提下，给已有 `CandidatePath` 补支撑信息。

### 6.5.2 允许新增的 helper

建议新增：

1. `_load_object_versions(path: Path) -> dict[str, list[ObjectVersion]]`
2. `_chain_kind_from_stages(stages: set[str] | list[str]) -> str`
3. `_augment_candidate_support(...) -> None`

### 6.5.3 `_load_object_versions(...)` 的要求

要求：

- 读取 `module4` 产出的 `object_versions/<task>.json`
- 返回按 `object_key` 聚合的版本列表

防御性要求：

- 路径为空、缺失、不是文件时，必须直接返回空字典；
- 绝对不能抛异常导致整个 task 失败。

目的：

- 让这一步尽量稳，不因为新 sidecar 缺失影响主 path 流程。

### 6.5.4 `_chain_kind_from_stages(...)` 的要求

将 `stage_coverage` 映射成固定短名字：

- `entry_exec_access_followup`
- `entry_exec_access`
- `entry_collection_exfil`
- `entry_exec`
- `collection_followup`
- 兜底：`generic_path`

规则要固定写死，不允许根据 task 自适应。

目的：

- 只是增强 dossier 可读性；
- 不影响主评分。

### 6.5.5 `_augment_candidate_support(...)` 的要求

职责：

在 path 已经生成并完成旧评分后，补：

- `support_event_ids`
- `support_object_keys`
- `support_relations`
- `context_ids`
- `chain_kind`

#### `support_event_ids`

来源固定为下面 3 类并集：

1. `process_state.evidence_event_ids`
2. bridge 的写/读事件 ID
3. retained events 中与 path 进程直接相关、且事件标签非空的事件 ID

要求：

- 去重
- 保持按事件出现顺序排序

#### `support_object_keys`

来源固定为：

1. path 上进程的 `important_objects`
2. bridge 对象键
3. retained events 中与 `support_event_ids` 对应的对象键

要求：

- 去重
- 排序

#### `support_relations`

至少补两类摘要：

1. bridge 摘要  
   例如：
   `bridge: procA -> procB via /tmp/a.sh [write_to_exec]`
2. object version 摘要  
   例如：
   `version: /tmp/a.sh@v0001 writers=1 readers=2 executors=1`

要求：

- 限制条数，最多保留前 12 条
- 文本稳定

#### `context_ids`

来源固定为：

1. path 上所有进程状态的 `context_ids`
2. path 关联对象状态的 `context_ids`

要求：

- 去重
- 排序

#### `chain_kind`

来源固定为 `_chain_kind_from_stages(path.stage_coverage)`

### 6.5.6 最关键的硬约束

`_augment_candidate_support(...)` **必须放在**：

1. `search_candidate_paths(...)` 之后
2. `score_candidate_paths(...)` 之后

不能放在前面。

这是本次施工最关键的约束之一。

原因：

- 这次只允许增强解释层；
- 不允许 support 结构反过来影响主成链和主排序。

### 6.5.7 动机和目的

动机：

- 当前 path dossier 太薄；
- 即使 path 是对的，也很难解释“这条链为什么成立”。

目的：

- 先让 path 更可解释；
- 但不改变 path 数量和主排序来源。

---

## 6.6 修改 `path_report.py`

### 6.6.1 改动目标

把 `CandidatePath` 上新增的 support 字段体现在 dossier 和 markdown 里。

### 6.6.2 允许修改的函数

只改：

1. `build_path_dossier(...)`
2. `render_candidate_path_markdown(...)`

### 6.6.3 `build_path_dossier(...)` 必须新增的字段

在 dossier 顶层补：

- `chain_kind`
- `context_ids`
- `support_event_ids`
- `support_object_keys`
- `support_relations`
- `process_envelope_time_range`

要求：

- `process_envelope_time_range` 直接复用 path 的旧 `time_range`
- 不要在这次施工里发明新的时间窗算法

### 6.6.4 `render_candidate_path_markdown(...)` 必须新增的展示

新增 `## Support` 小节，顺序固定为：

1. `chain_kind`
2. `context_ids`
3. `support_object_keys`
4. `support_relations`

要求：

- 没有内容时不显示空列表标题
- 不改原来的 timeline 选取逻辑

### 6.6.5 动机和目的

动机：

- 另一个窗口跑实验时，需要直接从 markdown 看出“新结构有没有落下来”；
- 不然只能翻 JSON，很低效。

目的：

- 提高人工检查效率；
- 为后续 module6 小步增强预留上下文。

---

## 6.7 新增 `tests/test_label_provenance.py`

### 6.7.1 改动目标

为这次新增的结构层补最小回归测试。

### 6.7.2 必须覆盖的测试点

至少写 2 组测试：

#### 测试 1：`LabelProvenanceBuilder.trace_back(...)`

构造一组：

- label A
- label B 依赖 A
- label C 依赖 B

验证：

- `trace_back(C)` 返回链条顺序稳定
- 不丢上游 label

#### 测试 2：`CandidatePath` 的新字段序列化/反序列化

构造一个 `CandidatePath`，填：

- `support_event_ids`
- `support_object_keys`
- `support_relations`
- `context_ids`
- `chain_kind`

验证：

- `to_dict()` 后字段存在
- `from_dict()` 后值不丢

### 6.7.3 允许但不是必须补的测试

如果实现窗口还有时间，可以再补：

- `ObjectVersion` round-trip
- `TaskLocalEvidenceGraph` round-trip

但这两项不是本次必须项。

---

## 7. 推荐实现顺序

必须按这个顺序改，不要乱序：

1. 先改 `path_schemas.py`
2. 再新增 `label_provenance.py`
3. 再改 `module3_evidence_recover.py`
4. 再改 `module4_semantic_compact.py`
5. 再改 `module5_path_finder.py`
6. 再改 `path_report.py`
7. 最后补 `tests/test_label_provenance.py`

这样做的原因：

- schema 不先落，后面所有模块都没法稳定接；
- `module4` 依赖 provenance 结构；
- `module5` 依赖 object version sidecar；
- `path_report` 最后改，避免中途 dossier 格式不停变。

---

## 8. 这次改完以后，另一个窗口必须怎么验收

## 8.1 代码级验收

必须通过：

1. `path_reason` 相关模块可导入
2. 新增测试通过
3. 旧测试至少这些不能挂：
   - `test_semantic_skip.py`
   - `test_bridge_builder.py`
   - `test_path_search.py`
   - `test_module5_split_inheritance.py`

## 8.2 产物级验收

至少检查一个 task，确认下面产物真实存在：

### `module3_evidence`

- `entity_index/<task>.json`
- `process_event_index/<task>.json`
- `object_event_index/<task>.json`
- `task_evidence_frontier/<task>.json`
- `task_local_evidence_graph/<task>.json`

### `module4_compact`

- `object_versions/<task>.json`
- `label_provenance/<task>.jsonl`

### `module5_paths`

`candidate_paths/<task>.json` 中的每条 path 至少出现：

- `support_event_ids`
- `support_object_keys`
- `support_relations`
- `context_ids`
- `chain_kind`

## 8.3 行为级验收

这次最重要的验收条件是：

**不能因为这次结构回补，导致候选链数量出现明显异常飙升或归零。**

执行要求：

- 选一组小样本 task 与回退前基线做对照；
- 如果 `candidate_path_count` 出现大幅波动，必须先定位原因，不能直接继续跑全量实验。

本次允许的变化：

- dossier 更厚
- sidecar 更多

本次不允许的变化：

- 因为这次改动把 path 成链门槛放宽
- 因为这次改动把 path 排序逻辑改变

---

## 9. 如果实现时遇到选择题，统一按下面规则处理

1. **凡是可能影响 path 数量的改动，一律不做。**
2. **凡是只是补 sidecar 和 dossier 的改动，可以做。**
3. **凡是要改 `path_search.py` 或 `path_scoring.py` 的想法，一律留到下一步。**
4. **凡是需要依赖 task 级特判的想法，一律不做。**

---

## 10. 这次施工完成后，代码应该处于什么状态

完成后，代码应该满足下面这句话：

**它仍然是旧的 path 检测器，但已经长出了更完整的证据骨架。**

这正是本次想要的结果。

如果另一个窗口改完后，系统已经明显变成：

- 更容易出链
- 更容易把重上下文会话抬成高风险链
- 需要重新解释 path 搜索结果

那就说明它改过界了。

---

## 11. 给执行窗口的最后一句话

这次不是让你“把系统改强”，而是让你“把系统的证据层补齐，同时保证行为基本不变”。

只要你在实现过程中始终抓住这个原则，这次就不会再重演之前那种“结构增强带来运行负优化”的问题。
