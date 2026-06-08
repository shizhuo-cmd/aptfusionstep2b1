# APT-Fusion 最终实施方案：基于 APTShield 思想的检测后语义压缩、候选攻击路径抽取与 LLM ATT&CK 分析

## 0. 文档定位

本文档是 APT-Fusion 在 `module1/module2` 之后的新后半段最终实施规格书。

目标不是继续修补当前的：

```text
module3_index -> module3_bundle -> module4_reason
```

而是以 APTShield 的核心思想为指导，重构为：

```text
module1/module2 检测恶意任务图
-> 回原始日志取证据
-> 语义压缩
-> 标签初始化与受控传播
-> 候选攻击路径抽取
-> 将攻击路径文档喂给大模型做 ATT&CK tactic/technique 分析
```

本文档面向“直接改项目”的实现，不是研究性草稿。

---

## 1. 总体结论

### 1.1 保留什么

保留当前前半段：

- `module1`：任务图构建
- `module2`：可疑任务图检测

这些模块仍负责输出：

- `task_subgraphs.json`
- `suspicious_tasks.json`
- `task_meta_rich.json`
- `task_attribution.json`
- `process_scores.csv`

### 1.2 替换什么

当前后半段不再以 `module3_index/module3_bundle/module4_reason` 为主线。

新主线改为：

```text
module3_evidence_recover
-> module4_semantic_compact
-> module5_path_finder
-> module6_attack_reason
-> module7_campaign (可选，后置)
```

### 1.3 为什么要这样改

当前后半段的主要问题不是“没有压缩”，而是“压缩时机和压缩粒度不对”：

1. 先按任务图进程把大量 1-hop 原始事件整池拉回；
2. 再按 priority/top-k 裁剪；
3. 再把压缩后的混合事件交给 LLM。

这会导致：

1. 不同攻击阶段的事件被混在一个大包里；
2. 重复语义事件占据预算；
3. 高复用对象把多条无关线索错误粘在一起；
4. LLM 实际看到的是“噪声压缩包”，不是“攻击语义链”。

APTShield 真正值得借鉴的不是“剪叶子”本身，而是：

1. `Redundant Semantics Skipping`
2. `Non-viable Entity Pruning`
3. `标签初始化 + 传播 + 聚合`
4. `把大图问题变成少量攻击语义链问题`

---

## 2. 新主线设计

### 2.1 目标流水线

```text
module1/module2
  -> module3_evidence_recover
  -> module4_semantic_compact
  -> module5_path_finder
  -> module6_attack_reason
  -> module7_campaign(optional)
```

### 2.2 每个阶段的职责

#### `module3_evidence_recover`

职责：

1. 读取 `module1/module2` 的恶意任务图及 sidecar；
2. 根据任务图进程节点回原始日志；
3. 做进程 ID 对齐、事件标准化、对象基础分类；
4. 输出“仍然 recall-oriented，但不再是原始混乱日志”的标准化事件流。

#### `module4_semantic_compact`

职责：

1. 维护对象访问记录；
2. 做 APTShield 风格语义跳过；
3. 做阶段感知 episode 聚合；
4. 对无价值退出叶子进程和无价值对象做视图层剪枝。

#### `module5_path_finder`

职责：

1. 完成完整标签初始化；
2. 沿父子关系做受控状态传播；
3. 只通过小范围高置信对象建立桥接边；
4. 做时间因果路径搜索；
5. 输出 Top-K 候选攻击路径。

#### `module6_attack_reason`

职责：

1. 将候选路径转换成 LLM-friendly 攻击路径文档；
2. 复用当前 `attack_kb.py` 的 ATT&CK 检索逻辑；
3. 让 LLM 基于“攻击路径文档”做 tactic/technique 映射与解释；
4. 输出结构化 ATT&CK 报告。

#### `module7_campaign`

职责：

1. 聚合多个路径报告；
2. 做任务间 IOC / technique / 时间窗口 / 关键进程相似度聚类；
3. 属于后置可选项，不是第一阶段必须实现。

---

## 3. 目录与文件落点

建议新增/修改如下文件：

```text
src/apt_fusion/
  module3_evidence_recover.py
  module4_semantic_compact.py
  module5_path_finder.py
  module6_attack_reason.py
  module7_campaign.py                  # 可选，后续再接
  path_schemas.py
  path_rules.py
  semantic_skip.py
  episode_aggregation.py
  object_classifier.py
  evidence_normalizer.py
  path_report.py
```

建议新增测试：

```text
tests/
  test_evidence_normalizer.py
  test_object_classifier.py
  test_semantic_skip.py
  test_episode_aggregation.py
  test_path_labeling.py
  test_bridge_builder.py
  test_path_search.py
  test_attack_reason_context.py
```

建议新增规则文件：

```text
configs/
  path_reason_default.yaml
```

---

## 4. Pipeline 改造要求

### 4.1 新 stage 名称

修改 `src/apt_fusion/pipeline.py`，增加以下 stage：

```text
module3_evidence
module4_compact
module5_paths
module6_reason
full_path_reason
```

建议保留旧链路作为对照：

```text
full_reason          # 旧 indexed bundle route，保留用于对照实验
full_path_reason     # 新主线
```

### 4.2 新主线执行顺序

```text
module1
-> module2
-> module3_evidence
-> module4_compact
-> module5_paths
-> module6_reason
```

### 4.3 Campaign 位置

如果需要 campaign clustering，放在 `module6_reason` 之后：

```text
full_path_reason
-> optional module7_campaign
```

不要在 `module5_paths` 之前做 campaign。

---

## 5. 配置模型改造要求

修改 `src/apt_fusion/config.py`，增加以下目录属性：

```python
module3_evidence_dir
module4_compact_dir
module5_paths_dir
module6_reason_dir
module7_campaign_dir
```

新增配置字段建议如下：

```yaml
path_reason_enabled: true

evidence_recover_include_object_side: true
evidence_recover_max_events_per_task: 300000
evidence_recover_task_time_padding_minutes: 30
evidence_recover_anchor_top_k: 3

semantic_skip_enabled: true
semantic_skip_ttl_seconds: 600
semantic_skip_max_table_size: 100000
semantic_force_keep_external_network: true
semantic_force_keep_exec: true
semantic_force_keep_write_sensitive: true

episode_max_representative_events: 5
episode_time_bucket_minutes: 1

path_bridge_max_time_gap_minutes: 30
path_max_depth: 6
path_max_total_span_minutes: 180
path_hot_process_threshold: 25.0
path_top_k: 20

path_require_execution_strong_for_high: true
path_allow_weak_execution_medium: true

reason_top_paths_per_task: 5
reason_max_timeline_items_per_path: 24
reason_max_bridge_edges_per_path: 8
reason_max_objects_per_path: 12
```

所有标签规则、路径白名单、对象路径规则、权重阈值，统一放进：

```text
configs/path_reason_default.yaml
```

---

## 6. 与 APT-Fusion 前半段的对接契约

这是必须写死的实施契约。

### 6.1 上游输入

`module3_evidence_recover` 必须消费：

1. `module1/task_subgraphs.json`
2. `module2/suspicious_tasks.json`
3. `module2/task_meta_rich.json`
4. `module2/task_attribution.json`
5. `module2/process_scores.csv`
6. `source_logs`

### 6.2 sidecar 先验

将 `task_meta_rich`、`task_attribution`、`process_scores` 合并成每个 task 一个 prior：

```json
{
  "task_id": "task_0558",
  "task_score": 0.87,
  "task_probability": 0.92,
  "root_process_ids": ["P1"],
  "top_processes": [{"process_id": "P2", "score": 0.93}],
  "top_edges": [{"src": "P2", "dst": "P3", "score": 0.81}],
  "first_event": "2026-05-25T10:00:00",
  "last_event": "2026-05-25T11:00:00",
  "matched_event_count_total": 183420
}
```

### 6.3 ID 对齐必须单独实现

当前 APT-Fusion 前半段 sidecar 中的 `process_id` 不一定等于最终恢复事件中的 `process_guid`。

因此必须新增：

```text
module3_evidence/id_mapping.json
```

至少建立：

```json
{
  "task_id": "task_0558",
  "process_id_to_process_guid": {
    "CID_1234": "trace:1234:2026-05-25T10:05:12:/bin/sh"
  }
}
```

如果无法完成映射，不允许静默忽略；必须在 summary 中记录：

```text
unmapped_seed_process_count
unmapped_top_process_count
```

---

## 7. 数据结构最终定义

### 7.1 `NormalizedEvent`

```python
@dataclass
class NormalizedEvent:
    event_id: str
    raw_log_id: str
    task_id: str
    host: str

    timestamp: datetime | None
    order_index: int

    process_guid: str
    process_name: str
    process_exe: str | None
    process_cmdline: str | None
    parent_process_guid: str | None

    event_type: str
    object_type: str
    object_key: str
    object_name: str | None
    object_class: str

    syscall_direction: str
    semantic_flow_direction: str

    result: str | None
    local_ip: str | None
    local_port: int | None
    remote_ip: str | None
    remote_port: int | None

    raw_event: dict
```

### 7.2 `ObjectAccessRecord`

```python
@dataclass
class ObjectAccessRecord:
    task_id: str
    object_key: str
    object_type: str
    object_class: str

    process_guid: str
    process_name: str

    event_type: str
    timestamp: datetime | None
    order_index: int
    event_id: str
    raw_log_id: str

    syscall_direction: str
    semantic_flow_direction: str

    process_label_signature_before: str
    process_label_signature_after: str

    object_label_signature_before: str
    object_label_signature_after: str

    object_semantic_epoch_before: int
    object_semantic_epoch_after: int
    process_control_epoch_before: int
    process_control_epoch_after: int
```

### 7.3 `ProcessState`

```python
@dataclass
class ProcessState:
    task_id: str
    process_guid: str
    process_name: str
    process_exe: str | None
    process_cmdline: str | None
    start_time: datetime | None
    end_time: datetime | None

    status_labels: set[str]
    behavior_labels: set[str]
    aggregate_labels: set[str]

    process_control_epoch: int
    score: float
    prior_score: float

    evidence_event_ids: list[str]
    important_objects: set[str]
```

### 7.4 `ObjectState`

```python
@dataclass
class ObjectState:
    task_id: str
    object_key: str
    object_type: str
    object_class: str

    labels: set[str]
    semantic_epoch: int

    access_records: list[ObjectAccessRecord]

    first_time: datetime | None
    last_time: datetime | None

    is_bridge_allowed: bool
    bridge_reason: str | None

    read_count: int = 0
    write_count: int = 0
    exec_count: int = 0
```

### 7.5 `EventEpisode`

```python
@dataclass
class EventEpisode:
    episode_id: str
    task_id: str
    process_guid: str
    event_type: str
    object_type: str
    object_class: str
    object_key: str

    semantic_flow_direction: str
    process_label_signature: str
    object_label_signature: str
    object_semantic_epoch: int
    process_control_epoch: int

    count: int
    first_time: datetime | None
    last_time: datetime | None

    representative_event_ids: list[str]
    representative_raw_log_ids: list[str]
    labels_triggered: set[str]
    is_force_kept: bool
```

### 7.6 `BridgeEdge`

```python
@dataclass
class BridgeEdge:
    task_id: str
    src_process_guid: str
    dst_process_guid: str
    object_key: str
    object_labels: set[str]

    write_event_id: str
    read_or_exec_event_id: str
    write_time: datetime | None
    read_or_exec_time: datetime | None

    bridge_type: str
    confidence: float
    reason: str
```

### 7.7 `CandidatePath`

```python
@dataclass
class CandidatePath:
    path_id: str
    task_id: str

    process_chain: list[str]
    bridge_edges: list[BridgeEdge]
    stage_coverage: list[str]
    labels: list[str]

    risk_score: float
    risk_level: str
    path_type: str

    time_range: tuple[datetime | None, datetime | None]
    evidence_timeline: list[dict]
    summary: str
    warnings: list[str]
```

---

## 8. 事件方向与语义方向

不允许再用单一 `direction` 字段。

### 8.1 `syscall_direction`

表示系统调用发起方向：

```text
P_TO_O / O_TO_P / P_TO_P / UNKNOWN
```

### 8.2 `semantic_flow_direction`

表示语义、控制、污染或数据的流动方向：

```text
P_TO_O / O_TO_P / P_TO_P / BIDIRECTIONAL / NONE / UNKNOWN
```

### 8.3 典型映射

| event_type | syscall_direction | semantic_flow_direction |
|---|---|---|
| READ file | P_TO_O | O_TO_P |
| WRITE file | P_TO_O | P_TO_O |
| EXEC file | P_TO_O | O_TO_P |
| MMAP/LOAD file | P_TO_O | O_TO_P |
| RECV socket | P_TO_O | O_TO_P |
| SEND socket | P_TO_O | P_TO_O |
| CONNECT socket | P_TO_O | P_TO_O |
| ACCEPT socket | O_TO_P | O_TO_P |
| FORK/CLONE | P_TO_P | P_TO_P |
| EXIT | P_TO_P | NONE |
| CHMOD/CHOWN/RENAME/DELETE | P_TO_O | P_TO_O |

规则要求：

1. 标签传播只看 `semantic_flow_direction`；
2. 报告解释可同时展示两种方向；
3. 压缩 key 中使用 `semantic_flow_direction`，不使用旧 `direction`。

---

## 9. `module3_evidence_recover` 详细设计

### 9.1 输入

每个 task 输入：

1. 任务图进程集合
2. task prior
3. 原始日志

### 9.2 取证策略

新方案不使用“把所有种子进程的所有邻接对象全量铺开”的粗回拉。

改成两段式：

#### 第一段：进程直连事件回拉

回拉所有与任务图进程直接相关的事件：

- process -> file
- process -> process
- process -> network
- process -> ipc/object

默认同时支持：

- subject side
- 关键 object side

#### 第二段：受控对象扩张

仅对下列对象允许二次扩张：

- 临时目录文件
- 被执行文件
- 可能来自下载/上传的文件
- 持久化文件
- 权限配置文件
- archive 文件

不允许对下列对象做二次扩张：

- `/etc/passwd`
- `.bash_history`
- 公共 DNS / 公共 IP
- 系统库
- 高频普通日志

### 9.3 输出

输出目录：

```text
artifacts/module3_evidence/
  task_index.json
  id_mapping.json
  priors_by_task.json
  normalized_events/
    task_0001.jsonl
  summary.json
```

### 9.4 可复用当前代码

建议优先复用：

- `module3_local_stream.py` 的事件解析逻辑
- 进程 alias 归一化逻辑
- 现有 `task_meta_rich/task_attribution` 读入逻辑

但输出不再是 SQLite index，也不再是旧 structured report。

---

## 10. `module4_semantic_compact` 详细设计

这是新主线的核心。

### 10.1 处理顺序必须固定

处理顺序如下：

```text
NormalizedEvent
-> object classify
-> prelabel init
-> semantic skip
-> episode aggregation
-> compacted object/process state export
```

注意：

`prelabel init` 必须先于 `semantic skip`。

原因：

1. `semantic skip` 需要 `process_label_signature`
2. `semantic skip` 需要 `object_label_signature`
3. `ObjectAccessRecord` 需要 before/after label signature

### 10.2 预标签与全标签分离

`module4_semantic_compact` 只做压缩所需的轻量预标签。

预标签范围：

- `P_WEB_CTX`
- `P_REMOTE_CTX`
- `P_NET_CTX`
- `P_UNTRUSTED_CTX`
- `O_NET_EXTERNAL`
- `O_FILE_TEMP`
- `O_FILE_UPLOADED`
- `O_FILE_DOWNLOADED`
- `O_FILE_NONEXIST`
- `O_PERSISTENCE`
- `O_PRIV_CONFIG`
- `O_CREDENTIAL`
- `O_HISTORY`
- `O_BUSINESS_DATA`

不要在这一阶段就做完整 path-risk 评分。

### 10.3 `semantic_epoch` 与 `process_control_epoch`

必须分开维护。

#### 对象 `semantic_epoch`

表示对象内容或安全语义变化。

以下事件触发：

```text
WRITE
CREATE
TRUNCATE
CHMOD
CHOWN
RENAME
DELETE
```

#### 进程 `process_control_epoch`

表示进程控制语义变化。

以下事件触发：

```text
RECV external
EXEC file
LOAD/MMAP suspicious executable object
```

规则：

1. `EXEC` 不应直接增加 `object.semantic_epoch`
2. `EXEC` 应增加 `process.process_control_epoch`
3. 需要保留“同一文件被执行过”这一事实时，用标签或 access record 表达

### 10.4 Semantic Skip

#### LST key

推荐 key：

```text
task_id
+ process_guid
+ event_type
+ object_key
+ object_class
+ semantic_flow_direction
```

#### 跳过条件

当前事件只有在以下全部满足时才允许跳过：

1. 不是强制保留事件
2. `process_label_signature` 未变化
3. `object_label_signature` 未变化
4. `object_semantic_epoch` 未变化
5. `process_control_epoch` 未变化
6. 距离上次同语义事件未超过 TTL

#### 强制保留事件

以下事件绝不允许在 `SemanticSkip` 中被删，只允许在后续 episode 聚合：

```text
EXEC
FORK
CLONE
CONNECT external
ACCEPT external
SEND external
RECV external
WRITE temp
WRITE suspicious-written
WRITE persistence
WRITE privilege
READ credential
READ history
READ business
CHMOD
CHOWN
RENAME
DELETE
EXIT
```

#### 失效机制

遇到以下事件时必须失效：

```text
WRITE/CREATE/TRUNCATE/CHMOD/CHOWN/RENAME/DELETE object:
  invalidate LST entries involving object_key
  object.semantic_epoch += 1

RECV external into process:
  invalidate LST entries involving process_guid
  process.process_control_epoch += 1

EXEC file:
  invalidate LST entries involving process_guid
  process.process_control_epoch += 1

FORK parent->child:
  initialize child status context from parent
```

### 10.5 Episode Aggregation

`SemanticSkip` 之后再按阶段感知 key 做 episode 聚合。

episode key：

```text
task_id
+ process_guid
+ event_type
+ object_type
+ object_class
+ normalized_object_key
+ semantic_flow_direction
+ process_label_signature
+ object_label_signature
+ object_semantic_epoch
+ process_control_epoch
```

这样可以避免把：

- benign write
- suspicious write
- downloaded-file exec
- later persistence write

压成同一个桶。

### 10.6 非活跃实体剪枝

这一步只作用于“路径视图”，不删除原始标准化事件文件。

可剪枝进程必须满足：

1. 已退出
2. 是叶子
3. 无强标签
4. 无高危后代
5. 不在 top_process/top_edge prior 中
6. 不参与保留路径

任何一条不满足，都不能剪。

### 10.7 输出

```text
artifacts/module4_compact/
  compact_summary.json
  object_states/
    task_0001.json
  process_states_prepath/
    task_0001.json
  episodes/
    task_0001.json
  access_records/
    task_0001.jsonl
```

---

## 11. 标签体系最终原则

每个标签都必须在 `path_reason_default.yaml` 中声明完整元信息：

```yaml
label_name:
  category: context | behavior | object | aggregate
  init_rules: [...]
  propagation_rules: [...]
  stage_mapping: Entry | ExecutionWeak | ExecutionStrong | TargetAccess | FollowUp | None
  bridge_allowed: true | false
  score: 0
  confidence: low | medium | high
  ttl_minutes: null
```

任何没有 `init_rules` 且没有明确来源的标签，一律删除。

---

## 12. 必须保留的标签集合

### 12.1 进程上下文标签

```text
P_WEB_CTX
P_REMOTE_CTX
P_NET_CTX
P_UNTRUSTED_CTX
P_HIGH_VALUE_CTX
P_SUSPECT_CTRL_CTX
```

### 12.2 进程行为标签

```text
B_EXTERNAL_RECV
B_EXTERNAL_SEND
B_EXEC_TEMP
B_EXEC_DOWNLOADED
B_EXEC_UPLOADED
B_EXEC_SUSPECT_WRITTEN
B_SHELL_SPAWN
B_SCRIPT_EXEC
B_INTERPRETER_LAUNCH
B_READ_CRED
B_READ_HISTORY
B_READ_BUSINESS
B_MASS_FILE_ACCESS
B_WRITE_PERSISTENCE
B_WRITE_PRIV_CONFIG
B_ARCHIVE_DATA
B_DELETE_LOG
B_LATERAL_CONNECT
B_REMOTE_LOGIN_SERVICE
B_WEB_WRITE
```

### 12.3 对象标签

```text
O_NET_EXTERNAL
O_FILE_TEMP
O_FILE_UPLOADED
O_FILE_DOWNLOADED
O_FILE_WRITTEN_BY_NET_CONTEXT
O_FILE_NONEXIST
O_SUSPECT_WRITTEN_EXECUTABLE
O_CREDENTIAL
O_HISTORY
O_BUSINESS_DATA
O_AUTH_CONFIG
O_PERSISTENCE
O_PRIV_CONFIG
O_ARCHIVE
O_SECURITY_LOG
```

### 12.4 聚合标签

```text
A_CHILD_SUSPICIOUS
A_BRIDGED_BY_SUSPICIOUS_OBJECT
```

---

## 13. 关键标签初始化规则

这里只写第一版必须实现的规则。

### 13.1 `P_WEB_CTX`

初始化条件：

1. 进程名命中 Web 服务进程
2. 入站端口命中 80/443/8080/8443 等
3. 访问 Web 根目录或 upload 路径

规则：

1. `P_WEB_CTX` 是 context，不是恶意标签
2. Web worker 的普通子进程默认只继承 `P_WEB_CTX`
3. 只有 child 是 shell/script/downloader/unknown binary 时，才可弱化触发 `P_SUSPECT_CTRL_CTX`

### 13.2 `P_REMOTE_CTX`

初始化条件：

1. 进程名命中 `sshd/dropbear/telnetd/xrdp`
2. 入站远程管理端口
3. `pts/*` 且父进程为 `sshd/dropbear`

规则：

1. 默认传播 3~5 层
2. 如果后续连续多层都是低风险系统命令，则停止传播

### 13.3 `O_FILE_DOWNLOADED`

不要再用“有网络上下文的进程写文件”直接打下载标签。

必须要求满足以下之一：

1. downloader 进程写文件，且最近 120 秒内有外连
2. cmdline 中带 URL 或下载参数
3. 最近 120 秒内有外部 `RECV`，且写入 temp dir

若仅满足“网络上下文写文件”，只打：

```text
O_FILE_WRITTEN_BY_NET_CONTEXT
```

且该标签不能直接作为强桥接依据。

### 13.4 `B_SHELL_SPAWN`

不要因为进程名是 `sh/bash` 就打高风险。

只在以下至少一项成立时打：

1. 父进程有 `P_WEB_CTX/P_REMOTE_CTX/P_SUSPECT_CTRL_CTX`
2. 父进程是 Web 服务
3. cmdline 有 `-c`、`curl`、`wget`、`nc`、`/tmp/`、`/dev/shm/`
4. 执行对象带 `O_FILE_DOWNLOADED/O_FILE_UPLOADED/O_SUSPECT_WRITTEN_EXECUTABLE`

并且：

1. 其 `stage_mapping = ExecutionWeak`
2. 不直接自动补满 `ExecutionStrong`

### 13.5 `B_SCRIPT_EXEC`

解释器默认只算弱执行。

触发条件同样要依赖：

1. 可疑 cmdline
2. 可疑父上下文
3. 读取/执行了可疑对象

### 13.6 `B_MASS_FILE_ACCESS`

由窗口统计产生，不由单条事件产生。

第一版建议：

```text
5 分钟内 distinct_file_count >= 100
或 total_read_bytes >= 100MB
```

### 13.7 `O_FILE_NONEXIST`

仅当：

```text
READ/OPEN/EXEC/LOAD/MMAP
且返回 ENOENT / NOT_FOUND
```

才初始化。

### 13.8 `O_BUSINESS_DATA`

必须由 config 提供业务目录或后缀匹配，不允许硬编码猜测。

---

## 14. `module5_path_finder` 详细设计

### 14.1 输入

`module5_path_finder` 读取：

1. `module4_compact` 的 episodes
2. `module4_compact` 的 access_records
3. `module4_compact` 的 process/object states
4. `module3_evidence` 的 task prior / id mapping

### 14.2 完整标签化

在这一阶段：

1. 完成所有非预标签行为标签打标
2. 沿父子边做受控传播
3. 做反向聚合 `A_CHILD_SUSPICIOUS`

### 14.3 传播规则

只传播状态标签：

```text
P_WEB_CTX
P_REMOTE_CTX
P_NET_CTX
P_UNTRUSTED_CTX
P_HIGH_VALUE_CTX
P_SUSPECT_CTRL_CTX
```

传播约束：

1. `P_HIGH_VALUE_CTX` 最多传播 1 层
2. `P_NET_CTX` 最多传播 2 层
3. `P_UNTRUSTED_CTX/P_SUSPECT_CTRL_CTX` 最多传播 3 层
4. common daemon 默认不向常规子进程传播可疑控制标签
5. 只有 child 是 shell/script/downloader/network-tool/unknown binary 时才放宽

### 14.4 桥接对象白名单

第一版只允许以下对象做桥接器：

```text
O_FILE_TEMP
O_FILE_DOWNLOADED
O_FILE_UPLOADED
O_SUSPECT_WRITTEN_EXECUTABLE
O_ARCHIVE
O_PERSISTENCE
O_PRIV_CONFIG
```

以下对象只作证据，不作桥接器：

```text
O_CREDENTIAL
O_HISTORY
O_BUSINESS_DATA
O_NET_EXTERNAL
O_AUTH_CONFIG
O_SECURITY_LOG
system_library
public_shared_file
```

### 14.5 桥接边构建

桥接只能基于 `ObjectAccessRecord`。

文件桥接规则：

1. `WRITE/CREATE/RENAME` 作为源
2. `READ/EXEC/MMAP/LOAD` 作为目标
3. 必须满足：
   - `writer != reader`
   - `write.order_index < read_or_exec.order_index`
   - 时间差不超过 `path_bridge_max_time_gap_minutes`
   - 生命周期因果可解释
   - `same_or_valid_semantic_epoch`

桥接置信度基线：

```text
WRITE temp -> EXEC same file: high
WRITE downloaded -> EXEC same file: high
WRITE uploaded -> EXEC same file: high
WRITE archive -> SEND external: medium
WRITE persistence file -> later spawned process: medium/high
READ credential -> later external send: evidence only, not bridge
same external IP connect: never bridge
```

### 14.6 Execution 分层

#### ExecutionWeak

```text
B_SHELL_SPAWN
B_SCRIPT_EXEC
B_INTERPRETER_LAUNCH
```

#### ExecutionStrong

```text
B_EXEC_TEMP
B_EXEC_DOWNLOADED
B_EXEC_UPLOADED
B_EXEC_SUSPECT_WRITTEN
```

规则：

1. 高危路径必须至少包含一个 `ExecutionStrong`
2. 只有 `ExecutionWeak` 的路径不能直接排到高危

### 14.7 阶段定义

```text
Entry:
  P_WEB_CTX
  P_REMOTE_CTX
  P_NET_CTX
  B_EXTERNAL_RECV
  B_REMOTE_LOGIN_SERVICE

ExecutionWeak:
  B_SHELL_SPAWN
  B_SCRIPT_EXEC
  B_INTERPRETER_LAUNCH

ExecutionStrong:
  B_EXEC_TEMP
  B_EXEC_DOWNLOADED
  B_EXEC_UPLOADED
  B_EXEC_SUSPECT_WRITTEN

TargetAccess:
  B_READ_CRED
  B_READ_HISTORY
  B_READ_BUSINESS
  B_MASS_FILE_ACCESS
  B_WRITE_PRIV_CONFIG

FollowUp:
  B_EXTERNAL_SEND
  B_LATERAL_CONNECT
  B_WRITE_PERSISTENCE
  B_ARCHIVE_DATA
  B_DELETE_LOG
```

### 14.8 路径搜索图

路径搜索图由两部分组成：

1. 原始进程父子边
2. 受限对象桥接边

### 14.9 路径合法性约束

路径必须满足：

1. 全链时间单调
2. 每个事件时间落在对应进程生命周期范围内
3. 父进程创建子进程时间早于子进程关键行为
4. 桥接源写时间早于桥接目标读/执时间
5. 使用桥接对象时 `semantic_epoch` 合法

### 14.10 保留路径条件

强候选路径：

```text
Entry + ExecutionStrong + TargetAccess
或
Entry + ExecutionStrong + FollowUp
或
ExecutionStrong + TargetAccess + FollowUp
或
Entry + ExecutionWeak + persistence/privilege/high-value action
```

弱候选路径：

```text
Entry + ExecutionWeak
Entry + TargetAccess
ExecutionWeak + FollowUp
```

弱候选路径允许输出，但排序必须落后于强候选。

### 14.11 路径评分

最终路径分数：

```text
PathScore =
  label_score
+ stage_coverage_score
+ temporal_coherence_score
+ bridge_confidence_score
+ apt_fusion_prior_score
- whitelist_penalty
- high_reuse_object_penalty
- weak_execution_penalty
```

`apt_fusion_prior_score` 建议来自：

1. `task_score`
2. path 中进程是否命中 `top_processes`
3. path 中边是否命中 `top_edges`
4. 事件是否主要落在 `task_time_range`

### 14.12 输出

```text
artifacts/module5_paths/
  process_summary.json
  object_summary.json
  bridge_edges/
    task_0001.json
  candidate_paths/
    task_0001.json
    task_0001.md
  summary.json
```

---

## 15. `module6_attack_reason` 详细设计

### 15.1 核心原则

LLM 不再直接看大事件池，而只看候选攻击路径文档。

### 15.2 复用当前能力

建议复用当前代码中的：

1. `attack_kb.py` 的 ATT&CK STIX 解析与检索
2. `module4_reason.py` 中 technique/tactic 兼容性校验
3. 当前 prompt input 导出机制

### 15.3 每条候选路径的 LLM 输入

每条 path 生成一个 dossier：

```json
{
  "task_id": "task_0558",
  "path_id": "task_0558_path_003",
  "path_type": "Entry-ExecutionStrong-TargetAccess-FollowUp",
  "risk_level": "HIGH",
  "risk_score": 91.4,
  "stage_coverage": ["Entry", "ExecutionStrong", "TargetAccess", "FollowUp"],
  "core_processes": [
    {"process_guid": "P1", "name": "nginx", "labels": ["P_WEB_CTX", "B_EXTERNAL_RECV"]},
    {"process_guid": "P2", "name": "sh", "labels": ["B_SHELL_SPAWN", "B_READ_CRED"]},
    {"process_guid": "P3", "name": "curl", "labels": ["B_EXTERNAL_SEND"]}
  ],
  "bridge_edges": [
    {
      "src": "P2",
      "dst": "P3",
      "object_key": "/tmp/a.sh",
      "object_labels": ["O_FILE_TEMP", "O_FILE_DOWNLOADED"],
      "confidence": 0.93
    }
  ],
  "evidence_timeline": [
    {
      "timestamp": "2026-05-25T10:05:12",
      "event_id": "e001",
      "description": "nginx 接收外部 Web 流量，初始化 P_WEB_CTX",
      "labels_triggered": ["P_WEB_CTX", "B_EXTERNAL_RECV"],
      "raw_log_id": "raw-001"
    }
  ],
  "warnings": [
    "B_SHELL_SPAWN is weak execution evidence; final judgment depends on later strong evidence."
  ]
}
```

### 15.4 LLM 任务

LLM 只负责：

1. 基于路径文档总结攻击行为链
2. 映射 ATT&CK tactics
3. 从检索出的 ATT&CK 候选中选 technique
4. 给出证据解释和不确定性

LLM 不负责：

1. 从十几万原始日志里自己找链
2. 重新做路径搜索
3. 为不存在的阶段补证据

### 15.5 输出

```text
artifacts/module6_reason/
  dossiers/
    task_0001_path_003.json
  reports/
    task_0001_path_003.report.json
  markdown/
    task_0001_path_003.md
  llm_inputs/
    task_0001_path_003.input.json
  summary.json
```

---

## 16. 是否保留当前 `module3_index/module3_bundle/module4_reason`

结论：

1. 第一阶段实现时，不需要把旧链路删掉
2. 但新主线不应再依赖：
   - SQLite evidence index
   - 旧 bundle 结构
   - 旧 full_reason 路由

建议：

```text
旧链路：
  full_reason
新链路：
  full_path_reason
```

对比期结束后，再决定是否彻底废弃旧链路。

---

## 17. 关键规则文件要求

`configs/path_reason_default.yaml` 至少要包括：

1. `paths`
2. `network`
3. `process_names`
4. `object_labels`
5. `process_labels`
6. `propagation_limits`
7. `bridge_whitelist`
8. `bridge_blacklist`
9. `weights`
10. `path_search`

必须支持：

1. dataset-specific override
2. host-specific override
3. business_data_paths override

---

## 18. 实施优先级

### P0：必须先做

1. `module3_evidence_recover`
2. `NormalizedEvent`
3. `ObjectAccessRecord`
4. `semantic_skip.py`
5. `episode_aggregation.py`
6. `process_control_epoch` / `object_semantic_epoch` 双 epoch
7. `P_WEB_CTX/P_REMOTE_CTX/O_FILE_DOWNLOADED/B_SHELL_SPAWN` 修正规则
8. 桥接白名单与时间因果桥接
9. 全链时间单调与生命周期校验

### P1：建议紧接着做

1. APT-Fusion prior 接入
2. ExecutionWeak / ExecutionStrong 分层
3. 弱/强路径分层输出
4. `module6_attack_reason`
5. LLM dossier 格式固定

### P2：后续增强

1. THEIA sibling-task merge
2. CADETS time-sliced task split
3. cross-host path linking
4. campaign clustering

---

## 19. 测试矩阵

至少覆盖以下场景。

### 正例

1. `wget WRITE /tmp/a.sh -> bash EXEC /tmp/a.sh -> bash READ /etc/passwd -> bash SEND external`
   - 应形成 `Entry + ExecutionStrong + TargetAccess + FollowUp`

2. `nginx upload shell.php -> sh -c -> write /etc/crontab`
   - 应形成 `Entry + ExecutionWeak/Strong + FollowUp`

3. `remote sshd -> bash -> python -> archive -> send external`
   - 应形成远程入口路径

### 负例

1. 多进程读取 `/etc/passwd`
   - 不应桥接

2. 多进程连接同一外部 IP
   - 不应桥接

3. 正常 `cron -> sh`
   - 不应直接高危

4. 普通 `user_terminal -> bash -> read ~/.bashrc -> exit`
   - 不应输出高危路径

5. 同一对象先 benign write 后 suspicious write
   - 不得压成同一语义阶段

### 稳定性

1. 空图
2. 空事件
3. 缺字段事件
4. 时间解析失败
5. 未知事件类型
6. sidecar 缺失
7. sidecar id 部分无法对齐

---

## 20. 产物与验收标准

### 20.1 模块级验收

`module3_evidence_recover`

1. 能稳定输出 per-task 标准化事件
2. 能输出 `id_mapping.json`
3. 能输出 prior summary

`module4_semantic_compact`

1. 原始事件显著下降
2. 不会把不同语义阶段压成一个 episode
3. 有压缩统计

`module5_path_finder`

1. 能输出桥接边
2. 能输出强/弱候选路径
3. 不会让 `/etc/passwd` 或同一外部 IP 误桥接

`module6_attack_reason`

1. 输入是路径文档，不是大事件池
2. 能输出 tactic/technique 及证据解释

### 20.2 整体验收

整体必须满足：

1. 与旧 `full_reason` 相比，LLM 输入 token 显著下降
2. 每个 task 的候选路径数量稳定在可控范围内
3. 输出的高危路径大多具备完整时间因果
4. 对路径的解释能回指到原始 `raw_log_id`
5. 负例场景不过度报高危

---

## 21. 最终实施原则

实现时必须始终遵守：

```text
1. 不因单点行为直接判定攻击；
2. 不把高复用对象作为桥接器；
3. 不把解释器出现直接等价为强执行；
4. 不把网络上下文写文件直接等价为下载恶意文件；
5. 不先拉海量事件再粗暴 top-k 截断；
6. 不把旧 bundle 继续当成新主线的核心输入；
7. LLM 只看路径文档，不看大事件池。
```

---

## 22. 给实现 Codex 的直接任务清单

```text
Task 1:
  修改 config.py 和 pipeline.py。
  新增 module3_evidence/module4_compact/module5_paths/module6_reason/full_path_reason。

Task 2:
  新增 path_schemas.py。
  定义 NormalizedEvent/ObjectAccessRecord/ProcessState/ObjectState/EventEpisode/BridgeEdge/CandidatePath。

Task 3:
  从 module3_local_stream.py 中抽取可复用的日志解析和进程 alias 逻辑，
  实现 module3_evidence_recover.py。

Task 4:
  实现 object_classifier.py、semantic_skip.py、episode_aggregation.py，
  完成 module4_semantic_compact.py。

Task 5:
  实现完整标签规则、受控传播、桥接白名单、路径搜索与评分，
  完成 module5_path_finder.py。

Task 6:
  复用 attack_kb.py 和当前 ATT&CK 校验逻辑，
  实现 module6_attack_reason.py。

Task 7:
  新增 configs/path_reason_default.yaml。
  其中必须显式包含 business_data_paths、bridge whitelist、ExecutionWeak/Strong 规则。

Task 8:
  补充正负例测试。
  重点验证 /etc/passwd、同 IP、多 shell、同对象不同语义阶段等场景。
```

这份文档即为后续改项目的唯一主规格书。
