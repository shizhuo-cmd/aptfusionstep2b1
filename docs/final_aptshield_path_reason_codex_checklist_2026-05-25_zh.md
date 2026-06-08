# APT-Fusion Codex 实施 Checklist：检测后语义压缩、候选攻击路径抽取与 LLM ATT&CK 分析

## 0. 使用说明

本文档是配套 [final_aptshield_path_reason_scheme_2026-05-25_zh.md](/D:/daima/APT-Fusion/docs/final_aptshield_path_reason_scheme_2026-05-25_zh.md) 的实施清单。

用途：

1. 给另一个窗口中的 Codex 直接按顺序改项目；
2. 避免实现时遗漏关键接口、关键测试和负例约束；
3. 将“大方案文档”拆成可以连续执行的工程任务。

执行原则：

1. 不要先大面积删除旧链路。
2. 先把新链路接入 pipeline，再逐步替换实现。
3. 每个阶段完成后必须有产物检查和最小测试。
4. 如果某一步需要改数据结构，先改 schema 和 config，再改业务逻辑。

---

## 1. 最终目标

把当前后半段主线从：

```text
module3_index -> module3_bundle -> module4_reason
```

重构为：

```text
module3_evidence
-> module4_compact
-> module5_paths
-> module6_reason
-> full_path_reason
```

要求：

1. `module1/module2` 不动主逻辑；
2. 新链路可独立运行；
3. 旧 `full_reason` 保留用于对照实验；
4. 新链路的 LLM 输入必须是“攻击路径文档”，不是大事件池。

---

## 2. 实施顺序总览

按以下顺序执行，不要乱序：

```text
Phase 0  基线确认与接口位点
Phase 1  config.py / pipeline.py 接口接入
Phase 2  新 schema 与规则装载
Phase 3  module3_evidence_recover
Phase 4  object classifier / prelabel / semantic skip / episode aggregation
Phase 5  module5_path_finder：标签传播、桥接、路径搜索、评分
Phase 6  module6_attack_reason：路径文档 -> ATT&CK 分析
Phase 7  测试、回归、对照运行
```

---

## 3. Phase 0：基线确认

### 3.1 先阅读

必须先读：

1. `docs/final_aptshield_path_reason_scheme_2026-05-25_zh.md`
2. `src/apt_fusion/pipeline.py`
3. `src/apt_fusion/config.py`
4. `src/apt_fusion/module3_local_stream.py`
5. `src/apt_fusion/module3_index.py`
6. `src/apt_fusion/module3_bundle.py`
7. `src/apt_fusion/module4_reason.py`

### 3.2 明确保留与替换

保留：

1. `module1`
2. `module2`
3. `attack_kb.py`
4. 旧 `module4_reason` 中 ATT&CK 校验逻辑里可复用的部分

替换主线：

1. `module3_index`
2. `module3_bundle`
3. `module4_reason`

注意：

1. 不是立刻删除这三个文件；
2. 是新增新主线，先并行存在。

### 3.3 基线运行

在动代码前，确保可以跑通当前：

```text
full_reason
```

保留一份 baseline summary，用于后面对照：

1. 每个 task 的 matched event count
2. 每个 bundle 的 event_count
3. 每个 report 的 evidence_support_rate

---

## 4. Phase 1：接入新 stage 和配置目录

### 4.1 修改 `src/apt_fusion/config.py`

新增字段：

1. `path_reason_enabled`
2. `evidence_recover_include_object_side`
3. `evidence_recover_max_events_per_task`
4. `evidence_recover_task_time_padding_minutes`
5. `evidence_recover_anchor_top_k`
6. `semantic_skip_enabled`
7. `semantic_skip_ttl_seconds`
8. `semantic_skip_max_table_size`
9. `episode_max_representative_events`
10. `episode_time_bucket_minutes`
11. `path_bridge_max_time_gap_minutes`
12. `path_max_depth`
13. `path_max_total_span_minutes`
14. `path_hot_process_threshold`
15. `path_top_k`
16. `reason_top_paths_per_task`
17. `reason_max_timeline_items_per_path`
18. `reason_max_bridge_edges_per_path`
19. `reason_max_objects_per_path`
20. `path_reason_rules_path`

新增目录 property：

1. `module3_evidence_dir`
2. `module4_compact_dir`
3. `module5_paths_dir`
4. `module6_reason_dir`
5. `module7_campaign_dir`

### 4.2 修改 `load_config`

要求：

1. 所有新字段都有默认值；
2. `path_reason_rules_path` 为空时默认指向 `configs/path_reason_default.yaml`；
3. `_validate()` 中补充新字段约束。

### 4.3 修改 `src/apt_fusion/pipeline.py`

新增 stage：

1. `module3_evidence`
2. `module4_compact`
3. `module5_paths`
4. `module6_reason`
5. `full_path_reason`

新增 import：

1. `run_module3_evidence`
2. `run_module4_compact`
3. `run_module5_paths`
4. `run_module6_reason`

### 4.4 本阶段验收

通过条件：

1. `load_config()` 不报错；
2. 新 stage 可以通过参数校验；
3. 不影响旧 `full_reason`。

---

## 5. Phase 2：先建通用 schema 和规则装载

### 5.1 新建 `src/apt_fusion/path_schemas.py`

必须定义：

1. `NormalizedEvent`
2. `ObjectAccessRecord`
3. `ProcessState`
4. `ObjectState`
5. `EventEpisode`
6. `BridgeEdge`
7. `CandidatePath`
8. 需要的话再加 `TaskPrior`

### 5.2 新建 `src/apt_fusion/path_rules.py`

职责：

1. 读取 `path_reason_default.yaml`
2. 暴露规则查询接口
3. 校验标签注册表是否完整

至少提供函数：

1. `load_path_rules(cfg)`
2. `get_label_meta(name)`
3. `is_bridge_allowed_label(name)`
4. `match_object_class(...)`
5. `label_has_init_rules(name)`

### 5.3 标签注册表校验

实现一个显式校验：

1. 所有被代码引用的标签必须在 YAML 中定义；
2. 每个标签必须有：
   - `category`
   - `stage_mapping`
   - `score`
   - `bridge_allowed`
3. context/behavior/object 标签必须有 `init_rules` 或明确说明只由传播产生。

### 5.4 本阶段验收

通过条件：

1. schema 文件可 import；
2. YAML 可正常加载；
3. 标签完整性校验可运行。

---

## 6. Phase 3：实现 `module3_evidence_recover`

### 6.1 新建 `src/apt_fusion/module3_evidence_recover.py`

职责：

1. 读取 `module1/module2` 输出；
2. 合并 sidecar prior；
3. 从原始日志回拉 per-task 事件；
4. 做 ID 对齐；
5. 输出标准化事件流。

### 6.2 可复用逻辑

优先复用：

1. `module3_local_stream.py` 中的事件抽取逻辑；
2. alias 归一化逻辑；
3. 任务选择逻辑；
4. 时间范围维护逻辑。

### 6.3 关键输出

必须写出：

```text
artifacts/module3_evidence/
  task_index.json
  id_mapping.json
  priors_by_task.json
  normalized_events/
  summary.json
```

### 6.4 强制要求

1. `id_mapping.json` 必须生成；
2. 如果 `task_attribution.process_id` 无法映射到事件流 `process_guid`，必须计数；
3. 标准化事件必须有 `order_index`；
4. `syscall_direction` 和 `semantic_flow_direction` 必须都填；
5. 不要先做 semantic skip。

### 6.5 本阶段测试

至少加：

1. `test_evidence_normalizer.py`
2. `test_id_mapping_generation.py`

### 6.6 本阶段验收

通过条件：

1. 单 task 能输出 `normalized_events/*.jsonl`
2. 事件顺序稳定
3. sidecar prior 能并入
4. summary 中有 unmapped 统计

---

## 7. Phase 4：实现语义压缩链

本阶段建议拆成 4 个文件：

1. `object_classifier.py`
2. `semantic_skip.py`
3. `episode_aggregation.py`
4. `module4_semantic_compact.py`

### 7.1 `object_classifier.py`

要求：

1. 只负责对象分类，不负责路径风险判断；
2. 支持 path prefix、suffix、glob、ip:port；
3. 支持：
   - `temp_file`
   - `credential_file`
   - `history_file`
   - `business_file`
   - `persistence_file`
   - `privilege_file`
   - `auth_config_file`
   - `archive_file`
   - `external_ip`
   - `internal_ip`
   - `local_ipc`
   - `system_library`
   - `system_resource`

### 7.2 `module4_semantic_compact.py` 处理顺序

顺序必须固定：

```text
normalized events
-> object classify
-> prelabel init
-> semantic skip
-> episode aggregation
-> compacted state export
```

### 7.3 预标签只做轻量标签

本阶段只允许打：

1. `P_WEB_CTX`
2. `P_REMOTE_CTX`
3. `P_NET_CTX`
4. `P_UNTRUSTED_CTX`
5. `O_NET_EXTERNAL`
6. `O_FILE_TEMP`
7. `O_FILE_UPLOADED`
8. `O_FILE_DOWNLOADED`
9. `O_FILE_NONEXIST`
10. `O_PERSISTENCE`
11. `O_PRIV_CONFIG`
12. `O_CREDENTIAL`
13. `O_HISTORY`
14. `O_BUSINESS_DATA`

### 7.4 `semantic_skip.py`

必须实现：

1. `LatestSemanticEntry`
2. `LatestSemanticTable`
3. `should_skip_semantically(...)`
4. object invalidation
5. process control invalidation

必须区分：

1. `object.semantic_epoch`
2. `process.process_control_epoch`

不要把 `EXEC` 记成对象 epoch 变化。

### 7.5 `episode_aggregation.py`

必须用以下字段参与 key：

1. `process_guid`
2. `event_type`
3. `object_type`
4. `object_class`
5. `object_key`
6. `semantic_flow_direction`
7. `process_label_signature`
8. `object_label_signature`
9. `object_semantic_epoch`
10. `process_control_epoch`

### 7.6 本阶段测试

至少加：

1. `test_object_classifier.py`
2. `test_semantic_skip.py`
3. `test_episode_aggregation.py`

重点测试：

1. 1000 条重复系统库读可以压缩
2. 同一对象先 benign write 后 suspicious write 不可压成同一阶段
3. `EXEC` 不改变对象 epoch，但改变进程 control epoch

### 7.7 本阶段验收

通过条件：

1. `raw_event_count`
2. `after_semantic_skip`
3. `after_episode_aggregation`

三者可正确统计并输出到 summary。

---

## 8. Phase 5：实现 `module5_path_finder`

建议拆成：

1. `path_labeler.py`
2. `path_propagator.py`
3. `bridge_builder.py`
4. `path_search.py`
5. `path_scoring.py`
6. `path_report.py`
7. `module5_path_finder.py`

### 8.1 `path_labeler.py`

在这一阶段完成完整行为标签初始化。

第一版重点：

1. `B_EXTERNAL_RECV`
2. `B_EXTERNAL_SEND`
3. `B_EXEC_TEMP`
4. `B_EXEC_DOWNLOADED`
5. `B_EXEC_UPLOADED`
6. `B_EXEC_SUSPECT_WRITTEN`
7. `B_SHELL_SPAWN`
8. `B_SCRIPT_EXEC`
9. `B_INTERPRETER_LAUNCH`
10. `B_READ_CRED`
11. `B_READ_HISTORY`
12. `B_READ_BUSINESS`
13. `B_MASS_FILE_ACCESS`
14. `B_WRITE_PERSISTENCE`
15. `B_WRITE_PRIV_CONFIG`
16. `B_ARCHIVE_DATA`
17. `B_DELETE_LOG`
18. `B_LATERAL_CONNECT`

### 8.2 `path_propagator.py`

只传播状态标签：

1. `P_WEB_CTX`
2. `P_REMOTE_CTX`
3. `P_NET_CTX`
4. `P_UNTRUSTED_CTX`
5. `P_HIGH_VALUE_CTX`
6. `P_SUSPECT_CTRL_CTX`

传播必须受限：

1. 深度限制
2. 时间窗口限制
3. daemon 限制
4. 子进程类型限制

### 8.3 `bridge_builder.py`

只允许桥接白名单对象。

桥接必须基于：

1. `ObjectAccessRecord`
2. `write/create/rename -> read/exec/mmap/load`
3. `order_index`
4. 生命周期合法
5. semantic epoch 合法

禁止桥接：

1. `/etc/passwd`
2. `.bash_history`
3. 外部 IP
4. 公共配置文件
5. 高复用业务文件

### 8.4 `path_search.py`

必须同时满足：

1. 全链时间单调
2. 进程生命周期合法
3. 桥接时间因果合法
4. 阶段覆盖合法

必须支持：

1. 强候选路径
2. 弱候选路径
3. 先强后弱排序

### 8.5 `path_scoring.py`

必须把 `APT-Fusion prior` 接进来：

1. `task_score`
2. `top_processes`
3. `top_edges`
4. `task_time_range`

### 8.6 本阶段测试

至少加：

1. `test_path_labeling.py`
2. `test_bridge_builder.py`
3. `test_path_search.py`

重点负例：

1. 多进程读 `/etc/passwd` 不桥接
2. 多进程连同一外部 IP 不桥接
3. `cron -> sh` 不自动高危
4. `user_terminal -> bash -> read ~/.bashrc -> exit` 不高危

重点正例：

1. 下载后执行形成 `ExecutionStrong`
2. Web 上下文 + 上传/执行 + 敏感访问 + 外传形成高危路径

### 8.7 本阶段验收

通过条件：

1. 每个 task 能输出 Top-K 路径
2. 高危路径数量可控
3. 负例不误桥接
4. 强候选排在弱候选前

---

## 9. Phase 6：实现 `module6_attack_reason`

### 9.1 可复用能力

优先复用：

1. `attack_kb.py`
2. 当前 ATT&CK tactic/technique 兼容性校验
3. 当前 `llm_inputs/` 导出模式

### 9.2 新输入格式

输入必须来自 `CandidatePath dossier`，不是旧 bundle。

### 9.3 `module6_attack_reason.py`

职责：

1. 读取每个 task 的 Top-N 路径
2. 为每条路径构造 dossier
3. 调 ATT&CK 检索
4. 调 LLM 生成 tactic/technique 报告
5. 输出 JSON + Markdown + llm_inputs

### 9.4 本阶段测试

至少加：

1. `test_attack_reason_context.py`

检查：

1. prompt context 不包含大事件池
2. 每条路径 dossier 字段完整
3. ATT&CK 候选为空时也能优雅退化

### 9.5 本阶段验收

通过条件：

1. `module6_reason` 能独立跑通
2. 每条路径有独立 dossier
3. `llm_inputs/` 可回看模型实际输入

---

## 10. Phase 7：对照实验与回归

### 10.1 对照维度

同时跑：

1. `full_reason`
2. `full_path_reason`

对比：

1. 每 task 原始 matched events
2. LLM 输入 token 规模
3. 候选路径数量
4. ATT&CK tactic/technique 覆盖
5. 误报样例

### 10.2 summary 输出建议

新增一个对照 summary：

```text
artifacts/full_path_reason_comparison/
  comparison_summary.json
```

至少包含：

1. `raw_event_count`
2. `after_semantic_skip`
3. `after_episode_aggregation`
4. `candidate_path_count`
5. `reason_report_count`
6. `avg_llm_input_items_per_path`

---

## 11. 必须创建或修改的文件清单

### 新建

1. `src/apt_fusion/module3_evidence_recover.py`
2. `src/apt_fusion/module4_semantic_compact.py`
3. `src/apt_fusion/module5_path_finder.py`
4. `src/apt_fusion/module6_attack_reason.py`
5. `src/apt_fusion/path_schemas.py`
6. `src/apt_fusion/path_rules.py`
7. `src/apt_fusion/evidence_normalizer.py`
8. `src/apt_fusion/object_classifier.py`
9. `src/apt_fusion/semantic_skip.py`
10. `src/apt_fusion/episode_aggregation.py`
11. `src/apt_fusion/path_labeler.py`
12. `src/apt_fusion/path_propagator.py`
13. `src/apt_fusion/bridge_builder.py`
14. `src/apt_fusion/path_search.py`
15. `src/apt_fusion/path_scoring.py`
16. `src/apt_fusion/path_report.py`
17. `configs/path_reason_default.yaml`

### 修改

1. `src/apt_fusion/config.py`
2. `src/apt_fusion/pipeline.py`

### 测试

1. `tests/test_evidence_normalizer.py`
2. `tests/test_object_classifier.py`
3. `tests/test_semantic_skip.py`
4. `tests/test_episode_aggregation.py`
5. `tests/test_path_labeling.py`
6. `tests/test_bridge_builder.py`
7. `tests/test_path_search.py`
8. `tests/test_attack_reason_context.py`

---

## 12. 每个阶段结束后的最低检查

### Phase 1 结束

检查：

1. `python -m apt_fusion.cli ... --stage full_reason` 仍可跑
2. 新 stage 已注册

### Phase 3 结束

检查：

1. `module3_evidence/normalized_events/*.jsonl`
2. `module3_evidence/id_mapping.json`
3. `module3_evidence/summary.json`

### Phase 4 结束

检查：

1. `module4_compact/access_records/*.jsonl`
2. `module4_compact/episodes/*.json`
3. `module4_compact/compact_summary.json`

### Phase 5 结束

检查：

1. `module5_paths/bridge_edges/*.json`
2. `module5_paths/candidate_paths/*.json`
3. `module5_paths/candidate_paths/*.md`

### Phase 6 结束

检查：

1. `module6_reason/dossiers/*.json`
2. `module6_reason/reports/*.json`
3. `module6_reason/llm_inputs/*.json`

---

## 13. 禁止事项

实现时禁止：

1. 继续把旧 `bundle` 当作新主线输入
2. 只按静态 key 聚合就叫 semantic skip
3. 把 `EXEC` 直接记成对象 epoch 变化
4. 把 shell/interpreter 出现直接当成强执行
5. 把 `/etc/passwd`、同一外部 IP 当桥接器
6. 先拉十几万事件再简单 top-k 截断交给 LLM
7. 在没有 `id_mapping` 的情况下假定 sidecar ID 天然对齐

---

## 14. 最终 Done 定义

只有满足以下全部条件，才算这次改造完成：

1. 新 stage `full_path_reason` 可以端到端运行；
2. 旧 `full_reason` 仍能保留用于对照；
3. 每个 task 能生成候选攻击路径；
4. LLM 输入变成路径 dossier；
5. 负例场景不产生高危桥接链；
6. 所有路径都能回指 `raw_log_id`；
7. 基础测试通过；
8. 输出 summary 能量化压缩率与路径数。

这份 checklist 应和最终方案文档一起使用，但实现时以本文档的阶段顺序为准。
