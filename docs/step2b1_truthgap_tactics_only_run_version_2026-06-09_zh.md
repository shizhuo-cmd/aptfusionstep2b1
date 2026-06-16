# `APT-Fusionstep2b1` 上次 `deterministic_tactics_only / llm_tactics_only` 实验版代码详解

## 0. 先给结论

上次跑的两条线：

- `deterministic_tactics_only`
- `llm_tactics_only`

都不是某个已经提交到 git 历史里的独立 commit，而是下面这个基线之上的一批**工作区未提交改动**共同组成的实验版：

- git 基线提交：`3c0e4b1 archive: initialize step2b1 source baseline`
- 实验标签：`truthgap + tactics_only + claim_attack_prior_mode=disabled`
- 时间锚点：`2026-06-08`

这版代码的本质不是“完全换一条新主线”，而是：

1. 继续复用 `microstep2b` 的 `CandidatePath` 主线。
2. 在 `module5` 上做 `truth-gap` 驱动的链条补强。
3. 在 `module6` 上把 ATT&CK 映射改成 `tactics_only`，并且关闭 `claim_attack_hints / behavior prior`。
4. 最终对比两条映射线：
   - 一条不用第二次 ATT&CK mapping LLM，直接按 Holmes 风格原子映射战术。
   - 一条保留第二次 ATT&CK mapping LLM，但只输出战术，不输出技术。

这份文档讲的就是**那次实际跑到云端的实验版代码**，不是更早的原始 `microstep2b`，也不是后来的别的实验分支。

## 1. 版本边界

### 1.1 这次实验对应的配置和 runner

实验配置：

- `configs/fusion_cloud_trace_train_stats_latefusion_bonus1_llama31_microstep2b_truthgap_tactics_only_deterministic_gtonly_20260608.yaml`
- `configs/fusion_cloud_trace_train_stats_latefusion_bonus1_llama31_microstep2b_truthgap_tactics_only_llm_gtonly_20260608.yaml`

实验 runner：

- `debug/remote_ops/trace_microstep2b_truthgap_tactics_only_deterministic_gtonly_20260608_runner.py`
- `debug/remote_ops/trace_microstep2b_truthgap_tactics_only_llm_gtonly_20260608_runner.py`
- `debug/remote_ops/trace_microstep2b_truthgap_tactics_only_compare_gtonly_20260608_runner.py`

对比总控逻辑非常明确：

1. 先跑 `deterministic`。
2. 再跑 `llm`。
3. 读取两边 `metrics_summary.json`。
4. 优先比较是否满足门槛：
   - `confirmed_window_recall >= 0.5`
   - `strict_tactic_recall_macro >= 0.25`
   - `off_window_high_risk_rate <= 0.125`
5. 如果两边都达标，优先选 `deterministic_tactics_only`。
6. 如果都不达标，就比较：
   - `strict_tactic_recall_macro`
   - `off_window_high_risk_rate`

也就是说，**两条线的区别只在 `module6` 的“战术映射方式”**，不是整条上游链都重跑一遍。

### 1.2 这次实验对应的工作区改动文件

这次实验版实际由下面这些文件共同组成。

已修改的 tracked 文件：

- `src/apt_fusion/config.py`
- `src/apt_fusion/evaluation/path_reason_eval.py`
- `src/apt_fusion/path_reason/module5_path_finder.py`
- `src/apt_fusion/path_reason/module6_attack_reason.py`
- `src/apt_fusion/path_reason/path_report.py`
- `src/apt_fusion/path_reason/path_schemas.py`
- `src/apt_fusion/path_reason/path_search.py`
- `tests/test_attack_reason_context.py`
- `tests/test_path_reason_eval.py`

新增但未提交的文件：

- `configs/fusion_cloud_trace_train_stats_latefusion_bonus1_llama31_microstep2b_truthgap_tactics_only_deterministic_gtonly_20260608.yaml`
- `configs/fusion_cloud_trace_train_stats_latefusion_bonus1_llama31_microstep2b_truthgap_tactics_only_llm_gtonly_20260608.yaml`
- `debug/remote_ops/analyze_trace_truth_gap_20260608.py`
- `debug/remote_ops/trace_microstep2b_truthgap_tactics_only_compare_gtonly_20260608_launch.sh`
- `debug/remote_ops/trace_microstep2b_truthgap_tactics_only_compare_gtonly_20260608_runner.py`
- `debug/remote_ops/trace_microstep2b_truthgap_tactics_only_deterministic_gtonly_20260608_runner.py`
- `debug/remote_ops/trace_microstep2b_truthgap_tactics_only_llm_gtonly_20260608_runner.py`
- `docs/step2b1_attack_analysis_full_explained_2026-06-09_zh.md`
- `docs/step2b1_attack_recognition_client_briefing_2026-06-09_zh.md`
- `tests/test_module5_family_preservation.py`

因此，最准确的叫法是：

`step2b1 基线存档版 + 2026-06-08 truthgap/tactics-only 工作区实验补丁`

### 1.3 这次实验和原始 `microstep2b` 的关系

这版不是彻底推翻旧方案，而是：

- 继续使用 `module5 -> CandidatePath -> module6`
- 没有切成 `causal_subgraph-first`
- 没有切成 APTShield strict reproduction
- 没有取消 `CandidatePath`

所以它仍然是**路径优先**，只是做了三件关键补丁：

1. 不让某些真实恶意 family 在 top-k 修剪时被挤掉。
2. 用 Holmes 风格原子把 claims 约束得更“窄”。
3. 把 ATT&CK 输出缩到 `tactics_only`，降低 technique 级别误判。

## 2. 上次实验真实跑了什么

### 2.1 `deterministic_tactics_only` 的执行顺序

这条线不是从原始日志全链重跑，而是：

1. 读取旧 GT-only 基线产物目录，复用：
   - `module1`
   - `module2`
   - `module3_evidence`
   - `module4_compact`
2. 在新的 artifacts 根目录下跑一次新的 `module5_paths`
3. 在相同 artifacts 下跑新的 `module6_reason`
4. 跑新的 `path_reason_eval`
5. 额外跑一次 `truth_gap_analysis`

也就是说：

- `module1-4` 是复用旧上游产物
- `module5` 是这次实验真正新算的
- `module6` 是这次实验真正新算的
- evaluator 也是这次实验的新版本

### 2.2 `llm_tactics_only` 的执行顺序

这条线更“窄”：

1. 直接复用 `deterministic` 产物里的 `module5_paths`
2. 只重新跑 `module6_reason`
3. 只重新跑 `path_reason_eval`
4. 也补一份 `truth_gap_analysis`

所以：

- `deterministic` 和 `llm` 看到的是**同一份 CandidatePath**
- 两边差异只来自 `module6` 的“战术映射方法”

这是理解结果差异时最重要的一点。

### 2.3 离线对照脚本参与了什么

`analyze_trace_truth_gap_20260608.py` 是**离线对照分析脚本**，不是在线检测逻辑的一部分。

它的作用是：

1. 只读 GT、攻击报告、原始日志和实验产物。
2. 重点分析 `0345 / 0546 / 0557 / 0558` 四张 GT-hit 任务图。
3. 导出：
   - `raw_log_chain_truth.json`
   - `task_truth_gap_summary.json`
   - `per_task_truth_gap.md`

它解决的问题是：

- 当前链条为什么漏掉真实恶意前因。
- 哪些 family 在旧版里保住了、在当前版里丢了。

它**不直接改变预测结果**，但驱动了后面 `module5` 的 family 保留和 precursor rescue 设计。

## 3. 这次实验的关键配置值

### 3.1 和任务图、上游复用有关的配置

两条线共有的关键配置：

- `module3_task_selection_mode = ground_truth_positive_base_only`
- `task_component_split_mode = fanout`
- `task_component_child_threshold = 2`
- `evidence_recover_max_events_per_task = 300000`
- `evidence_recover_include_object_side = true`

含义：

- 只挑 GT-positive base task。
- 任务图分裂规则是“子进程数大于阈值就 fanout 分裂”。
- 证据恢复仍然是任务图本地证据恢复，不是全局原始日志推全图。

### 3.2 和 CandidatePath 数量有关的配置

- `path_top_k = 20`
- `reason_top_paths_per_task = 5`

含义：

1. `module5` 最终每个任务最多保留 20 条候选链。
2. `module6` 真正送去推理的只有每个任务前 5 条。

这意味着：

- 某条链就算在 `module5` 里存在，只要没进每任务前 5，也不会进入 `module6`。

### 3.3 和战术-only 有关的配置

`deterministic` 配置：

- `claim_attack_prior_mode = disabled`
- `attack_mapping_scope = tactics_only`
- `tactic_mapping_mode = deterministic`

`llm` 配置：

- `claim_attack_prior_mode = disabled`
- `attack_mapping_scope = tactics_only`
- `tactic_mapping_mode = llm`

### 3.4 和 ATT&CK 检索有关的配置

- `attack_kb_candidate_limit = 12`
- `attack_kb_sparse_top_k = 24`
- `attack_kb_vector_top_k = 24`
- `attack_kb_sparse_weight = 0.45`
- `attack_kb_vector_weight = 0.55`
- `attack_kb_enable_vector = false`

这里有两个很关键的细节：

1. `attack_kb_enable_vector = false`
   - 所以这次实验**没有启用向量检索**
   - 实际只有 TF-IDF 稀疏检索 + 兼容性 bonus 在起作用

2. `attack_kb_claim_weight = 0.25`
   - 这个字段在这版代码里**并没有真正被使用**
   - 它只是配置里保留了，但检索打分函数没有消费它

### 3.5 这次 YAML 里有哪些“写了但那次没真正生效”的项

这一步非常重要，因为如果不把“死配置”和“活配置”分开，后面会很容易把实验结果归因错。

#### 3.5.1 因为复用上游 artifacts 而未生效的配置

上次两条 `tactics_only` 线都没有重跑 `module1 / module2 / module3 / module4` 的核心计算，所以这些配置虽然写在 YAML 里，但**不是那次结果的直接来源**：

- `task_graph_stat_late_fusion_enabled`
- `task_graph_stat_fusion_weight`
- `task_detector_model_input / output`
- `task_classifier_*`
- `task_decision_threshold`
- `task_tapas_*`
- `number_of_hops`
- `max_edges`
- `top_k`
- `abnormality_level`

更准确地说：

- 它们会影响“被复用的旧基线产物是怎么生成的”
- 但不会影响“上次 tactics-only 实验中新跑出来的 module5/module6/eval”

#### 3.5.2 因为只在 truth-gap 分析里使用而不是在线检测里使用的配置

- `source_logs`

在这次实验里，`source_logs` 主要用于：

- `truth_gap_analysis`

而不是用于重新构建在线检测的 `module3/module4` 主产物。

#### 3.5.3 在代码里保留但没有被这次路径真正消费的项

除了前面提到的 `attack_kb_claim_weight`，这版还有一些“YAML 里存在，但代码里这次没读到”的规则项。

例如 `path_reason_default.yaml` 里的：

- `scoring.combos.downloaded_write_then_exec`
- `scoring.penalties.common_daemon_normal_child`
- `scoring.penalties.whitelist_process`
- `scoring.penalties.time_gap_too_large`
- `scoring.penalties.low_value_object`

这些规则名存在，但这次实验版 `path_scoring.py` 实际并没有消费它们。

因此，如果后面要分析某次结果为什么高或低，不能把这些“未生效规则”拿来解释。

## 4. 这版 `module5` 实际怎么构造候选链

这一部分是这次实验版最重要的地方，因为它决定了模型到底能不能看到“恶意前因链”。

### 4.1 `module5` 仍然是 `CandidatePath` 主线

入口函数是：

- `src/apt_fusion/path_reason/module5_path_finder.py`

真实顺序是：

1. 读取 `module4_compact` 输出。
2. 加载 `process_states / object_states / object_versions / retained_events / label_provenance`。
3. 给事件补 `path_labels_triggered`。
4. 传播 status labels。
5. 构造 bridge edges。
6. 搜索 CandidatePath。
7. 给 CandidatePath 打分。
8. 补 support 信息。
9. 打 `family_tags`。
10. 必要时做 `precursor_rescue`。
11. 做 `family-preserved` top-k 保留。
12. 再用 provenance/support 质量做二次调分。
13. 输出 json 和 markdown dossier。

### 4.2 这次仍然复用了旧的 label 体系

这版**没有推翻 `path_reason_default.yaml` 的 label 体系**。它沿用的仍然是旧 step2b1 的：

- context labels
- behavior labels
- object labels
- aggregate labels

最核心的 stage 映射仍然是五段：

- `Entry`
- `ExecutionWeak`
- `ExecutionStrong`
- `TargetAccess`
- `FollowUp`

也就是说，这版不是 APTShield 标签体系，也不是 Holmes 原生标签体系，而是：

`旧 step2b1 标签体系 + 新增 family / Holmes atom 辅助层`

### 4.3 这版实际依赖的旧 label 规则

本次实验最常用、最关键的 label 及其含义如下。

#### 4.3.1 进程上下文类标签

`P_WEB_CTX`

- stage: `Entry`
- 触发语义：
  - Web 服务进程名
  - 监听/接收 web 端口
  - 访问 web root
  - 写 upload 路径

`P_REMOTE_CTX`

- stage: `Entry`
- 触发语义：
  - 远程登录服务进程
  - 远程管理端口的入站连接
  - 远程服务父进程下的 `pts/*`

`P_NET_CTX`

- stage: `Entry`
- 触发语义：
  - 外部网络接触

`P_UNTRUSTED_CTX`

- stage: `Entry`
- 触发语义：
  - 外部数据接收进入进程
  - 执行 uploaded/downloaded 对象

`P_HIGH_VALUE_CTX`

- stage: `TargetAccess`
- 触发语义：
  - 读取凭据
  - 读取历史
  - 读取业务数据

`P_SUSPECT_CTRL_CTX`

- stage: `ExecutionWeak`
- 触发语义：
  - 下载后执行

#### 4.3.2 行为类标签

`B_EXTERNAL_RECV`

- stage: `Entry`
- 规则名：`recv_external_ip`
- 含义：从外部 IP 接收数据

`B_EXTERNAL_SEND`

- stage: `FollowUp`
- 规则名：`send_external_ip`
- 含义：向外部 IP 发送数据

`B_EXEC_TEMP`

- stage: `ExecutionStrong`
- 规则名：`exec_temp_file`
- 含义：执行临时目录对象

`B_EXEC_DOWNLOADED`

- stage: `ExecutionStrong`
- 规则名：`exec_downloaded_file`
- 含义：执行下载文件

`B_EXEC_UPLOADED`

- stage: `ExecutionStrong`
- 规则名：`exec_uploaded_file`
- 含义：执行上传文件

`B_EXEC_SUSPECT_WRITTEN`

- stage: `ExecutionStrong`
- 规则名：`exec_suspect_written`
- 含义：执行可疑写入对象

`B_SHELL_SPAWN`

- stage: `ExecutionWeak`
- 规则名：`suspicious_shell_child`
- 含义：可疑 shell 子进程

`B_SCRIPT_EXEC`

- stage: `ExecutionWeak`
- 规则名：`suspicious_interpreter`
- 含义：解释器执行

`B_INTERPRETER_LAUNCH`

- stage: `ExecutionWeak`
- 规则名：`interpreter_seen`
- 含义：看到了 shell/interpreter 启动

`B_READ_CRED`

- stage: `TargetAccess`
- 规则名：`read_credential_file`

`B_READ_HISTORY`

- stage: `TargetAccess`
- 规则名：`read_history_file`

`B_READ_BUSINESS`

- stage: `TargetAccess`
- 规则名：`read_business_file`

`B_MASS_FILE_ACCESS`

- stage: `TargetAccess`
- 规则名：`mass_file_access_window`

`B_WRITE_PERSISTENCE`

- stage: `FollowUp`
- 规则名：`write_persistence_file`

`B_WRITE_PRIV_CONFIG`

- stage: `TargetAccess`
- 规则名：`modify_privilege_file`

`B_ARCHIVE_DATA`

- stage: `FollowUp`
- 规则名：`archive_tool_or_file`

`B_DELETE_LOG`

- stage: `FollowUp`
- 规则名：`modify_log_file`

`B_LATERAL_CONNECT`

- stage: `FollowUp`
- 规则名：`connect_internal_lateral_port`

#### 4.3.3 对象类标签

`O_FILE_TEMP`

- stage: `ExecutionWeak`
- 规则名：`path_in_temp_dir`

`O_FILE_UPLOADED`

- stage: `Entry`
- 规则名：`write_to_upload_path`

`O_FILE_DOWNLOADED`

- stage: `Entry`
- 规则名：
  - `downloader_process_writes_file`
  - `cmdline_url_write`
  - `external_recv_then_temp_write`

`O_SUSPECT_WRITTEN_EXECUTABLE`

- stage: `ExecutionStrong`
- 规则名：`written_then_exec_or_load`

`O_CREDENTIAL`

- stage: `TargetAccess`
- 规则名：`credential_path_match`

`O_HISTORY`

- stage: `TargetAccess`
- 规则名：`history_path_match`

`O_BUSINESS_DATA`

- stage: `TargetAccess`
- 规则名：`business_path_match`

`O_PERSISTENCE`

- stage: `FollowUp`
- 规则名：`persistence_path_match`

`O_PRIV_CONFIG`

- stage: `TargetAccess`
- 规则名：`privilege_path_match`

`O_ARCHIVE`

- stage: `FollowUp`
- 规则名：`archive_path_match`

`O_SECURITY_LOG`

- stage: `FollowUp`
- 规则名：`log_path_match`

### 4.4 旧链搜索规则没有被废掉

这版仍然使用 `search_candidate_paths()`，因此真正的候选链搜索逻辑仍然是：

1. 从 seed 进程出发。
2. 在两种边上做 DFS：
   - 父子进程边
   - bridge object 边
3. 受以下约束：
   - `max_depth = 6`
   - `max_total_span_minutes = 180`
   - `max_time_gap_minutes = 120`
4. 中途每形成一条链，检查它是否满足 stage 组合规则。

#### 4.4.1 seed 规则

seed 进程判定：

- 只要进程有 `behavior_labels`
- 或者 status labels 中含有：
  - `P_WEB_CTX`
  - `P_REMOTE_CTX`
  - `P_UNTRUSTED_CTX`
  - `P_SUSPECT_CTRL_CTX`

就会作为搜索起点。

#### 4.4.2 旧 stage 组合准入规则

`strong_stage_sets`

- `["Entry", "ExecutionStrong", "TargetAccess"]`
- `["Entry", "ExecutionStrong", "FollowUp"]`
- `["ExecutionStrong", "TargetAccess", "FollowUp"]`

`weak_stage_sets`

- `["Entry", "ExecutionWeak"]`
- `["Entry", "TargetAccess"]`
- `["ExecutionWeak", "FollowUp"]`

`medium_upgrade_rules`

- `["Entry", "ExecutionWeak", "TargetAccess"]`
- `["Entry", "ExecutionWeak", "FollowUp"]`

解释：

- 没有达到这些 stage 组合的链，不会被认为是 CandidatePath。
- 所以这版并没有“所有有点可疑的局部子图都保留”，它还是有明显的旧式阶段门槛。

### 4.5 旧打分逻辑仍然在起作用

`score_candidate_paths()` 的总分构成是：

`label_score + combo_score + stage_score + bridge_score + prior_score - penalties`

#### 4.5.1 label 分数

每个 label 有固定分值，例如：

- `P_UNTRUSTED_CTX = 5`
- `P_SUSPECT_CTRL_CTX = 8`
- `B_EXTERNAL_RECV = 8`
- `B_EXTERNAL_SEND = 20`
- `B_EXEC_TEMP = 20`
- `B_EXEC_DOWNLOADED = 30`
- `B_EXEC_SUSPECT_WRITTEN = 28`
- `B_READ_CRED = 15`
- `B_READ_BUSINESS = 18`
- `B_WRITE_PERSISTENCE = 30`
- `B_DELETE_LOG = 25`
- `B_LATERAL_CONNECT = 20`

#### 4.5.2 combo 组合加分

这版实际启用的组合规则是：

- `external_plus_temp_exec`
  - `B_EXTERNAL_RECV + B_EXEC_TEMP`
  - 或 `B_EXTERNAL_RECV + B_EXEC_DOWNLOADED`

- `external_plus_shell`
  - `B_EXTERNAL_RECV + B_SHELL_SPAWN`

- `suspicious_exec_plus_sensitive_read`
  - `B_EXEC_DOWNLOADED + B_READ_CRED`
  - 或 `B_EXEC_SUSPECT_WRITTEN + B_READ_CRED`

- `sensitive_read_plus_external_send`
  - `B_READ_CRED + B_EXTERNAL_SEND`
  - 或 `B_READ_BUSINESS + B_EXTERNAL_SEND`

- `suspicious_exec_plus_persistence`
  - `B_EXEC_DOWNLOADED + B_WRITE_PERSISTENCE`
  - 或 `B_EXEC_SUSPECT_WRITTEN + B_WRITE_PERSISTENCE`

- `suspicious_exec_plus_lateral`
  - `B_EXEC_DOWNLOADED + B_LATERAL_CONNECT`
  - 或 `B_EXEC_SUSPECT_WRITTEN + B_LATERAL_CONNECT`

- `continuous_labeled_chain`
  - `process_chain` 长度至少 3
  - `stage_coverage` 至少 3 段

注意：

- YAML 里还有一个 `downloaded_write_then_exec`
- 但这版 `path_scoring.py` 没有真正读取它
- 所以它不是上次实验分数变化的来源

#### 4.5.3 prior 分数

仍然使用旧的 `TaskPrior`：

- `graph_task_score_weight`
- `top_process_rank_weight`
- `top_edge_rank_weight`
- `in_task_time_range_bonus`
- `out_of_task_time_range_penalty`

这意味着这版虽然在链条上做了 truth-gap 修补，但本质上还受旧 `module1/2` 任务图先验影响。

#### 4.5.4 penalty 规则

这版保留的主要惩罚项：

- `weak_execution_only`
  - 只有 `ExecutionWeak` 没有 `ExecutionStrong`

- `high_reuse_object`
  - bridge edges 太多

- `single_point_sensitive_read`
  - 只有单点敏感读取，没有更完整上下文

注意：

- YAML 里还保留了 `common_daemon_normal_child / whitelist_process / time_gap_too_large / low_value_object`
- 但这版 `path_scoring.py` 没有实际消费这些 penalty

### 4.6 bridge 边规则

bridge 仍然是旧 step2b1 的对象因果边，不是 APTShield 那种全局实体传播。

bridge 的核心条件：

1. 对象必须有 allow label：
   - `O_FILE_TEMP`
   - `O_FILE_DOWNLOADED`
   - `O_FILE_UPLOADED`
   - `O_SUSPECT_WRITTEN_EXECUTABLE`
   - `O_ARCHIVE`
   - `O_PERSISTENCE`
   - `O_PRIV_CONFIG`
2. 对象不能带 deny label：
   - `O_CREDENTIAL`
   - `O_HISTORY`
   - `O_BUSINESS_DATA`
   - `O_NET_EXTERNAL`
   - `O_NET_INTERNAL`
   - `O_AUTH_CONFIG`
   - `O_SECURITY_LOG`
3. 对象类不能是：
   - `system_library`
   - `system_resource`
   - `proc_status`
4. 只允许：
   - 写者事件类型：`WRITE / CREATE / RENAME`
   - 读者或执行者事件类型：`READ / EXEC / MMAP / LOAD`
5. 必须满足：
   - 写在前，读/执行在后
   - 时间差不超过 30 分钟
   - semantic epoch 连贯

bridge 类型：

- `write_to_exec`
- `persistence_follow_on`
- `archive_follow_on`
- `write_to_read`

bridge 置信度规则：

- 可疑文件被后续 `EXEC/LOAD/MMAP`：`0.93`
- 持久化/特权配置对象：`0.78`
- 归档对象：`0.66`
- 其他允许对象：`0.55`

### 4.7 这次新增的 support 补全

这是这版实验的关键补丁之一。

每条 `CandidatePath` 在原有字段之外，会补以下信息：

- `support_event_ids`
- `support_object_keys`
- `support_relations`
- `context_ids`
- `chain_kind`
- `precursor_event_ids`
- `followup_event_ids`
- `network_support_summary`
- `object_lineage_summary`

这些字段的目的不是让路径“更长”，而是让：

1. `module6` 在 prompt 里能看到更清楚的“前因-后果结构”。
2. Holmes claim 规则能直接吃到结构化支撑，而不只靠 timeline 猜。

### 4.8 这次新增的 family 体系

这是这版实验最核心的自造层之一。

#### 4.8.1 `family` 是什么

`family` 不是 ATT&CK tactic，也不是 ATT&CK technique。

它是为了离线 truth-gap 对照而造出来的“真实链段家族标签”，用于回答：

- 这条链更像“前因短命解释器链”
- 还是“回连 C2”
- 还是“扫描”
- 还是“清理删除”
- 还是“长寿命 mail/browser/file tail”

它的目标不是标准化攻击命名，而是**避免真实恶意链段在 top-k 裁剪中消失**。

#### 4.8.2 family 列表

这版按优先级定义了 7 类 family：

1. `short_lived_precursor`
2. `attachment_or_tcexec_exec`
3. `initial_or_drop_exec`
4. `callback_c2`
5. `scan_discovery`
6. `cleanup_delete`
7. `mail_browser_context_tail`

#### 4.8.3 Holmes atom 到 family 的映射

这版先把 Holmes 原子映射到 family：

- `attachment_user_exec -> attachment_or_tcexec_exec`
- `untrusted_file_exec -> initial_or_drop_exec`
- `make_file_exec -> initial_or_drop_exec`
- `make_mem_exec -> initial_or_drop_exec`
- `cnc_communication -> callback_c2`
- `network_service_discovery -> scan_discovery`
- `clear_logs -> cleanup_delete`
- `sensitive_temp_rm -> cleanup_delete`
- `untrusted_file_rm -> cleanup_delete`
- `interpreter_precursor_chain -> short_lived_precursor`

#### 4.8.4 path 到 family 的追加规则

即使 Holmes 没给 atom，path 也可能直接被打 family：

`attachment_or_tcexec_exec`

- 事件文本里出现：
  - `attachment`
  - `tcexec`
  - `pine`
  - `mail`
  - `rimapd`

`initial_or_drop_exec`

- 事件文本里出现：
  - `/tmp/`
  - `/var/tmp/`
  - `/dev/shm/`
  - `ztmp`
- 或 path labels 含：
  - `B_EXEC_TEMP`
  - `B_EXEC_DOWNLOADED`
  - `B_EXEC_UPLOADED`
  - `B_EXEC_SUSPECT_WRITTEN`

`callback_c2`

- path labels 含：
  - `B_EXTERNAL_SEND`
  - `B_EXTERNAL_RECV`
- 或 `network_support_summary` 里有 `remote_targets=`

`scan_discovery`

- path labels 含：
  - `B_LATERAL_CONNECT`
- 或 `network_support_summary` 里有 `internal_connect=`

`short_lived_precursor`

- `precursor_event_ids` 非空

`cleanup_delete`

- path labels 含 `B_DELETE_LOG`
- 或事件文本中出现：
  - `delete`
  - `unlink`
  - `ztmp`

`mail_browser_context_tail`

- 事件文本或进程名文本里出现：
  - `firefox`
  - `thunderbird`
  - `pine`
  - `mail`
  - `browser`

### 4.9 这次新增的 precursor/followup 抽取

#### 4.9.1 precursor 规则

`precursor_event_ids` 的 marker 固定是：

- `tcexec`
- `command-not-found`
- `/dev/pts/3`
- `python3`
- `chmod`
- `bash`

任何 support 事件文本中命中这些 marker，就会进入 `precursor_event_ids`。

#### 4.9.2 followup 规则

`followup_event_ids` 会收：

1. 带以下 labels 的事件：
   - `B_EXTERNAL_SEND`
   - `B_LATERAL_CONNECT`
   - `B_DELETE_LOG`
2. 任何 `external_ip / internal_ip` 的网络通信事件
3. 删除 temp 路径对象的事件

目的：

- 把“前因”和“后果”从同一个长 timeline 里拆出来，减少模型只看到尾巴的概率。

### 4.10 这次新增的 `network_support_summary`

这也是自造字段，不是 ATT&CK 术语。

它会统计：

- `external_recv`
- `external_send`
- `internal_connect`
- `remote_targets`
- `internal_targets`

例如可能变成：

- `external_recv=2; external_send=3; remote_targets=1`
- `internal_connect=8; internal_targets=6`

它解决的问题是：

- LLM 不擅长从零散几十条 connect/send/recv 事件里自己做计数。
- Holmes 规则也不应该每次都从原始 timeline 重扫所有网络事件。

### 4.11 这次新增的 `object_lineage_summary`

这也是自造字段。

优先展示：

1. bridge 里真正可疑对象的跨进程因果关系：
   - `object_key: src->dst (reason)`
2. 如果 bridge 不够，就退化成 object version 摘要：
   - `writers / readers / executors`

它解决的问题是：

- 让模型直接看到“谁写了它、谁读/执行了它”，而不是只看到对象名。

### 4.12 这次新增的 `missed_truth_like_hints`

这是一个**诊断字段**，不直接参与预测。

触发规则：

- Holmes diagnostics 里缺了某个 expected atom
  - 记为 `missing_atom:<atom>`
- 有 `mail_browser_context_tail` 但没有 `short_lived_precursor`
  - 记为 `mail_browser_tail_without_precursor`
- 有 `scan_discovery` 但没有 `callback_c2`，同时又看到了 remote target
  - 记为 `external_network_seen_without_callback_family`
- 有 attachment marker 但没打上 `attachment_or_tcexec_exec`
  - 记为 `attachment_markers_without_exec_family`

它解决的问题是：

- 让人工复盘时能一眼看到“这条 path 看起来像少了哪一段”。

### 4.13 这次新增的 precursor rescue

如果正常 `search_candidate_paths() + score_candidate_paths()` 的结果里**一条都没有** `short_lived_precursor` family，那么会额外尝试构造一条救援 path。

构造规则：

1. 在 `retained_events` 里找命中 precursor marker 的事件。
2. 至少要有 2 条这样的事件。
3. 取这些事件对应的进程。
4. 再把它们同父进程、且启动时间和 precursor 首时刻差不超过 10 分钟的兄弟进程也纳入。
5. 按启动时间排序形成 `process_chain`。
6. 截断到 `path_search.max_depth`。
7. 如果这条链已经和现有 path 的 process chain 完全相同，就不再重复生成。

这条救援 path 的固定属性：

- `path_type = precursor_rescued`
- `family_tags = ["short_lived_precursor"]`
- `chain_kind = precursor_rescued`
- `warnings = ["precursor_rescued: preserved short-lived precursor branch"]`

它解决的具体问题是：

- `0546` 里短命 `bash / command-not-found / tcexec / python3 / chmod` 分支太容易被长寿命 mail/browser/file-tail 链挤掉。

### 4.14 这次新增的 family 保留槽位

这是另一个非常关键的自造机制。

#### 4.14.1 它是什么

不是简单按 risk_score 排前 `path_top_k`。

而是先按优先级 family 为每类预留一个槽位，再用剩余槽位按排序补满。

#### 4.14.2 规则

family 优先级顺序是：

1. `short_lived_precursor`
2. `attachment_or_tcexec_exec`
3. `initial_or_drop_exec`
4. `callback_c2`
5. `scan_discovery`
6. `cleanup_delete`
7. `mail_browser_context_tail`

选择逻辑：

1. 先按 `_path_sort_key` 排序：
   - 风险分高
   - family 数量多
   - stage 覆盖多
   - process_chain 长
2. 然后对每个 family，挑出该 family 的第一条 path 保底保留。
3. 再把剩余空位按总排序依次填满。

这就意味着：

- 一条 precursor path 分数可以低于某条 tail path
- 但只要它是唯一的 precursor family，它就不会被完全挤掉

### 4.15 这次新增的 provenance/support 二次重排

这是最后一步重打分。

#### 4.15.1 `support_compactness`

看 support 事件时间跨度：

- `<= 5m`：`+2`
- `<= 15m`：`+1`
- `<= 45m`：`0`
- `<= 90m`：`-1`
- `<= 180m`：`-2`
- `> 180m`：`-3`

解决的问题：

- 时间拉得太长的“大杂烩 path”通常解释性更差。

#### 4.15.2 `provenance_density`

看关键 provenance label 是否有真实 provenance record 支撑：

- 覆盖率 `>= 0.85`：`+3`
- `>= 0.6`：`+1.5`
- `>= 0.35`：`0`
- `> 0`：`-1.5`
- `= 0`：`-3`

解决的问题：

- 纯靠弱语义推断出来、但没有 provenance 支撑的 path 不应排太前。

#### 4.15.3 `support_coherence`

看 support 对象和 support relation 是否协调：

- 对象很少、关系明确：加分
- 对象很多、关系极少：减分

解决的问题：

- 一条 path 如果挂了很多对象，却几乎说不清对象之间的关系，通常是噪声链。

#### 4.15.4 调整幅度

三项分数相加后，会被裁到 `[-4, +4]`，再加到 `risk_score` 上。

也就是说，这一步是**重排**，不是彻底推翻旧分数。

## 5. 这版 Holmes claim 层到底是什么

### 5.1 先说结论

这版所谓的 `Holmes` 不是把 Holmes 论文的整套系统复现进来了。

它指的是：

`一套受 Holmes 风格启发、但由本仓库自定义的 TTP atom 目录 + 规则生成 + claim DAG`

所以这里的：

- `Holmes atom`
- `Holmes-style TTP atom`
- `Holmes claim graph`

都属于这版代码自己的解释层术语，不是论文原样对象名。

### 5.2 Holmes atom 目录

这版目录固定为 `HOLMES_TTP_CATALOG`。

每个 atom 都带：

- `apt_stage`
- `statement`
- `query_terms`
- `tactic_ids`
- `technique_ids`
- `allow_tactics`

完整列表如下。

| atom | apt_stage | tactic_ids | technique_ids | 语义 |
| --- | --- | --- | --- | --- |
| `untrusted_read` | Initial Compromise | `TA0001` | 空 | 进程接收/读取外部不可信内容 |
| `make_mem_exec` | Initial Compromise | `TA0002` | 空 | 处理不可信输入后把内存改成可执行 |
| `make_file_exec` | Initial Compromise | `TA0002` | 空 | 把落地文件改成可执行 |
| `untrusted_file_exec` | Initial Compromise | `TA0002, TA0011` | `T1105` | 执行不可信/落地文件 |
| `attachment_user_exec` | Initial Compromise | `TA0001, TA0002` | `T1566.001, T1566.002, T1204.002` | 用户打开/执行附件样对象 |
| `shell_exec` | Establish Foothold | `TA0002` | `T1059` | shell/interpreter 执行命令 |
| `cnc_communication` | Establish Foothold | `TA0011` | `T1071.001` | 与外部端点进行回连/C2 通信 |
| `sudo_exec` | Privilege Escalation | `TA0004` | 空 | 通过 sudo/提权辅助工具执行 |
| `switch_su` | Privilege Escalation | `TA0004` | 空 | 进程切换到更高权限身份 |
| `sensitive_read` | Internal Recon | `TA0006, TA0009` | `T1552.003, T1005` | 读取凭据/历史/敏感本地文件 |
| `sensitive_command` | Internal Recon | `TA0007` | 空 | 执行枚举或主机侦察命令 |
| `network_service_discovery` | Internal Recon | `TA0007` | `T1046` | 多主机/爆发式连接，像扫描或服务发现 |
| `send_internal` | Move Laterally | `TA0008` | 空 | 对内网发起可疑连接 |
| `sensitive_leak` | Complete Mission | `TA0010, TA0011` | `T1041` | 敏感数据后接外发 |
| `clear_logs` | Cleanup Tracks | `TA0005` | `T1070.004` | 清理日志/防御规避 |
| `sensitive_temp_rm` | Cleanup Tracks | `TA0005` | `T1070.004` | 删除收集后留下的临时物 |
| `untrusted_file_rm` | Cleanup Tracks | `TA0005` | `T1070.004` | 删除执行过的落地恶意对象 |
| `interpreter_precursor_chain` | Establish Foothold | `TA0002, TA0001` | `T1059` | 短命解释器前因链 |

### 5.3 Holmes atom 的触发规则

这是这版里真正最重要的“规则表”之一。

`untrusted_read`

- 只要有 `external_recv_ids`

`make_mem_exec`

- 有 `mem_exec_ids`
- 且同时存在 `external_recv_ids` 或 `precursor_ids`

`make_file_exec`

- 有 `chmod_ids`
- 且同时存在 `external_recv_ids` 或 `bridge_exec_ids` 或 `precursor_ids`

`untrusted_file_exec`

- 有 `bridge_exec_ids`

`attachment_user_exec`

- 有 `attachment_ids`

`shell_exec`

- 有 `shell_exec_ids`

`cnc_communication`

- 有 `external_send_ids`
- 或者存在 `external_recv_ids` 且 dossier 带 `network_support_summary`

`sudo_exec`

- 有 `sudo_ids`

`switch_su`

- 有 `su_ids`

`sensitive_read`

- 有 `sensitive_ids` 或 `history_ids` 或 `business_ids`

`sensitive_command`

- 有 `recon_command_ids`

`network_service_discovery`

- `scan_ids >= 2`
- 或 `(scan_ids 非空 且 lateral_ids 非空)`

`send_internal`

- 有 `internal_send_ids`

`sensitive_leak`

- 有 `external_send_ids`
- 且同时有 `sensitive_ids / business_ids / history_ids`

`clear_logs`

- 有 `log_delete_ids`

`sensitive_temp_rm`

- 有 `temp_remove_ids`
- 且同时有 `sensitive_ids / business_ids / history_ids`

`untrusted_file_rm`

- 有 `temp_remove_ids`
- 且同时有 `bridge_exec_ids`

`interpreter_precursor_chain`

- 有 `precursor_ids`

### 5.4 `evidence_event_ids` 是怎么来的

这版 Holmes 规则不是只给 atom 名字，还会给每个 claim 绑定支撑事件 ID。

例如：

- `bridge_exec_ids` 来自 bridge 的 `write_event_id / read_or_exec_event_id`
- `precursor_ids` 优先用 dossier 明确给出的 `precursor_event_ids`
- `scan_ids` 通过：
  - `B_LATERAL_CONNECT`
  - 或 `internal_ip / external_ip` 上的 `CONNECT`
- `temp_remove_ids` 通过删除 `/tmp / temp / gtcache / ztmp`

这一步解决的问题是：

- 后续 ATT&CK 映射必须能追到 claim ID，而 claim 又必须能追到 event ID。

### 5.5 Holmes claim 的 prerequisite 规则

这版 claim graph 里的边全部是 `prerequisite`。

规则如下：

- `make_mem_exec <- untrusted_read`
- `make_file_exec <- untrusted_read`
- `untrusted_file_exec <- untrusted_read / make_file_exec / attachment_user_exec`
- `attachment_user_exec <- untrusted_read`
- `shell_exec <- untrusted_file_exec / attachment_user_exec / interpreter_precursor_chain`
- `cnc_communication <- untrusted_file_exec / attachment_user_exec / shell_exec / interpreter_precursor_chain`
- `sudo_exec <- shell_exec`
- `switch_su <- shell_exec`
- `sensitive_read <- untrusted_file_exec / shell_exec / cnc_communication / interpreter_precursor_chain`
- `sensitive_command <- untrusted_file_exec / shell_exec / cnc_communication / interpreter_precursor_chain`
- `network_service_discovery <- shell_exec / cnc_communication / attachment_user_exec`
- `send_internal <- shell_exec / cnc_communication`
- `sensitive_leak <- sensitive_read / cnc_communication`
- `clear_logs <- shell_exec / cnc_communication`
- `sensitive_temp_rm <- sensitive_read`
- `untrusted_file_rm <- untrusted_file_exec`
- `interpreter_precursor_chain <- attachment_user_exec / make_file_exec / untrusted_read`

动机：

- 让后续 LLM 映射时，不是把 claims 当成平铺清单，而是保留“前因-后果”的结构。

### 5.6 `module6` 第一次 LLM 抽取并不是自由生成 claims

这版第一次 LLM 抽取仍然会调用大模型，但约束非常强：

1. 只允许从 Holmes 预匹配原子里“确认、细化或省略”。
2. 不允许发明新的 `behavior_type`。
3. 不允许发明新的 `claim_id`。
4. 优先使用 bridge、support relation、带 label 的网络/文件事件。
5. 禁止写泛泛而谈的“可能存在威胁”。
6. 如果没有支持，就返回空 claims。

也就是说：

- 第一次 LLM 不是自由的 open-ended 语义总结。
- 它更像是在做“Holmes atom 审核 + 文本润色”。

### 5.7 claims 校验规则

LLM 抽取完 claims 后，不会直接信任。

#### 5.7.1 结构校验

claim 至少要有：

- `claim_id`
- `statement`
- `evidence_event_ids`

而且 `evidence_event_ids` 必须在 dossier 真实事件集合里。

#### 5.7.2 generic claim 过滤

如果 statement 里含这些泛化词，就丢掉：

- `series of system calls`
- `may indicate a potential threat`
- `malicious object`
- `not fully understood`

#### 5.7.3 按 behavior_type 的 required signal 校验

这版非常关键的一层是：**每类 claim 都有自己必须看到的信号**。

例如：

`untrusted_read`

- 必须有 `B_EXTERNAL_RECV`
- 或外部 IP 的 `RECV / CONNECT`

`make_mem_exec`

- statement 或事件文本里必须有：
  - `mprotect`
  - `mem exec`
  - `virtualalloc`

`make_file_exec`

- 必须看到：
  - `chmod`
  - `executable`
  - `staged object`
- 或事件类型是 `CHMOD / MODIFY_FILE_ATTRIBUTES`

`untrusted_file_exec / attachment_user_exec`

- 必须看到执行类 label：
  - `B_EXEC_SUSPECT_WRITTEN`
  - `B_EXEC_DOWNLOADED`
  - `B_EXEC_UPLOADED`
  - `B_EXEC_TEMP`
- 或者 evidence event 在 bridge_exec_ids 里

`shell_exec / interpreter_precursor_chain`

- 必须命中：
  - `bash`
  - `shell`
  - `python`
  - `perl`
  - `php`
  - `tcexec`
  - `command-not-found`

`cnc_communication`

- 必须有：
  - `B_EXTERNAL_SEND`
  - 或 `B_EXTERNAL_RECV`
  - 或 `external_ip` 上的 `SEND / CONNECT / RECV`

`sensitive_read`

- 必须看到：
  - `B_READ_CRED`
  - `B_READ_HISTORY`
  - `B_READ_BUSINESS`
  - `B_MASS_FILE_ACCESS`

`network_service_discovery`

- 必须有 `B_LATERAL_CONNECT`
- 或文本里有：
  - `scan`
  - `discovery`
  - `connect burst`
  - `service discovery`

`clear_logs / sensitive_temp_rm / untrusted_file_rm`

- 必须有 `B_DELETE_LOG`
- 或事件类型属于：
  - `DELETE`
  - `UNLINK`
  - `RENAME`

动机：

- 防止 LLM 因为看见一点弱上下文，就把不该成立的 claim 也写出来。

### 5.8 fallback merge 规则

这版最后不会只用 LLM claims，而是：

`final_claims = merge(LLM_valid_claims, Holmes_rule_claims)`

更准确地说，fallback claim graph 先由 Holmes 规则生成，再让 LLM 来：

- 覆盖 statement
- 提高 confidence
- 补更多 evidence_event_ids

如果 LLM 没说出来，Holmes 规则 claim 仍然会保留。

它解决的问题是：

- 不让第一次 LLM 把关键 claim 漏掉之后，整条链直接空掉。

## 6. ATT&CK 候选到底怎么取回来的

### 6.1 这版候选检索不是纯向量召回

入口：

- `retrieve_attack_candidates()`

查询上下文 `_QueryContext` 由这些部分组成：

- `terms`
- `action_families`
- `command_lexemes`
- `object_semantics`
- `os_hint`
- `claim_terms`
- `behavior_types`

### 6.2 query terms 怎么构造

#### 6.2.1 action families

从 bundle 事件动作和 claim 文本里提取：

- `execution`
- `network_c2`
- `file_persistence`
- `recon`
- `credential`

例如：

- 有 `CONNECT / SEND / RECV` 就会加 `network_c2`
- 有 `EXECUTE / LOAD / MMAP / FORK` 就会加 `execution`
- claim 文本里出现 `discover / enumeration / whoami / scan` 就会加 `recon`

#### 6.2.2 behavior type terms

会把 behavior type 展开成 ATT&CK 相关语义词。

例如：

- `network_service_discovery -> port scan / service scan / discovery`
- `phishing_or_user_execution -> spearphishing / user execution / malicious file`

Holmes atoms 也会把自己的 `query_terms` 注入进来。

#### 6.2.3 command lexemes

会从事件文本和 claim 文本里抽命令词，例如：

- `bash`
- `python`
- `curl`
- `wget`
- `scp`
- `ssh`
- `cron`
- `systemctl`
- `nc`

#### 6.2.4 object semantics

会从路径和对象语义抽一些词，例如：

- `shell profile modification`
- `scheduled task or service artifact`
- `temporary executable artifact`
- `host discovery file`
- `remote endpoint`
- `file discovery artifact`

#### 6.2.5 OS hint

会做一个很粗的系统类型判断：

- `windows`
- `macos`
- `linux`
- `unknown`

TRACE 这次基本会偏 `linux`。

### 6.3 候选打分公式

每个 tactic/technique 的总分是：

`0.45 * sparse_score + 0.55 * dense_score + compatibility_bonus`

但这次配置里：

- `attack_kb_enable_vector = false`

所以：

- `dense_score = 0`

也就是说这次实际总分近似于：

`0.45 * sparse_score + compatibility_bonus`

### 6.4 compatibility bonus 规则

这版 compatibility bonus 很重要，因为它弥补了纯关键词检索的不足。

#### 6.4.1 action family bonus

如果 query 带某个 action family，而候选文本里也像这个 family，会加分：

- `network_c2`：`+0.28`
- `execution`：`+0.26`
- `file_persistence`：`+0.28`
- `recon`：`+0.28`
- `credential`：`+0.28`

#### 6.4.2 object semantic bonus

- object 语义 token 有重叠：每个语义 `+0.10`

#### 6.4.3 OS 兼容性 bonus/penalty

若 `os_hint = linux`：

- 命中 Windows/Mac 特征：`-0.45`
- 命中 Linux 特征：`+0.14`

其他系统同理。

#### 6.4.4 claim token overlap bonus

- `0.08 * overlap_count`
- 上限 `0.30`

#### 6.4.5 behavior prior bonus

如果候选 ATT&CK ID 正好是某个 behavior type 的 prior：

- technique prior：`+0.75`
- tactic prior：`+0.45`

注意：

- 这一步属于**候选检索阶段的 behavior prior**
- 即使 `claim_attack_prior_mode=disabled`，这版代码里 ATT&CK 检索本身仍然会在 `_compatibility_bonus()` 用到 `behavior_types`
- 但不会再额外做 `claim_attack_hints` 注入和 mapping suppress/backfill

### 6.5 候选列表规模

这次检索输出：

- tactics：最多 `max(5, min(candidate_limit, 8))`
- techniques：最多 `candidate_limit = 12`

而 tactics-only 模式下后续会把 techniques 清空。

## 7. 这版 `module6` 到底怎么输出战术

### 7.1 两条线的共同前半段

无论 `deterministic` 还是 `llm`，前半段都一样：

1. 从 `module5_paths/candidate_paths/*.json` 读取 path。
2. 每个任务只处理前 `reason_top_paths_per_task = 5` 条。
3. 为每条 path 生成 dossier。
4. 第一次 LLM 做 claim extract。
5. Holmes 规则做 fallback merge。
6. 从 ATT&CK KB 取候选。

真正的分叉只发生在“把 claims 映射成 ATT&CK”的时候。

### 7.2 `claim_attack_prior_mode=disabled` 到底关掉了什么

这是这次实验的核心前提。

关掉后，以下逻辑都不再生效：

1. 不生成 `claim_attack_hints`
2. mapping prompt 不渲染 `CLAIM_HINTS`
3. prompt 规则里不再提 `claim_attack_hints`
4. 不做 `_augment_attack_candidates_with_behavior_priors()`
5. `_validate_mappings()` 不再强制行为 allowlist/prior 过滤
6. `_apply_behavior_prior_mappings()` 直接变成 no-op

也就是说，关掉 prior 后：

- 还会有 Holmes atoms
- 还会有 ATT&CK candidate retrieval
- 但不会再做 claim 级别的“推荐战术/技术”牵引

### 7.3 tactics-only 模式到底关掉了什么

当 `attack_mapping_scope = tactics_only` 时：

1. 候选上下文里只保留 `TACTIC_CANDIDATES`
2. `TECHNIQUE_CANDIDATES` 不再进入 prompt
3. 最终 mapping 强制：
   - `technique_id = ""`
   - `technique = ""`
4. evaluator 不再把“没产 technique”当 warning

它解决的问题是：

- technique 级别太细，容易因为 claim 细节不够而误判。
- 先把 tactic 稳住，比强行输出 technique 更可靠。

### 7.4 `deterministic_tactics_only` 的映射规则

这条线根本**不调用第二次 ATT&CK mapping LLM**。

规则非常直接：

1. 对每个 final claim，看它的 `behavior_type`
2. 从 `HOLMES_TTP_CATALOG[behavior_type].tactic_ids` 取 tactic
3. 如果 catalog 里 tactic 为空，再退到 `_PATH_BEHAVIOR_ALIGNMENT_PRIORS`
4. 生成一条 tactic-only mapping
5. 以 `(tactic_id, evidence_claim_ids)` 去重

例如：

- `cnc_communication -> TA0011`
- `network_service_discovery -> TA0007`
- `clear_logs -> TA0005`
- `attachment_user_exec -> TA0001, TA0002`

confidence 规则：

- `max(0.72, claim.confidence)`

它解决的问题是：

- 把第二次大模型映射的随机性拿掉
- 直接检验“Holmes atoms 本身有没有足够稳定地指向战术”

### 7.5 `llm_tactics_only` 的映射 prompt 规则

这条线保留第二次大模型，但 prompt 很受限。

固定规则包括：

- 只用提供的 claims、timeline 和 ATT&CK 候选
- claims 视作 Holmes-style TTP atoms
- 保留 claim 的因果顺序
- 每个 claim 独立映射
- 只能从候选 ATT&CK 列表里选
- 先选最有支撑的 tactic
- tactics-only：`technique_id` 和 `technique` 必须留空
- 不允许把 generic execution-chain claim 映射到 injection/COM/hollowing/hijacking
- `network_service_discovery` 和 `sensitive_command` 更偏向 `Discovery`
- `clear_logs / sensitive_temp_rm / untrusted_file_rm` 更偏向 `Defense Evasion`
- `attachment_user_exec` 更偏向 `Initial Access + Execution`
- 凭据读取但证据不够时，宁可只给 `Credential Access` tactic

这条线解决的问题是：

- deterministic 太硬，可能无法根据上下文细调 tactic
- 但仍然把模型限制在 tactic 级别，降低 technique 级噪声

### 7.6 LLM mapping 的结果还会被校验

`_validate_mappings()` 会做这些事：

1. claim ID 必须真实存在
2. tactic/technique ID 必须格式合法
3. tactic/technique 必须能在候选 ATT&CK 列表里找到
4. 如果只给了 technique，会尝试反推出 tactic
5. 如果 `tactics_only`，强制清空 technique
6. tactic 和 technique 必须彼此兼容
7. evidence claim 再过一遍 claim 支撑过滤
8. 最后按 `(tactic_id, technique_id, claim_ids)` 去重

也就是说，第二次 LLM 不是“说什么都收”，它只是提出候选，最后还要通过规则网。

## 8. evaluator 当时怎么评

### 8.1 仍然是窗口评估，不是单事件评估

这版 evaluator 仍然按 GT 窗口来评，不是逐条事件对齐。

GT 窗口来自：

- `docs/darpa_attack_eval_ground_truth_2026-05-26.json`

评估时会：

1. 把每条 predicted path 和 GT window 做时间匹配
2. 对每个窗口收集 top-N 匹配 path 的战术并集
3. 再和 GT tactics 比较

### 8.2 top-N 规则

这版 evaluator 的 `match_top_n = 5`。

也就是说，每个 GT window 只用：

- 时间上 primary match 的 path
- 再按 risk/risk_level/purity 排序
- 取前 5 条

然后对这 5 条做 tactics 并集。

### 8.3 tactics-only 下的主指标

这版真正看的主指标是：

- `confirmed_window_recall`
- `strict_tactic_recall_macro`
- `strict_tactic_precision_macro`
- `off_window_high_risk_rate`

此外还会落：

- `tactic_comparison.json`
- `tactic_diff_by_task.json`
- `candidate_tactic_coverage_by_task.json`

其中：

`tactic_diff_by_task.json`

- `gt_tactics`
- `predicted_tactics_union_top_n`
- `matched_tactics`
- `missed_tactics`
- `extra_tactics`

`candidate_tactic_coverage_by_task.json`

- `candidate_tactics_union_top_n`
- `covered_gt_tactics`
- `missing_candidate_tactics`

这个文件很重要，因为它能区分：

- 是候选就没召回
- 还是候选有了，但最后 mapping 没映出来

## 9. 这版代码里自造词到底都是什么意思

### 9.1 `truth-gap`

不是模型术语，也不是 ATT&CK 术语。

它指：

`GT / 攻击报告 / 原始日志 / 当前产物` 之间的真实链条缺口分析

### 9.2 `family`

不是 tactic，也不是 technique。

它是为了保住“真实链段类型”而造的中间标签。

### 9.3 `precursor`

指恶意链里的前因短命分支，尤其是：

- `bash`
- `command-not-found`
- `tcexec`
- `python3`
- `chmod`
- `/dev/pts/3`

### 9.4 `precursor_rescue`

当正常候选链全把 precursor 挤掉后，额外救回一条短命前因链。

### 9.5 `followup`

指链的后果性动作：

- 对外发送
- 横向连接
- 删除日志
- 删除 temp 痕迹

### 9.6 `network_support_summary`

把分散网络事件压成简短统计摘要，减少 prompt 噪声。

### 9.7 `object_lineage_summary`

把“对象被谁写、被谁读/执行”的因果关系压成摘要。

### 9.8 `holmes_matched_atoms`

指这条 path 被 Holmes 风格规则匹配到了哪些 atom。

### 9.9 `missed_truth_like_hints`

指人工诊断提示，告诉你这条链可能缺了哪类真实链段。

### 9.10 `claim_attack_prior_mode`

控制 claim 级 ATT&CK 先验是否启用。

- `full`
- `disabled`

### 9.11 `tactics_only`

输出 ATT&CK 时只要 tactic，不要 technique。

### 9.12 `deterministic_tactics_only`

第一次 LLM 做 claims，第二次 ATT&CK mapping 不用 LLM，直接按 Holmes atom 映射 tactic。

### 9.13 `llm_tactics_only`

第一次 LLM 做 claims，第二次 ATT&CK mapping 仍用 LLM，但只输出 tactic。

## 10. 这版方法每一步的动机

### 10.1 为什么不直接推翻 `CandidatePath`

因为这轮目标不是换范式，而是尽快回答一个更具体的问题：

- 旧 `microstep2b` 为什么会把真实恶意前因丢掉？
- 如果只在链条保留和战术映射上修补，是否已经能明显改善结果？

所以保留旧主线，可以把效果变化更明确地归因给：

- 链条保留
- Holmes claim 约束
- tactics-only 映射

### 10.2 为什么要造 `family`

因为旧 top-k 机制更偏好：

- 长
- 分高
- stage 多

但真实恶意前因链常常：

- 短
- 命中标签少
- 存活时间短

如果不显式保留 family，`0546` 这种前因分支会一直被长尾 mail/browser/file 读链挤掉。

### 10.3 为什么要造 `precursor_rescue`

因为有些任务里：

- 真正恶意的是一个很短、很快消失的解释器链
- 但证据图里更容易留下的是长寿命后续上下文

单靠原始 path score 很难把短命链排上去，所以必须给它一个“兜底”。

### 10.4 为什么要加 `network_support_summary` 和 `object_lineage_summary`

因为原始 timeline 对大模型不友好：

- 网络事件多时，模型容易只看到“很多 connect”
- 文件对象多时，模型容易只看到“很多文件访问”

但攻击判断真正需要的是：

- 有多少外连
- 有多少内连
- 涉及多少目标
- 哪个对象是从谁写到谁执行

所以做结构化摘要是为了提高信息保真，而不是为了好看。

### 10.5 为什么 Holmes claims 只允许“确认/删减”预匹配原子

因为你前面已经明确感觉到：

- `claims` 这块最容易漂
- 一旦让 LLM 自由发明行为名，它就会越来越偏离证据

所以这版做法是：

- 先由规则匹配出一个收缩过的 atom 集
- 再让 LLM 只在这个集合里做确认和润色

### 10.6 为什么要关闭 `claim_attack_hints`

因为此前你已经怀疑它会把结果拉偏到：

- `Credential Access`
- `Collection`
- `C2`

尤其容易让 `0546` 这类任务过度解释成“长尾收集语义”。

所以这次实验就是在问：

`偏差到底来自 claims 本身，还是来自 claims -> ATT&CK 这一层 prior 牵引？`

### 10.7 为什么要做 `deterministic` 和 `llm` 双路

因为这能把问题拆开：

- 如果 deterministic 已经够好，说明 Holmes atoms 本身足够稳定
- 如果 deterministic 不够，llm tactics-only 还能提升，说明上下文推理仍然有价值
- 如果两边都不够，问题更可能在上游 CandidatePath 本身

## 11. 这次实验版最关键的局限

### 11.1 它仍然依赖旧 `CandidatePath`

所以它还会继承旧问题：

- seed 选择偏差
- stage 组合门槛偏差
- DFS 搜链偏差
- 任务图先验偏差

### 11.2 它并没有完全拿掉 ATT&CK 先验

虽然 `claim_attack_prior_mode=disabled` 关掉了 claim-level prior，但 ATT&CK 检索时：

- query 仍然会使用 Holmes behavior types
- compatibility bonus 仍然会使用 behavior prior

所以它不是“完全无先验”的战术映射。

### 11.3 `attack_kb_enable_vector=false`

这意味着这次检索不是 dense+semantic 的强检索，而是：

- TF-IDF 稀疏检索
- 加一些规则 bonus

因此候选召回上限本身就有限。

### 11.4 `attack_kb_claim_weight` 在这版没生效

这是一个实现层面的不一致：

- 配置里有
- 代码里没用

所以不能把它当成这次实验结果的解释变量。

### 11.5 仍然只让 `module6` 看每任务前 5 条 path

这意味着：

- 有些明明存在于 `module5` 的低排名好链
- 仍然可能因为没进 `reason_top_paths_per_task=5`
- 完全进不了 `module6`

## 12. 一句话概括这版代码

如果必须用一句话概括上次跑的版本，可以这样说：

`它还是 step2b1 的 CandidatePath 主线，但在 module5 用 truth-gap 分析补了一层 family 保留和 precursor rescue，在 module6 用 Holmes 风格 claims 约束语义，再把 ATT&CK 输出收缩成关闭 prior 的 tactics-only 双路映射。`
