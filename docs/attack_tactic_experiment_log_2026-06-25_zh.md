# `APT-Fusionstep2b1` 攻击战术分析修改实验记录

## 1. 文档目的

这份文档用于沉淀 `APT-Fusionstep2b1` 近几轮“攻击战术分析后半段”修改实验的结论，方便后续继续设计优化方案时快速参考。

重点记录：

- 每次实验具体改了什么
- 为什么要做这次修改
- 在哪些数据集上验证
- 实验结果是成功、失败，还是“未生效但有诊断价值”
- 成功或失败的主要原因
- 当前应该从哪条稳定基线继续往下做

本文主要覆盖已经有明确 runner、artifact、指标或定性结论的实验线。对于产物已清理、但结论已经稳定的实验，也保留必要的复盘说明。

## 2. 统一口径与当前基线

### 2.1 当前统一 GT 与时间偏移

- 当前后续分析统一参考：
  - [darpa_attack_eval_ground_truth_e3_report_enriched_20260618.json](/D:/daima/APT-Fusionstep2b1/docs/darpa_attack_eval_ground_truth_e3_report_enriched_20260618.json)
- `TRACE` 和 `THEIA` 的战术分析实验统一显式应用 `+240` 分钟偏移。
- 这个 `+240` 是 runner / evaluator 级参数，不写回 GT 文件本身。

### 2.2 当前代码语义

当前稳定线更接近：

- `step2` 风格的链条 / claim 收紧版本
- 外加 `step2b_browsercredguard` 的浏览器凭据上下文保护
- 外加 `step4l_concretecleanupdossierpatch` 的 cleanup 证据整理
- evaluator 侧再叠加 `step4m_windowcontinuation` 的同任务尾段重归属

需要特别说明：

- 当前本地工作树里，`O_SERVICE_SYSTEM_FILE`、`O_SENSITIVE_STRONG`、`O_SENSITIVE_WEAK`、`O_STAGED_EXEC_SOURCE`、`O_LOG_ARTIFACT` 这些名字在下游规则和报告里已经被引用。
- 但在当前稳定代码线上，它们还不是一套完整、稳定、持续启用的 `module4` 上游对象角色传播体系。
- 也就是说，当前稳定线并不是“真正完成版的对象标签传播线”。

## 3. 当前稳定基线

### 3.1 TRACE 稳定基线

artifact：

- `artifacts_trace_train_stats_latefusion_bonus1_microstep2b_truthgap_tactics_only_llm_worktree_step4m_windowcontinuation_e3gt_plus240_gtonly_20260626`

指标：

- `confirmed_window_recall = 0.5`
- `strict_tactic_recall_macro = 0.4375`
- `strict_tactic_precision_macro = 1.0`
- `off_window_high_risk_rate = 0.0`

关键窗口现状：

| 窗口 | 应有战术 | 当前命中 | 当前漏报 | 当前误报 |
| --- | --- | --- | --- | --- |
| `TRACE_20180410_0946_1109_01` | `INITIAL_ACCESS, EXECUTION, PRIVILEGE_ESCALATION, COMMAND_AND_CONTROL` | 无 | 全漏 | 无 |
| `TRACE_20180410_1228_1230_02` | `INITIAL_ACCESS, EXECUTION, CREDENTIAL_ACCESS` | 无 | 全漏 | 无 |
| `TRACE_20180412_1336_1336_03` | `INITIAL_ACCESS, EXECUTION` | 无 | 全漏 | 无 |
| `TRACE_20180413_1243_1253_04` | `INITIAL_ACCESS, EXECUTION, COMMAND_AND_CONTROL, DISCOVERY, DEFENSE_EVASION` | 全命中 | 无 | 无 |
| `TRACE_20180413_1350_1428_05` | `INITIAL_ACCESS, EXECUTION, COMMAND_AND_CONTROL, DISCOVERY` | `INITIAL_ACCESS, EXECUTION, COMMAND_AND_CONTROL` | `DISCOVERY` | 无 |

结论：

- 这是当前 TRACE 的稳定回归线。
- 后续 TRACE 的每一步优化，默认都要和这条线比较，不能覆盖掉它。

### 3.2 THEIA 稳定基线

artifact：

- `artifacts_theia_train_stats_latefusion_llama31_microstep2b_module1_gtbase_tactics_only_llm_fanout_gt2_e3gt_windowgate_step4m_windowcontinuation_offset240_20260626`

指标：

- `confirmed_window_recall = 0.6666666666666666`
- `strict_tactic_recall_macro = 0.6666666666666666`
- `strict_tactic_precision_macro = 1.0`
- `off_window_high_risk_rate = 0.0`

关键窗口现状：

| 窗口 | 应有战术 | 当前命中 | 当前漏报 | 当前误报 |
| --- | --- | --- | --- | --- |
| `THEIA_20180410_1341_1455_01` | `INITIAL_ACCESS, EXECUTION, PRIVILEGE_ESCALATION, COMMAND_AND_CONTROL, DISCOVERY` | 全命中 | 无 | 无 |
| `THEIA_20180410_1342_1342_02` | `INITIAL_ACCESS, EXECUTION, CREDENTIAL_ACCESS` | 全命中 | 无 | 无 |
| `THEIA_20180412_1244_1326_03` | `INITIAL_ACCESS, EXECUTION, PRIVILEGE_ESCALATION, COMMAND_AND_CONTROL, DISCOVERY, DEFENSE_EVASION` | 无 | 全漏 | 无 |
| `THEIA_20180413_1350_1404_04` | `INITIAL_ACCESS, EXECUTION` | 无 | 全漏 | 无 |

结论：

- 这是当前 THEIA 的稳定主跑线。
- 后续 THEIA 的每一步优化，默认都要和这条线比较，不能覆盖掉它。

## 4. 实验总览

| 实验名 | 数据集 | 主要修改 | 结果 | 当前状态 |
| --- | --- | --- | --- | --- |
| `servicectx_20260616` | CADETS | 全局正常服务上下文抑制 | 失败 | 已淘汰，只作反例参考 |
| `ruletight1_20260616` | CADETS | 第一轮链条语义收紧 | 相对成功 | 作为 CADETS 误报分析参考线 |
| `step3_objecttransfer_20260617` | CADETS + TRACE | 对象角色标签和传播尝试 | 有产出，但未成为稳定线 | 只作历史参考和上游快照 |
| `e3gt_offset240_20260624` | THEIA | 切到 enriched GT + `+240`，但不做 window gate | 失败 | 不作为后续主线 |
| `e3gt_windowgate_20260624` | THEIA | 先按 confirmed 窗口做下游过滤 | 成功 | 保留为 THEIA 主跑前置策略 |
| `replay_from_module3_e3gt_plus240_20260624` | TRACE | 用 enriched GT + `+240` 重放后半段 | 成功 | 保留为 TRACE 稳定回归基线 |
| `step1_privfollow_20260624` | TRACE + THEIA | 增加 privilege follow-up 尝试 | 未生效 | 不作为稳定线，但诊断价值高 |
| `step2b_browsercredguard_20260624` | TRACE + THEIA | 浏览器/邮件凭据上下文保护 | 成功 | 当前稳定线的一部分 |
| `step2c_followuptimeline_20260624` | TRACE + THEIA | 放宽 dossier 时间线 | 失败 | 已回退；失败结论保留 |
| `step2d_clearlogsfallback_20260624` | TRACE + THEIA | 用 followup/cleanup 回退补 `clear_logs` | 失败 | 已回退；失败结论保留 |
| `step2e_narrowcleanup_20260624` | TRACE + THEIA | 缩窄 `clear_logs` fallback | 失败 | 已回退；失败结论保留 |
| `step4a_discoverysupplement_20260624` | TRACE + THEIA | 从 discovery claim 末端补 tactic | 失败 | 已回退；失败结论保留 |
| `step3a_payloadclonepriv_20260625` | THEIA 主跑 + TRACE 回归 | 用 staged payload clone 跟进补 privilege 链 | 失败 / 未生效 | 已停止，不应作为稳定线 |
| `step12_dropfix_pathfix_20260625` | THEIA 主跑 + TRACE 回归 | 修 `subjhistory` 首条事件丢失 + 修 THEIA `FileObject` 嵌套路径提取 | 相对成功 | 作为后续 THEIA 诊断与稳定线的解析修正基线 |
| `theia_alias_epoch_diag_step12_20260625` | THEIA | 诊断 `(parent_uuid, tgid, path)` 是否过度合并 | 诊断成功 | 明确排除“alias 过度合并是主因” |
| `step4m_windowcontinuation_20260626` | TRACE + THEIA | evaluator 把同任务 confirmed 尾段从 `OFF_WINDOW` 重归属为 `CONFIRMED_CONTINUATION` | 成功 | 当前 TRACE/THEIA 稳定 evaluator 基线 |
| `step4_temporalsplit_retry_20260626` | THEIA | 再试 THEIA 时间感知切图 | 失败 | 已标记失败并清理大产物，不继续主推 |
| `theia_20180412_observable_probe_offset_sweep_20260626` | THEIA | 对 `2018-04-12` 窗口做原始日志观测项定点核查与 offset sweep | 诊断成功 | 明确排除“换固定 offset 即可解决” |

## 5. 各实验详细记录

### 5.1 `servicectx_20260616`

数据集：

- CADETS `exclude_segmented`

修改内容：

- 试图加一层“正常服务上下文”全局抑制。

动机：

- 想快速压掉由 `smtpd`、`sshd`、系统服务文件、普通外连等组成的误报链。

实验效果：

- 误报没有以可控方式下降。
- 真阳性也被明显伤到。

失败原因：

- 主要问题不在“服务上下文本身”，而在更前面的链条语义已经打歪。
- 如果前面已经把普通 `chmod`、服务对象读取、普通外连错误拼成攻击链，后面再做全局服务抑制，往往会变成高副作用补丁。

结论：

- 明确失败。
- 后续不恢复这条线。

### 5.2 `ruletight1_20260616`

数据集：

- CADETS `exclude_segmented`

修改内容：

- 第一轮更偏向链条语义收紧的修复。
- 重点不是“全局压服务”，而是先压过宽的 precursor / initial-exec / sensitive-read 类语义。

动机：

- 先压掉普通服务链被误抬成攻击链的问题。

实验效果：

- 相比 `servicectx` 这类全局抑制，更接近正确方向。
- 后续很多 CADETS 误报分析都以它为参考线。

结论：

- 相对成功。
- 它验证了一个重要原则：
  - 先修链条语义，比先做全局 benign/service 抑制更可靠。

### 5.3 `step3_objecttransfer_20260617`

数据集：

- CADETS
- TRACE

修改内容：

- 尝试引入对象角色标签和传播。

动机：

- 想把“系统服务对象”和“真实敏感对象”分开。
- 想把“普通 chmod”和“真实 staged exec 对象”分开。

实验效果：

- 这不是空改。
- 当时保留下来的 `step3` artifact 里，`module4_compact` 确实出现过：
  - `O_SERVICE_SYSTEM_FILE`
  - `O_SENSITIVE_WEAK`
  - `O_LOG_ARTIFACT`
  - TRACE 侧还出现过 `O_STAGED_EXEC_SOURCE`、`O_SENSITIVE_STRONG`
- 这些标签也进入过 `module6_reason/llm_inputs` 的摘要字段。

为什么没有成为稳定线：

- 整体收益不够稳定。
- 没有形成足够明确、跨数据集都站得住的全局增益。
- 后续稳定主线回到了更轻的 `step2` 风格链条 / claim 线。

结论：

- 不是“完全无效”的失败实验。
- 但也不是当前主推稳定线。
- 适合作为“后续若继续做真正对象传播”的历史原型参考。

### 5.4 `e3gt_offset240_20260624`

数据集：

- THEIA

修改内容：

- 切到 enriched GT，并显式应用 `+240`。
- 但没有先做 window gate。

动机：

- 先把 GT 口径和时间口径统一起来。

实验效果：

- 指标：
  - `confirmed_window_recall = 0.6666666666666666`
  - `strict_tactic_recall_macro = 0.48888888888888893`
  - `strict_tactic_precision_macro = 0.8333333333333333`
  - `off_window_high_risk_rate = 0.8704545454545455`
- `module3` 选进后半段的正类 base task 有 `201` 张。
- `module6` 产出 `815` 条 report，覆盖 `199` 张 task。

失败原因：

- 不是链条规则单点错误，而是进入后半段的任务范围过宽。
- 后续任何链条 / claim 层修补，都会先被大规模窗口外噪声淹没。

结论：

- 不能作为后续主跑基线。
- 它的主要价值是证明：
  - 对 THEIA 来说，先做窗口级下游收窄是必要前置。

### 5.5 `e3gt_windowgate_20260624`

数据集：

- THEIA

修改内容：

- 在 `module4` 入口按 confirmed 窗口 overlap 对 task 做下游过滤。
- 不改 `module1/module3` 原始产物，只收窄 `module4 -> module6 -> eval` 的消费范围。

动机：

- 把 THEIA 后半段输入先收窄到可控集合，再谈链条和 claim 修复。

实验效果：

- 指标：
  - `confirmed_window_recall = 0.6666666666666666`
  - `strict_tactic_recall_macro = 0.48888888888888893`
  - `strict_tactic_precision_macro = 0.8333333333333333`
  - `off_window_high_risk_rate = 0.05785123966942149`
- 噪声显著下降。

成功原因：

- 它没有试图“修攻击语义”，而是先把输入范围控制住。
- 这是典型的“先修实验入口，再修规则”的成功例子。

结论：

- 成功。
- 这是 THEIA 主跑的必要前置策略。

### 5.6 `replay_from_module3_e3gt_plus240_20260624`

数据集：

- TRACE

修改内容：

- 使用 enriched GT 和 `+240` 偏移重放后半段。
- 重点是统一 GT 口径，不额外引入新的链条语义。

动机：

- 先获得一条稳定、可复用、和新攻击报告一致的 TRACE 回归基线。

实验效果：

- 指标：
  - `confirmed_window_recall = 0.5`
  - `strict_tactic_recall_macro = 0.3875`
  - `strict_tactic_precision_macro = 1.0`
  - `off_window_high_risk_rate = 0.0`

结论：

- 成功。
- 这是后续 TRACE 每一步优化的统一对照线。

### 5.7 `step1_privfollow_20260624`

数据集：

- TRACE
- THEIA

修改内容：

- 尝试补“privilege follow-up”语义。
- 目标是让后半段更容易承接 `payload_elevate` / `PRIVILEGE_ESCALATION` 类链条。

动机：

- 重点针对 `THEIA_20180410_1341_1455_01` 缺 `PRIVILEGE_ESCALATION`。

实验效果：

- TRACE 指标和基线完全一致。
- THEIA 指标和 `windowgate` 基线完全一致。
- 关键窗口没有变化：
  - `THEIA_20180410_1341_1455_01` 仍然漏 `PRIVILEGE_ESCALATION`
  - `THEIA_20180410_1342_1342_02` 仍然是“漏 `CREDENTIAL_ACCESS`、多 `COMMAND_AND_CONTROL`”

失败原因：

- 这一步没有真正让 candidate path 或 dossier 稳定看到足够强的 privilege follow-up 信号。
- 说明问题不只是在“后段有没有一个 privilege 原子”，更可能在：
  - 上游链条没有保住相应语义
  - 或 dossier 没把关键证据带下来

结论：

- 未生效。
- 保留为诊断参考，不作为稳定线。

### 5.8 `step2b_browsercredguard_20260624`

数据集：

- TRACE
- THEIA

修改内容：

主要改在 `module6_attack_reason.py`，引入浏览器 / 邮件凭据上下文保护：

- `_BROWSER_CREDENTIAL_PROCESS_MARKERS`
- `_BROWSER_CREDENTIAL_ALLOWED_TACTICS`
- `_claim_behavior_types(...)`
- `_browser_credential_submit_context(...)`
- `_prune_attack_candidates_for_claim_context(...)`

规则核心是：

- 如果当前 dossier / claims 明显处于浏览器、邮件、凭据提交上下文
- 那么在 `tactics_only` 模式下，把候选战术收窄到：
  - `TA0001`
  - `TA0002`
  - `TA0006`

动机：

- 修 `THEIA_20180410_1342_1342_02` 被 browser tail 拉成 `COMMAND_AND_CONTROL` 的问题。

实验效果：

- THEIA：
  - `THEIA_20180410_1342_1342_02` 从“漏 `CREDENTIAL_ACCESS`、多 `COMMAND_AND_CONTROL`”
  - 变成“`INITIAL_ACCESS, EXECUTION, CREDENTIAL_ACCESS` 全命中，且无误报”
- TRACE：
  - 指标基本不变，没有副作用
- THEIA 整体指标提升到：
  - `confirmed_window_recall = 0.6666666666666666`
  - `strict_tactic_recall_macro = 0.6`
  - `strict_tactic_precision_macro = 0.9`
  - `off_window_high_risk_rate = 0.05785123966942149`

成功原因：

- 这不是全局压某类上下文，而是在非常窄的浏览器 / 邮件凭据提交场景下约束候选战术。
- 约束位置在 `module6`，没有破坏前面已经恢复好的链条。

副作用：

- `THEIA_20180410_1341_1455_01` 仍然漏 `PRIVILEGE_ESCALATION`。
- 同时还多报了 `CREDENTIAL_ACCESS`。

结论：

- 成功。
- 这是当前稳定基线的一部分。

### 5.9 `step2c_followuptimeline_20260624`

数据集：

- TRACE
- THEIA

修改内容：

- 放宽 dossier 时间线。
- 把更多 precursor / followup 事件塞给后段。

动机：

- 想补“链条已经抓到，但时间线展示不完整”的问题。

实验效果：

- TRACE 精度明显下降。
- THEIA `off_window_high_risk_rate` 上升。
- 还引入了额外噪声战术。

失败原因：

- 这一步扩大了后段解释空间，但没有真正修复前面的 claim 或 family 判断。
- 等于把更多尾部噪声喂给 LLM。

结论：

- 失败。
- 后续不应再用“单纯扩 dossier 时间线”来补语义。

### 5.10 `step2d_clearlogsfallback_20260624`

数据集：

- TRACE
- THEIA

修改内容：

- 用 `cleanup_delete` family、`followup_event_ids`、cleanup lineage 等弱信号回退补 `clear_logs`。

动机：

- 重点想补 `TRACE_20180413_1243_1253_04` 缺 `DEFENSE_EVASION`。

实验效果：

- TRACE 的确给 `TRACE_20180413_1243_1253_04` 补出了 `DEFENSE_EVASION`。
- 但 THEIA 明显恶化，很多窗口被错误污染上 `DEFENSE_EVASION`。

失败原因：

- 这是典型的“为了补一个窗口，加入跨数据集污染的宽 fallback”。
- `clear_logs` 不能靠宽松 followup / cleanup 反推。

结论：

- 失败。
- 这是后续设计里必须反复避免的反例。

### 5.11 `step2e_narrowcleanup_20260624`

数据集：

- TRACE
- THEIA

修改内容：

- 在 `step2d` 基础上把 `clear_logs` fallback 缩窄到显式 temp / log 路径。

动机：

- 想保留 TRACE 的 `DEFENSE_EVASION` 收益，同时压掉 THEIA 上的副作用。

实验效果：

- THEIA 基本回到稳定线。
- 但 TRACE 仍然是“补出 `DEFENSE_EVASION`，同时丢掉 `DISCOVERY`”。

失败原因：

- 它比 `step2d` 安全，但本质问题没解决：
  - 还是在 claim 层用 fallback 去替代真实 cleanup 证据
  - 导致 tactic 层出现替换效应

结论：

- 失败。
- 不满足“不能伤害现有已命中 GT tactic”的门槛。

### 5.12 `step4a_discoverysupplement_20260624`

数据集：

- TRACE
- THEIA

修改内容：

- 在 `tactics_only` 下，如果候选战术里已经有 `TA0007`，但最终 mapping 里没有，就尝试从 discovery claim 补 `DISCOVERY`。

动机：

- 针对 `TRACE_20180413_1350_1428_05`：
  - `candidate_tactics_union_top_n` 里有 `DISCOVERY`
  - 但最终 `predicted_tactics_union_top_n` 里没有

实验效果：

- THEIA 基本没变。
- TRACE 也没有实质改善。

失败原因：

- 说明问题不只是“最后 mapping 少补了一下”。
- 更大概率是更早的 claim、path、family 语义本身就没有稳定保住 `DISCOVERY`。

结论：

- 失败。
- 证明“末端补 tactic”通常救不了前面 claim 本身不稳的问题。

### 5.13 `step3a_payloadclonepriv_20260625`

数据集：

- THEIA 主跑
- TRACE 回归

修改内容：

- 在 `chain_semantics.py` 中增强 staged payload 路径收集。
- 尝试根据 `raw_event.properties.map.cmdLine` 和后续 clone 关系，补 `payload_elevate` / `PRIVILEGE_ESCALATION` 线索。
- 新增了针对 clone follow-up 的测试样例。

动机：

- 继续补 `THEIA_20180410_1341_1455_01` 缺 `PRIVILEGE_ESCALATION`。

实验效果：

- 总指标与 `step2b_browsercredguard` 完全一致。
- 关键窗口没有变化：
  - `THEIA_20180410_1341_1455_01` 仍然漏 `PRIVILEGE_ESCALATION`
  - 仍然多报 `CREDENTIAL_ACCESS`
- `THEIA_20180410_1342_1342_02` 保持正确。

失败原因：

- 这次不是“规则表达有问题”，而是“证据根本没进入 claim 生成入口”。
- 进一步排查发现：
  - `build_path_dossier(...)` 生成的 `evidence_timeline` 没有保留 `raw_event`
  - 后续 claim 生成看不到 `cmdLine` 这样的原始字段
- 所以即使上游 helper 能从原始事件里抽路径，后面真正跑 claim 时也拿不到这条线索。

结论：

- 失败 / 未生效。
- 但诊断价值很高，因为它明确暴露出：
  - 如果后续还想补 `PRIVILEGE_ESCALATION`，需要先把最小必要的 `cmdline` / payload path hint 带进 dossier 或 candidate path，而不是只在 helper 层加规则。

### 5.14 `step4m_windowcontinuation_20260626`

数据集：

- THEIA
- TRACE

修改内容：

- 只改 evaluator，不改 `module4/module5/module6` 主逻辑。
- 在 `src/apt_fusion/evaluation/path_reason_eval.py` 中新增一条非常窄的窗口续接规则：
  - 如果某条 path 原本被判为 `OFF_WINDOW`
  - 但它和同一 `task_id` 下某条 `CONFIRMED_MATCH` path 共享核心进程链或桥接对象
  - 且它的战术集合是锚定 path 战术集合的子集
  - 并且它只是紧跟 confirmed 窗口后的同任务尾段
  - 那么把它重标为 `CONFIRMED_CONTINUATION`
- 这条续接规则只用于：
  - 消除“同一恶意任务的尾段被算成离窗高风险”的假阳性
  - 不允许它抬高窗口召回
  - 不允许它扩大战术并集
- 同步补了 `tests/test_path_reason_eval.py` 中对应的 evaluator 单测。

动机：

- THEIA 当前稳定线里，`task_3099` 下有两条高风险 path 被打成了 `OFF_WINDOW`。
- 但进一步检查后发现，它们并不是新的误报链，而是同一 confirmed 恶意任务的后缀 continuation。
- 如果继续把它们算作 `off_window_high_risk`，会虚高 THEIA 的窗口外噪声。

实验效果：

- THEIA：
  - 基线：`step4l_concretecleanupdossierpatch_20260626`
  - 新线：`step4m_windowcontinuation_20260626`
  - 指标变化：
    - `confirmed_window_recall`：不变，仍为 `0.6666666666666666`
    - `strict_tactic_recall_macro`：不变，仍为 `0.6666666666666666`
    - `strict_tactic_precision_macro`：不变，仍为 `1.0`
    - `off_window_high_risk_rate`：从 `0.01652892561983471` 降到 `0.0`
  - 关键窗口战术结果不变：
    - `THEIA_20180410_1342_1342_02` 继续全命中、无误报
    - `THEIA_20180410_1341_1455_01` 继续全命中、无误报
    - `THEIA_20180412_1244_1326_03` 仍然整窗全漏
- TRACE：
  - 只重跑 evaluator 做回归
  - `confirmed_window_recall / strict_tactic_recall_macro / strict_tactic_precision_macro / off_window_high_risk_rate` 全部不变

成功原因：

- 这一步没有去“补 claim”或“补战术”，只是把同一任务内已经确认的恶意后续尾段从离窗噪声里剥离出来。
- 它解决的是评估归属问题，不是语义识别问题，因此风险很低。

结论：

- 成功。
- 可以把 `step4m_windowcontinuation_20260626` 视为新的 THEIA/TRACE 稳定 evaluator 基线。
- 但它没有解决 `THEIA_20180412_1244_1326_03` 的根本缺失。

### 5.15 THEIA alias 过度合并诊断（Step 3A）

数据集：

- THEIA

修改内容：

- 不改主流程规则，只做诊断。
- 新增并运行了 `debug/remote_ops/analyze_theia_alias_epoch_20260625.py`，检查 THEIA 当前 `(parent_uuid, tgid, normalized_path)` subject alias 键是否存在严重过度合并。
- 统计维度包括：
  - `uuid_count`
  - `span_minutes`
  - `file_count`
  - `task_ids_hit`
  - `window_ids_hit`
  - 是否覆盖 non-overlap GT 任务

动机：

- 当时怀疑 THEIA 有 201 张 GT-positive base task，但只有少数落进 confirmed 攻击窗口，可能是 subject alias 合并过宽，把本来应该分开的攻击阶段粘在了一起。

实验效果：

- 诊断结果输出在：
  - `debug/remote_ops/out/theia_alias_epoch_diag_step12_20260625/theia_alias_epoch_diagnostics.json`
- 关键结论：
  - `wide_key_count = 38`
  - `nonoverlap_task_fraction_hit_by_wide_key = 0.0112`
  - `top20_wide_key_task_coverage_fraction = 0.0112`
  - `step3b_recommended = false`

失败原因 / 结论原因：

- 这里不是“实验失败”，而是“诊断排除了一条假设”。
- 虽然确实存在少数跨度非常大的 wide key，但它们几乎没有覆盖当前绝大多数不落窗 GT 任务。
- 因此：
  - THEIA GT 任务大量不落窗，主因不是 alias 过度合并
  - 没必要继续优先推进 `theia_subject_alias_mode=epoch_bounded`

结论：

- 成功完成诊断。
- `Step 3B alias epoch 修复` 当前不推荐继续做。

### 5.16 `step4_temporalsplit_retry_20260626`

数据集：

- THEIA

修改内容：

- 继续尝试从任务图形成层解决 THEIA 大量 GT-positive task 不落窗的问题。
- 启用 THEIA 专用 temporal split：
  - `task_component_theia_temporal_split_enabled = true`
  - `task_component_theia_max_span_minutes = 45`
  - `task_component_theia_branch_gap_minutes = 10`
- 先只跑：
  - `module1 -> module3 -> overlap diagnostics`
- 没有直接推进到完整后半段，因为先要确认它是否真的改善“落窗”。

动机：

- `THEIA_20180412_1244_1326_03` 一直没有 overlap task。
- 之前的诊断表明，大量 non-overlap task 更像是“shared_gt_node_cross_window”或“长寿命上下文粘连”，所以尝试再切细一些。

实验效果：

- temporal split 后：
  - `task_count` 从 `8223` 增加到 `8486`
  - `2018-04-10` 两个 confirmed 窗口的按恶意 subject 节点可对上的任务图数量变化为：
    - `THEIA_20180410_1341_1455_01`：`13 -> 14`
    - `THEIA_20180410_1342_1342_02`：`15 -> 15`
  - 但关键窗口：
    - `THEIA_20180412_1244_1326_03`：仍然是 `0 -> 0`
- 此外，这轮 `module3` 长跑没有必要继续保留，于是只保留了结论，删除了大产物。

失败原因：

- 这一步只在“任务图边界更细”这一层带来了一点局部变化，但没有触及真正的瓶颈窗口。
- 说明 `2018-04-12` 的缺失并不是简单的“component 跨度太大、切得不够细”。

结论：

- 失败。
- 失败产物已按失败实验处理并清理：
  - 只保留小型诊断结果
  - 大型 partial artifact 已删除
- 后续不应继续把时间感知切图当作 `THEIA_20180412_1244_1326_03` 的主修方向。

### 5.17 THEIA `20180412` 原始日志观测项定点诊断与 offset sweep

数据集：

- THEIA

修改内容：

- 针对 `THEIA_20180412_1244_1326_03` 单独做了两层只读核查：
  1. `observable probe`
     - 直接按 enriched GT 里的 `explicit_observables` 去当前 THEIA 解析链路中搜
     - 观测项包括：
       - 进程名：`firefox`、`drakon`、`micro`、`sshd`、`loaderdrakon`
       - 文件：`/var/log/xdev`、`/var/log/wdev`、`/tmp/memtrace.so`、`/var/log/mail`
       - 外连：`149.52.198.23`、`146.153.68.151`、`104.228.117.212`、`141.43.176.203`
       - 行为锚点：`whoami`、`ps`、`putfile`、`inject`、`elevate`
  2. `offset sweep`
     - 新增脚本：
       - [analyze_theia_window_observable_offset_sweep_20260626.py](/D:/daima/APT-Fusionstep2b1/debug/remote_ops/analyze_theia_window_observable_offset_sweep_20260626.py)
     - 在 `-360` 到 `+600` 分钟范围内，每 `30` 分钟扫一遍
     - 目的不是再“猜新偏移”，而是排除“也许不是 +240，而是别的固定时间差”这个假设

动机：

- 前面已经看到：
  - 这个窗口没有 overlap task
  - temporal split 也救不回来
- 因此必须先判断：
  - 是原始日志里就没有这些行为
  - 还是日志里有，但当前偏移不对
  - 还是日志里有，但 GT UUID 名单对不上

实验效果：

- `observable probe` 结果：
  - `matched_event_count = 0`
  - `matched_subject_uuid_count = 0`
  - `matched_object_uuid_count = 0`
  - 所有关键观测项命中全为 `0`
- `offset sweep` 结果：
  - 从 `-360` 到 `+600` 分钟的所有 offset
  - 命中计数全部为 `0`
- 相关输出保留为小文件：
  - `debug/remote_ops/out/theia_20180412_observable_probe_20260626.json`
  - `debug/remote_ops/out/theia_window_observable_offset_sweep_20260626/THEIA_20180412_1244_1326_03_offset_sweep.json`

失败原因 / 诊断结论：

- 这里同样不是“实验失败”，而是“把一个方向彻底排除掉”。
- 这一步说明：
  - `THEIA_20180412_1244_1326_03` 的问题不是简单的 `+240` 偏移错了
  - 甚至不是换成别的固定分钟偏移就能解决
  - 在当前手头这份 THEIA 原始日志、当前解析链路和当前 GT 名单口径下，这个窗口的报告观测项整体都没有落点

结论：

- 成功完成诊断。
- 后续如果还要继续处理 `THEIA_20180412_1244_1326_03`，优先级应改为：
  - 先做“原始 THEIA 源文件级核对”
  - 确认这段攻击在我们手头日志里到底是否存在
  - 再决定是修 parser / GT 对齐，还是把该窗口标记为当前数据条件下不可对齐
- 在此之前，不应继续把它当作 `module5/module6` 链条语义优化目标。

### 5.18 `step12_dropfix_pathfix_20260625`

数据集：

- THEIA 主跑
- TRACE 回归

修改内容：

- 修 `vendor/tapas/darpa.py` 中 THEIA `filters(...)` 的 `subjhistory` 首条事件丢失问题。
- 修 `src/apt_fusion/path_reason/log_stream.py` 中 THEIA `FileObject` 对嵌套路径字段的提取：
  - 新增对 `baseObject.properties.map.filename`
  - 以及 `baseObject.properties.map.path`
    的 fallback。

动机：

- 这是两处最像“真实 bug / 真实解析缺口”的点。
- 它们的目标不是直接抬高 tactic 分数，而是先把：
  - THEIA 任务切图前的 subject history
  - THEIA 后半段证据图里的文件对象路径
    纠正到和原始日志结构更一致。

实验效果：

- 没有带来决定性的落窗提升。
- 但它清掉了一个确定性 bug，并让 THEIA 后半段对象路径语义不再明显错位。
- THEIA / TRACE 后半段指标没有出现明显回退。
- 后续 `Step 3A alias 诊断`、`temporal split retry`、`2018-04-12 observable probe` 都以它作为解析修正后的共同基线。

结论：

- 相对成功。
- 它更像“修基建、修解析一致性”的成功，而不是“直接提升窗口战术指标”的成功。
- 后续如果再审查 THEIA 上游任务图或对象语义，默认都应从这条修正后的版本继续出发。

### 5.19 2026-06-26 之后的稳定基线修订说明

这轮整理后，文档中的“当前稳定基线”需要做两点统一修订：

- TRACE 稳定线不再停留在 `step2b_browsercredguard_20260624`，而是更新为：
  - `step4m_windowcontinuation_20260626`
- THEIA 稳定线也不再停留在 `step2b_browsercredguard_20260624`，而是更新为：
  - `step4m_windowcontinuation_20260626`

原因是：

- `step4m` 没有改坏任何窗口级 tactic 结果。
- 它只修 evaluator 对“同一 confirmed 恶意任务尾段”的归属方式。
- 对 THEIA 来说，它把 `off_window_high_risk_rate` 从 `0.01652892561983471` 进一步压到 `0.0`。
- 对 TRACE 来说，它保持各项指标不变，因此是低风险、可接受的稳定补丁。

同时也要明确：

- `THEIA_20180412_1244_1326_03` 的缺失，当前不能再继续归咎于：
  - 简单固定时间偏移不对
  - alias 过度合并
  - temporal split 切得不够细
- 在现有日志、现有 GT 名单和现有解析链路下，它更像是一个“源日志 / 攻击报告 / GT 三者尚未对齐”的独立问题。
- 因此当前默认稳定线应当：
  - 保留 `THEIA_20180412_1244_1326_03` 为未解决窗口
  - 但不要再为了它继续扰动整条 TRACE/THEIA 稳定后半段基线
  - 真要继续处理它，应另开“源日志级对齐”方向，而不是继续在 `module5/module6` 上硬补。

## 6. 跨实验共识

### 6.1 先修链条语义，比先做全局 benign/service 抑制更重要

多次实验都说明：

- 普通 `chmod`
- 服务对象读取
- browser / mail tail
- 泛外连 / 收发

如果先在前面被错误拼成 precursor、initial exec、sensitive read、C2 等语义，后面再做全局服务抑制，通常只会变成高副作用补丁。

### 6.2 `clear_logs` / `DEFENSE_EVASION` 不能靠宽 fallback 硬补

`step2d` 和 `step2e` 已经说明：

- TRACE 某个窗口的 `DEFENSE_EVASION` 缺失，不能靠宽松 fallback 直接补
- 否则很容易污染 THEIA 或替换掉原本正确的 tactic

后续如果还要继续补 `DEFENSE_EVASION`，优先应从下面几类证据去做：

- 更真实的 cleanup 对象语义
- 更明确的 log / temp / staged lineage
- 更稳定的 claim 形成

### 6.3 如果 claim 本身不稳，末端 mapping 打补丁通常没用

`step4a_discoverysupplement` 证明：

- 即使候选战术里已经有某个 tactic
- 只要上游 claim / family / path 本身没有稳定保住对应攻击行为
- 仅在最终 mapping 末端补 tactic，往往效果有限

### 6.4 对象角色传播仍有潜力，但属于更重的一步

`step3_objecttransfer` 说明：

- 对象角色语义不是空想法
- 它确实能更自然地区分：
  - 系统服务对象 vs 真实敏感对象
  - 普通 `chmod` vs staged exec 对象

但当前稳定线还没有把这套能力做成真正可靠、持续启用的上游产物。因此后续如果再做，应作为单独一步推进，并单独评估收益和副作用。

### 6.5 若要补 `PRIVILEGE_ESCALATION`，需要保留更原始的路径 / 命令证据

`step1_privfollow` 和 `step3a_payloadclonepriv` 共同说明：

- 仅在 claim helper 层加规则不够
- 如果 dossier / candidate path 看不到原始 `cmdline`、payload 路径、root 重执行这类线索
- 后段永远无法稳定生成 `payload_elevate`

因此后续若继续攻这个点，优先方向应该是：

- 在 `module5` 或 `path_report` 中保留最小必要的 payload path / cmdline hint
- 再让 claim 生成消费这些 hint

## 7. 当前推荐继续出发的稳定组合

当前继续往后优化时，建议固定从下面这条组合基线出发：

- THEIA：
  - artifact：
    - `artifacts_theia_train_stats_latefusion_llama31_microstep2b_module1_gtbase_tactics_only_llm_fanout_gt2_e3gt_windowgate_step4m_windowcontinuation_offset240_20260626`
  - 语义组成：
    - `window-gate first`
    - `step2b_browsercredguard`
    - `step4l_concretecleanupdossierpatch`
    - `step4m_windowcontinuation`
- TRACE：
  - artifact：
    - `artifacts_trace_train_stats_latefusion_bonus1_microstep2b_truthgap_tactics_only_llm_worktree_step4m_windowcontinuation_e3gt_plus240_gtonly_20260626`
  - 语义组成：
    - `truthgap replay`
    - `step2b_browsercredguard`
    - `step4l_concretecleanupdossierpatch`
    - `step4m_windowcontinuation`

也就是说，当前默认稳定线就是：

- `window-gate first`
- TRACE / THEIA 都统一切到 enriched GT，并显式应用 `+240`
- `cleanup dossier` 已走到 `step4l`
- evaluator 采用 `step4m_windowcontinuation`
- 不启用 `step2c / step2d / step2e / step4a / temporal split`
- 不恢复 `servicectx`
- 不默认启用真正的对象角色传播
- `THEIA_20180412_1244_1326_03` 暂时按“源日志 / GT 对齐未解”单独挂起，不再拿它扰动整条稳定基线

## 8. 后续优化建议

后续再写新的优化方案时，建议优先按下面顺序推进：

1. 先做逐窗口、逐行为、逐规则归因
2. 先修前因链、初始执行链、C2、敏感读 / 外发、cleanup 的 claim 形成
3. 如果 claim 和链条都已经对了，但战术仍漏，再看 mapping / validation
4. 如果反复发现对象语义是主瓶颈，再单独推进真正的对象角色标签赋值与传播
5. 对 THEIA `20180412` 这类窗口，先做原始日志 / 报告 / GT 对齐核实；在确认日志里确实有对应行为前，不要继续把它当作链条语义问题硬补

不建议优先做：

- 全局 benign service context 抑制
- 宽 fallback 式的 `clear_logs`
- 只在最终 mapping 末端做战术补丁

## 9. 产物与命名注意事项

- 所有失败实验的 artifact 和 compare 输出目录，都应显式带 `_failed_`。
- 不要覆盖当前稳定基线产物。
- 清理失败实验时要注意：
  - 不能误删被稳定线复用的目录
  - 不能删掉被软链接引用的 `module5_paths` 或其他上游快照
- 若实验中途终止，也应在文档和产物命名里明确标注“中止 / 未生效 / 失败”的原因。

## 10. 2026-06-27 新增记录

### 10.1 代码与同步状态

- 本地仓库 `D:\daima\APT-Fusionstep2b1` 已新增一次明确检查点提交：
  - `7de769e feat: checkpoint theia-trace e3gt windowgate step4m baselines and upstream diagnostics`
- 该提交已经成功写入本地 git 历史。
- 同时，当前源码快照已经通过 `pscp + tar` 的方式同步到云端：
  - 远端源码目录：`/root/autodl-tmp/APT-Fusionstep2b1`
- 这次同步后的云端源码可视为“本地当前版本”的可执行副本。

### 10.2 GitHub 推送现状

- 这次没有完成 GitHub 推送。
- 结论不是代码问题，而是当前机器缺少可直接复用的 GitHub 凭据：
  - 远端地址是 `https://github.com/shizhuo-cmd/aptfusionstep2b1.git`
  - 本机 `credential.helper=manager`
  - 本机没有 `gh` 登录
  - 本机 `~/.ssh` 下也没有 GitHub 私钥，只有 `config` 和 `known_hosts`
- 因此当前状态应记为：
  - `本地提交成功`
  - `云端源码同步成功`
  - `GitHub 推送未完成，原因是凭据缺失`

### 10.3 云端失败产物清理

- 已在云端清理 `/root/autodl-tmp/APT-Fusionstep2b1` 下名称带 `*_failed_*` 的失败实验目录。
- 这一步的目的：
  - 降低磁盘占用
  - 避免后续继续把失败产物误认成稳定基线
- 清理策略：
  - 只删显式失败目录
  - 不动当前稳定基线
  - 不动仍会被后续 replay 复用的上游快照

### 10.4 THEIA 3.11 上游数据核对

本轮重新执行了 THEIA 3.11 对应窗口的原始日志核对：

- 目标窗口：
  - `THEIA_20180412_1244_1326_03`
- 对照方式：
  - 直接按 enriched GT 的窗口定义
  - 分别对 `offset=0` 和 `offset=+240`
  - 在原始日志里搜索报告可观察项与 GT 节点相关事件
- 结果：
  - 在已经测试的固定偏移范围内，这个窗口都没有观测到有效命中
  - `offset=0` 和 `offset=+240` 都不是有效对齐方式
- 当前结论：
  - `THEIA_20180412_1244_1326_03` 仍应优先归因到 `源日志 / GT / 报告对齐未解`
  - 不能把它继续当成“仅靠链条语义就能修好”的后半段问题

### 10.5 TRACE 原始日志切换与零战术窗口核对

数据准备动作：

- 已删除云端展开后的 THEIA 原始日志目录
- 已解压 TRACE 原始日志归档
- 使用当前版本代码与 `+240` 偏移口径，对 TRACE 中“完全没有检测出战术”的窗口做原始日志 GT UUID 核对

当前核对的零战术窗口：

- `TRACE_20180410_0946_1109_01`
- `TRACE_20180410_1228_1230_02`
- `TRACE_20180412_1336_1336_03`

核对结果：

- 这 3 个窗口在 `+240` 后，`subject/process` 命中仍为 `0`
- `any_role` 命中也为 `0`
- 即：在当前 GT UUID 名单与当前日志解析口径下，这 3 个窗口在原始日志层面就没有打到对应 GT UUID

结论：

- 这 3 个 TRACE 零战术窗口，不是单纯 `module5/module6` 没识别出来
- 更像是更前面的 `GT 节点名单 / 窗口时间 / 原始日志可观察性` 本身就没有对上
- 因此当前不应直接把它们归因成链条语义或 tactic mapping 的失败

### 10.6 CADETS 直跑：绕过 module2，仅用 GT 命中的 base task

本轮新增了一条 CADETS 专用直跑线：

- 配置语义：
  - `module1 -> module3 -> module4 -> module5 -> module6 -> eval`
  - 不走 `module2` 恶意图检测筛选
  - 任务选择方式改为 `module1_ground_truth_positive_base_only`
  - `fanout > 2`
  - `exclude_segmented`
  - evaluator 使用 enriched GT，并显式应用 `+240`
- 产物目录：
  - `artifacts_cadets_train_stats_latefusion_llama31_microstep2b_module1_gtbase_tactics_only_llm_fanout_gt2_e3gt_plus240_20260627`

指标：

- `confirmed_window_recall = 0.5`
- `strict_tactic_recall_macro = 0.09166666666666667`
- `strict_tactic_precision_macro = 1.0`
- `off_window_high_risk_rate = 0.9375`

结论：

- 这条线能把后半段跑通，但整体噪声仍很高
- 两个窗口仍然完全没有 primary-time matched path：
  - `CADETS_20180406_1121_1208_01`
  - `CADETS_20180411_1508_1515_02`

### 10.7 CADETS 零战术窗口上游核对

对上面两个 CADETS 零战术窗口，再做了一轮原始日志核对：

- 对照窗口：
  - `CADETS_20180406_1121_1208_01`
  - `CADETS_20180411_1508_1515_02`
- 对照方式：
  - `offset=0`
  - `offset=+240`
  - 同时看 `subject/process` 命中和 `any_role` 命中

结果非常一致：

- 两个窗口在 `offset=0` 和 `offset=+240` 下：
  - `subject/process hit = 0`
  - `any_role hit = 7`
- 这 7 个 UUID 全都只出现在 `object-side`，不出现在 `subject/process-side`
- 高频动作主要是：
  - `MMAP`
  - `OPEN`
  - `CLOSE`
  - `READ`
  - 少量 `EXECUTE`

当前结论：

- 这两个 CADETS 零战术窗口并不是“完全没有 GT 命中”
- 但它们命中的更像是恶意对象 / 恶意对象侧 UUID，而不是活跃恶意进程 UUID
- 因此如果当前主线主要靠进程图、证据图中的进程链条来承接攻击语义，就天然会对这两个窗口不友好
- 这也再次说明：
  - CADETS 某些窗口的主瓶颈并不只是 tactic 识别
  - 还包括 `GT 名单角色语义`、`对象侧命中如何进入链条`、以及 `进程优先主线` 的表达上限

### 10.8 这轮实验的主要用途与后续意义

这轮 2026-06-27 的工作，主要不是为了直接抬高指标，而是为了把“零战术窗口”的问题分层拆清楚：

- THEIA 3.11：
  - 更像 `日志 / GT / 报告对齐` 问题
- TRACE 三个零战术窗口：
  - 当前口径下，原始日志层面就没有命中 GT UUID
- CADETS 两个零战术窗口：
  - 命中集中在 `object-side`，而不是 `subject/process-side`

因此后续优化时应避免把这些窗口一股脑归因成“后半段规则不够好”。更合理的下一步方向是：

1. 先把“窗口没有 GT 进程命中”与“窗口有对象命中但没有进程命中”分开处理。
2. 对 CADETS 这类 `object-side only` 窗口，评估是否需要把对象证据更实质地接进链条，而不是继续只靠进程主线。
3. 对 TRACE / THEIA 那些原始日志层面就没有 GT 命中的窗口，优先做 GT 对齐、报告对齐和日志可观察性复核，不应直接推进 claim 或 tactic mapping 修补。
