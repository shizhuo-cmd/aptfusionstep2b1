# APT-Fusion 检测粒度与指标计算规范：基于 DARPA 官方攻击文档的时间窗、攻击路径与 ATT&CK 评估标准

## 0. 文档目的

本文档用于统一 APT-Fusion 新后半段方案的：

1. 检测粒度定义
2. ground truth 粒度定义
3. 候选攻击路径与官方攻击文档的匹配规则
4. 时间粒度、攻击链粒度、ATT&CK 技术粒度的指标计算方法

本文档是给“另一个窗口负责计算指标”的实现规范，不是研究性讨论。

---

## 1. 结论先行

### 1.1 最终检测粒度

检测粒度不应定义为：

```text
整台主机一天一条完整攻击链
```

也不应定义为：

```text
单条原始日志事件
```

推荐定义为：

```text
host + attack_window + candidate_path
```

即：

1. `host`：主机维度
2. `attack_window`：官方报告给出的攻击时间窗
3. `candidate_path`：系统从日志中重建出的具体候选攻击子链

### 1.2 时间粒度

必须区分两种时间粒度：

1. `GT 时间粒度`
   - 由 DARPA 官方报告给出
   - 通常是分钟级窗口
   - 不是秒级 ground truth

2. `系统检测时间粒度`
   - 由日志中实际事件时间决定
   - 可以精确到秒级

结论：

```text
系统输出可以精确到秒级；
评估时应按“是否落在官方窗口内/附近”判断，
而不是要求与官方文档秒级完全一致。
```

### 1.3 攻击链粒度

必须允许：

```text
一个官方攻击窗口
对应多条系统候选路径
```

原因：

1. 官方文档中的一个时间窗往往包含多步行为
2. 我们的新方案输出单位是“候选路径”，不是“整窗完整链”
3. 一个窗口里可能同时出现：
   - Entry/Execution 子链
   - Download/Exec 子链
   - Discovery/Collection 子链
   - Cleanup/FollowUp 子链

因此：

```text
运行时检测单元 = candidate_path
评估单元 = attack_window
ATT&CK 汇总单元 = attack_window 内匹配到的 path 集合
```

---

## 2. 数据来源与优先级

本规范使用两份外部文档作为 GT 来源：

1. 严格版：
   [ALL_HOSTS_ATTCK_STRICT_MAPPING.md](D:/download/ALL_HOSTS_ATTCK_STRICT_MAPPING.md)
2. 宽松汇总版：
   [ALL_HOSTS_ATTACK_ATTCK_MAPPING.md](D:/download/ALL_HOSTS_ATTACK_ATTCK_MAPPING.md)

优先级规则：

1. `严格版` 是主评估标准
2. `宽松版` 只用于辅助分析和上界参考

### 2.1 严格版用途

严格版用于：

1. `Confirmed` 技术 recall/precision
2. 官方攻击时间窗定义
3. Attempted/Failed 单独统计
4. 不强行映射行为的排除规则

### 2.2 宽松版用途

宽松版用于：

1. 召回上界参考
2. tactic 层面宽松对比
3. 解释“为什么系统看到了行为，但严格版不确认 technique”

### 2.3 不允许混用

主指标不允许：

1. 一部分 host 用严格版
2. 一部分 host 用宽松版

主报告必须统一以严格版为准。

---

## 3. Ground Truth 粒度定义

### 3.1 GT 基本单元

GT 单元定义为：

```text
HostAttackWindow
```

即每条官方攻击时间窗记录是一个独立评估单元。

### 3.2 GT JSON 规范

建议先把严格版 md 转成：

```text
gt_windows_strict.json
```

格式如下：

```json
[
  {
    "window_id": "TRACE_2018-04-13_1243_1253_01",
    "host": "TRACE",
    "source_doc": "ALL_HOSTS_ATTCK_STRICT_MAPPING.md",
    "source_ref": "§3.15 / Report Page 28-30",
    "status": "confirmed",
    "time_precision": "minute_window",
    "start_time": "2018-04-13T12:43:00",
    "end_time": "2018-04-13T12:53:00",
    "confirmed_techniques": ["T1203", "T1071.001", "T1057", "T1105", "T1046", "T1070.004"],
    "attempted_techniques": [],
    "confirmed_tactics": ["INITIAL_ACCESS", "EXECUTION", "COMMAND_AND_CONTROL", "DISCOVERY", "DEFENSE_EVASION"],
    "coarse_chain_tags": ["browser_compromise", "shell", "scan", "cleanup"],
    "notes": "strict mapping confirmed"
  }
]
```

### 3.3 `status` 定义

只允许：

```text
confirmed
attempted_failed
insufficient
```

含义：

1. `confirmed`
   - 主评估对象
2. `attempted_failed`
   - 不计入主成功 recall/precision
   - 单独算 attempted activity 指标
3. `insufficient`
   - 只作为背景，不参与主指标

### 3.4 `time_precision` 定义

只允许：

```text
minute_window
coarse_summary
date_only
unknown
```

主时间指标只使用：

```text
status = confirmed
and time_precision = minute_window
```

### 3.5 technique 集合来源

主 technique 集合只来自严格版中的 `确认映射`。

例如：

TRACE `2018-04-13 12:43-12:53` 的 confirmed technique 集合来自：
[ALL_HOSTS_ATTCK_STRICT_MAPPING.md](D:/download/ALL_HOSTS_ATTCK_STRICT_MAPPING.md:80)

不要把：

1. `Attempted`
2. `Not mapped`
3. 仅战术可见但 technique 不确认

混进主 GT technique 集合。

---

## 4. 系统预测粒度定义

### 4.1 运行时基本单元

系统运行时基本单元定义为：

```text
CandidatePath
```

它来自新方案中的 `module5_paths` 和 `module6_reason`。

### 4.2 预测 JSON 规范

建议评估窗口统一读取：

```text
predicted_paths.json
```

格式如下：

```json
[
  {
    "host": "TRACE",
    "task_id": "task_0558",
    "path_id": "task_0558_path_003",
    "risk_score": 91.4,
    "risk_level": "HIGH",
    "start_time": "2018-04-13T12:44:12",
    "end_time": "2018-04-13T12:49:03",
    "stage_coverage": ["Entry", "ExecutionStrong", "TargetAccess", "FollowUp"],
    "process_chain": ["P1", "P2", "P3"],
    "bridge_objects": ["/tmp/ztmp"],
    "predicted_tactics": ["INITIAL_ACCESS", "EXECUTION", "COMMAND_AND_CONTROL", "DISCOVERY"],
    "predicted_techniques": ["T1203", "T1071.001", "T1057", "T1046", "T1070.004"],
    "warnings": []
  }
]
```

### 4.3 预测层次

必须区分：

1. `pre-LLM path metrics`
   - 只看 path 时间、阶段、风险
2. `post-LLM ATT&CK metrics`
   - 额外看 predicted tactics/techniques

不能把两者混在一起算。

---

## 5. 时间匹配规则

这是本规范最重要的部分。

### 5.1 GT 窗口 padding

由于 DARPA 官方报告大多是分钟级窗口，评估时允许一个固定 padding：

```text
window_pad_before = 5 分钟
window_pad_after  = 5 分钟
```

定义：

```text
padded_window = [gt.start_time - 5m, gt.end_time + 5m]
```

### 5.2 路径时间量

对每条预测路径 `p` 定义：

```text
path_duration = max(1 second, p.end_time - p.start_time)
intersection_seconds = overlap(p.time_range, padded_window)
path_in_window_ratio = intersection_seconds / path_duration
path_midpoint = (p.start_time + p.end_time) / 2
midpoint_in_window = path_midpoint in padded_window
```

### 5.3 三档时间匹配

#### `strict_time_match`

满足任一：

1. `path_in_window_ratio >= 0.8`
2. 路径完全位于 `padded_window` 内

#### `primary_time_match`

满足以下全部：

1. `intersection_seconds > 0`
2. `path_in_window_ratio >= 0.5` 或 `midpoint_in_window = true`

#### `loose_time_match`

仅要求：

1. `intersection_seconds > 0`

### 5.4 `near_miss`

如果完全无重叠，但最近边界距离不超过：

```text
5 分钟
```

则记为：

```text
near_miss_time
```

`near_miss` 只用于误差分析，不计入主命中。

---

## 6. 路径与窗口的匹配策略

### 6.1 一对多允许

一个官方窗口可以匹配多条预测路径。

这是允许且预期的。

### 6.2 主匹配路径 `best_path`

为了计算时间定位误差，每个 GT window 需要选一个主匹配路径：

在同 host、且满足 `primary_time_match` 的路径中，按以下优先级排序：

1. `path_in_window_ratio` 更大
2. `risk_score` 更高
3. `|path_midpoint - gt_window_midpoint|` 更小

排第一的路径记为：

```text
best_path(window)
```

### 6.3 路径集合 `matched_path_set`

为了计算 technique/tactic recall，一个窗口不只看 `best_path`，而看：

```text
matched_path_set(window, N)
```

定义：

1. 同 host
2. 满足 `primary_time_match`
3. 按 `risk_score` 从高到低排序
4. 取前 `N` 条

默认：

```text
N = 5
```

理由：

一个官方窗口可能被系统拆成多条候选子链；
ATT&CK recall 应该允许这些子链的技术并集共同覆盖 GT。

### 6.4 预测路径归属

为了计算预测侧误报统计，每条路径需要归属到一个窗口：

规则：

1. 在同 host 的所有 `confirmed` GT window 中，找满足 `primary_time_match` 的候选窗口
2. 如果有多个，选 `path_in_window_ratio` 最大的一个
3. 若没有 confirmed 匹配，再尝试匹配 `attempted_failed`
4. 若仍没有，则记为：

```text
OFF_WINDOW
```

---

## 7. 攻击链粒度定义

### 7.1 运行时粒度

运行时输出的链粒度定义为：

```text
候选攻击子链
```

不是：

```text
整窗完整攻击剧本
```

### 7.2 评估粒度

攻击链评估单元是：

```text
GT attack window
```

但链条语义来源于：

```text
matched_path_set(window)
```

### 7.3 允许拆链

以下情况都允许：

1. 一个 GT window 对应 2~5 条预测 path
2. 一条 path 只覆盖其中一段行为
3. technique recall 由这些 path 的并集提供

### 7.4 不允许跨窗强拼

如果两条 path 分别对应两个不相邻官方时间窗，不允许为了提高 recall 人工拼成一条“超长主机链”。

---

## 8. 主指标定义

分两层：

1. `路径/时间层指标`
2. `ATT&CK 映射层指标`

---

## 9. 路径/时间层指标

### 9.1 `ConfirmedWindowRecall`

定义：

对所有：

```text
status = confirmed
and time_precision = minute_window
```

的 GT window，若存在至少一条预测 path 满足 `primary_time_match`，则记为 hit。

公式：

```text
ConfirmedWindowRecall =
  hit_confirmed_windows / total_confirmed_windows
```

### 9.2 `StrictWindowRecall`

与上相同，但要求至少一条 path 满足 `strict_time_match`。

### 9.3 `HighRiskWindowRecall`

仅统计：

1. `primary_time_match`
2. 且 `risk_level = HIGH`

的 path 是否存在。

### 9.4 `AttemptWindowFlagRate`

对 `status = attempted_failed` 的 GT window：

若存在至少一条 `risk_level in {MEDIUM, HIGH}` 且满足 `loose_time_match` 的 path，则记为 flagged。

公式：

```text
AttemptWindowFlagRate =
  flagged_attempt_windows / total_attempt_windows
```

注意：

它是辅助指标，不算进主成功 recall。

### 9.5 `OffWindowHighRiskCount`

统计所有：

1. `risk_level = HIGH`
2. 最终归属 = `OFF_WINDOW`

的 path 数量。

该值越低越好。

### 9.6 `OffWindowHighRiskRate`

公式：

```text
OffWindowHighRiskRate =
  high_risk_off_window_paths / total_high_risk_paths
```

### 9.7 `TimeLocalizationMAE`

对每个 `best_path(window)`，计算：

```text
start_error_sec = abs(best_path.start_time - gt.start_time)
end_error_sec = abs(best_path.end_time - gt.end_time)
midpoint_error_sec = abs(best_path.midpoint - gt.midpoint)
```

报告：

1. `median_start_error_sec`
2. `median_end_error_sec`
3. `median_midpoint_error_sec`

### 9.8 `PathPurity`

对每个 `best_path(window)`：

```text
PathPurity = path_in_window_ratio
```

报告：

1. 平均值
2. 中位数

### 9.9 `WindowSplitFactor`

定义：

```text
WindowSplitFactor(window) =
  count(paths in matched_path_set(window, all))
```

报告：

1. 平均值
2. 中位数
3. `p95`

解释：

1. 太低：可能欠分解
2. 太高：可能过分解

---

## 10. ATT&CK 映射层指标

这些指标只在 `module6_reason` 之后计算。

### 10.1 `StrictTechniqueRecall`

对每个 confirmed GT window：

1. 取 `matched_path_set(window, N=5)` 的 `predicted_techniques` 并集
2. 与 GT 的 `confirmed_techniques` 比较

公式：

```text
StrictTechniqueRecall(window) =
  | PredTechniquesUnion(window) ∩ GTConfirmedTechniques(window) |
  / | GTConfirmedTechniques(window) |
```

报告：

1. macro average
2. micro average

### 10.2 `StrictTechniquePrecision`

仅对有 matched paths 的 confirmed GT window：

公式：

```text
StrictTechniquePrecision(window) =
  | PredTechniquesUnion(window) ∩ GTConfirmedTechniques(window) |
  / max(1, | PredTechniquesUnion(window) |)
```

注意：

1. 仅使用分配到 confirmed window 的 path
2. 归属到 attempted window 的 path 不纳入 strict precision 分母
3. `OFF_WINDOW` 高危 path 用 `OffWindowHighRiskRate` 单独衡量，不混进此 precision

### 10.3 `StrictTacticRecall`

计算方法与 technique recall 相同，但比较 tactic 集合。

### 10.4 `BroadTechniqueRecall`

这是辅助指标，不是主指标。

方法：

1. 使用宽松版 GT technique 集合
2. 其余规则不变

用途：

解释：

```text
系统看到了某些行为，
但严格版不确认 technique；
这些行为在宽松版里是否能被解释为“合理候选”。
```

### 10.5 `WindowFullCoverageRate`

对 confirmed GT window：

若 `matched_path_set(window, N=5)` 的 technique 并集完全覆盖 GT confirmed technique 集合，则记为 full-covered。

公式：

```text
WindowFullCoverageRate =
  full_covered_confirmed_windows / total_confirmed_windows
```

---

## 11. 成功、尝试、证据不足的处理规则

### 11.1 `confirmed`

参与：

1. 主时间指标
2. 主 ATT&CK recall/precision

### 11.2 `attempted_failed`

参与：

1. `AttemptWindowFlagRate`
2. 误报解释

不参与：

1. 主成功 recall
2. 主 strict precision

### 11.3 `insufficient`

不参与主指标。

只在分析报告里做背景说明。

---

## 12. 风险等级阈值建议

默认采用系统自身输出：

1. `HIGH`
2. `MEDIUM`
3. `LOW`

主评估建议：

1. `ConfirmedWindowRecall`：看 `MEDIUM + HIGH`
2. `HighRiskWindowRecall`：只看 `HIGH`
3. `OffWindowHighRiskCount`：只统计 `HIGH`

原因：

1. `MEDIUM` 适合 recall
2. `HIGH` 更接近实际报警质量

---

## 13. 推荐报告结构

评估窗口最终建议输出：

```text
metrics_summary.json
window_level_metrics.json
path_assignment.json
technique_comparison.json
```

### 13.1 `metrics_summary.json`

至少包含：

```json
{
  "confirmed_window_count": 0,
  "attempt_window_count": 0,
  "confirmed_window_recall": 0.0,
  "strict_window_recall": 0.0,
  "high_risk_window_recall": 0.0,
  "attempt_window_flag_rate": 0.0,
  "off_window_high_risk_count": 0,
  "off_window_high_risk_rate": 0.0,
  "median_start_error_sec": 0.0,
  "median_end_error_sec": 0.0,
  "median_midpoint_error_sec": 0.0,
  "mean_path_purity": 0.0,
  "median_path_purity": 0.0,
  "mean_window_split_factor": 0.0,
  "strict_technique_recall_macro": 0.0,
  "strict_technique_precision_macro": 0.0,
  "strict_tactic_recall_macro": 0.0,
  "broad_technique_recall_macro": 0.0,
  "window_full_coverage_rate": 0.0
}
```

### 13.2 `window_level_metrics.json`

每个 GT window 输出：

1. `best_path_id`
2. `matched_path_ids`
3. `time_match_type`
4. `path_purity`
5. `strict_technique_recall`
6. `strict_technique_precision`
7. `warnings`

### 13.3 `path_assignment.json`

每条 path 输出：

1. 归属到哪个 GT window
2. 是 `CONFIRMED_MATCH / ATTEMPT_MATCH / OFF_WINDOW`
3. `path_in_window_ratio`
4. `risk_level`

---

## 14. 例子：如何理解“可以精确到具体时间和攻击链条”

### 14.1 可以精确到的对象

系统输出可以精确到：

```text
2018-04-13 12:44:12 -> 12:49:03
TRACE
task_0558_path_003
nginx -> sh -> curl
/tmp/ztmp bridge
T1203/T1071.001/T1046 候选
```

这是“秒级路径输出”。

### 14.2 不能要求精确到的对象

官方严格版往往只给：

```text
2018-04-13 12:43-12:53
TRACE
T1203, T1071.001, T1057, T1105, T1046, T1070.004
```

见：
[ALL_HOSTS_ATTCK_STRICT_MAPPING.md](D:/download/ALL_HOSTS_ATTCK_STRICT_MAPPING.md:80)

因此评估时不应要求：

1. 秒级绝对一致
2. 一条 path 覆盖整窗所有 technique

正确要求是：

1. path 时间是否落在窗口中
2. path 集合是否覆盖该窗口的 confirmed techniques

---

## 15. 推荐给计算窗口的直接任务清单

```text
Task 1:
  将 ALL_HOSTS_ATTCK_STRICT_MAPPING.md 转成 gt_windows_strict.json。
  每个官方时间窗一条记录。

Task 2:
  可选地将 ALL_HOSTS_ATTACK_ATTCK_MAPPING.md 转成 gt_windows_broad.json。

Task 3:
  从 APT-Fusion 新链路输出中提取 predicted_paths.json。

Task 4:
  实现时间匹配函数：
    strict_time_match
    primary_time_match
    loose_time_match
    near_miss

Task 5:
  为每个 GT window 计算 best_path 和 matched_path_set(window, N=5)。

Task 6:
  计算路径/时间层指标：
    ConfirmedWindowRecall
    StrictWindowRecall
    HighRiskWindowRecall
    AttemptWindowFlagRate
    OffWindowHighRiskCount
    TimeLocalizationMAE
    PathPurity
    WindowSplitFactor

Task 7:
  计算 ATT&CK 层指标：
    StrictTechniqueRecall
    StrictTechniquePrecision
    StrictTacticRecall
    BroadTechniqueRecall
    WindowFullCoverageRate

Task 8:
  输出 metrics_summary.json、window_level_metrics.json、
  path_assignment.json、technique_comparison.json。
```

---

## 16. 最终原则

计算指标时必须始终遵守：

```text
1. 预测单元是 path，不是整窗；
2. 评估单元是官方 attack window；
3. 技术 recall 用 window 内 matched path 的并集计算；
4. Attempted/Failed 不纳入主成功指标；
5. 秒级路径输出可以有，但官方 GT 仍是分钟级窗口；
6. 不要求一条 path 覆盖整窗所有 technique；
7. 主报告以严格版 GT 为准，宽松版只作辅助对照。
```

这份文档即为后续“计算指标窗口”的唯一粒度与评估规范。
