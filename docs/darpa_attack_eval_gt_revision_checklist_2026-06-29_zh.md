# DARPA 攻击评估 GT 战术修订清单（2026-06-29）

## 目的

这份清单用于修订 `docs/darpa_attack_eval_ground_truth_e3_report_enriched_20260618.json` 中 `TRACE / CADETS / THEIA` 三个数据集的攻击窗口战术标注。

目标不是把窗口战术整体放宽到“看到一点苗头就算”，而是做三件事：

1. 保留当前 JSON 里已经正确的“成功链战术”。
2. 把原始 E3 报告中明确写出的、但当前 JSON 没有表达出来的失败型战术尝试，补到 `attempted_tactics / attempted_techniques`。
3. 只在原始报告有明确成功证据时，才扩展 `confirmed_tactics / confirmed_techniques`。

## 修订原则

1. `confirmed_tactics` 只记录“窗口内明确成功形成”的攻击战术。
2. `attempted_tactics` 只记录“窗口内明确发生、但失败了”的战术尝试；不要把攻击者意图、计划、背景目标直接写进去。
3. 同一个窗口里，如果某个战术已经被成功行为覆盖，一般不要再因为同窗的失败行为重复补一个同名 `attempted_tactics`，除非失败行为表达的是另一类明显不同的语义。
4. 如果报告能明确说明战术，但无法仅凭报告稳定落到具体 ATT&CK technique，则允许“只补 tactic、不补 technique”；但这种情况应标成“可选修订”，不要直接覆盖主基准。
5. 对 `CADETS 4.1` 这类“基础设施被利用、但主机本身未被攻陷”的窗口，保持 `insufficient` 不动。

## 高置信建议直接修改

### 1. `THEIA_20180410_1341_1455_01`

当前状态：

- 当前 `confirmed_tactics`：`INITIAL_ACCESS, EXECUTION, PRIVILEGE_ESCALATION, COMMAND_AND_CONTROL, DISCOVERY`
- 当前 `confirmed_techniques`：`T1189, T1071.001, T1105, T1046`

建议修改：

- 在 `confirmed_tactics` 中新增 `DEFENSE_EVASION`
- 在 `confirmed_techniques` 中新增 `T1070.004`

修改依据：

- 原始报告在 `3.3` 节明确写了删除落地物：
  - `rm clean`
  - `rm profile`
- 见 `TC_Ground_Truth_Report_E3_Update.md` 第 395 至 399 行。

理由：

- 这里不是“推断式清理”，而是报告直接写出了删除行为。
- 当前窗口已经收录了成功的 exploit、提权、C2、发现行为，因此补 `DEFENSE_EVASION` 属于把一个已明确成功的清理行为补齐，不是放宽口径。

风险：

- 低。

---

### 2. `CADETS_20180406_1121_1208_01`

当前状态：

- 当前 `confirmed_tactics`：`INITIAL_ACCESS, EXECUTION, PRIVILEGE_ESCALATION, COMMAND_AND_CONTROL, DISCOVERY`
- 当前 `attempted_tactics`：空

建议修改：

- 保持 `confirmed_tactics / confirmed_techniques` 不变
- 在 `attempted_techniques` 中新增 `T1055`
- 在 `attempted_tactics` 中新增 `DEFENSE_EVASION`

修改依据：

- 原始报告在 `3.1` 节明确写了：
  - `The attacker tried to inject into sshd PID 809 but the injection failed.`
  - 事件日志中也有 `inject /var/log/devc xxx`
- 见 `TC_Ground_Truth_Report_E3_Update.md` 第 165 至 167 行、第 197 至 201 行。

理由：

- 当前 JSON 已经正确表达了成功的 exploit、提权、C2、发现。
- 但“向 sshd 做进程注入且失败”这一点没有体现在窗口级字段中，只放在说明文字里，属于偏保守。
- 这一步更适合落到 `attempted_tactics`，而不是改动 `confirmed_tactics`。

风险：

- 低到中。
- 这里把失败注入归到 `DEFENSE_EVASION` 比归到 `PRIVILEGE_ESCALATION` 更稳妥，因为该窗里 root 进程已经通过 `elevate` 成功建立，不需要再把失败注入强行解释为“新的提权成功”。

---

### 3. `CADETS_20180411_1508_1515_02`

当前状态：

- 当前 `confirmed_tactics`：`INITIAL_ACCESS, EXECUTION, COMMAND_AND_CONTROL`
- 当前 `attempted_tactics`：空

建议修改：

- 保持 `confirmed_tactics / confirmed_techniques` 不变
- 在 `attempted_techniques` 中新增 `T1055`
- 在 `attempted_tactics` 中新增 `DEFENSE_EVASION`

修改依据：

- 原始报告在 `3.8` 节明确写了：
  - `The attacker tried process injection but once again failed`
  - `F1>inject /tmp/grain 802 (failed and caused kernel panic)`
- 见 `TC_Ground_Truth_Report_E3_Update.md` 第 703 至 707 行、第 743 行。

理由：

- 这扇窗当前只保留了成功的 exploit、C2 和载荷落盘/执行链。
- 失败注入没有升级成窗口级 attempted 字段，表达上偏保守。
- 和 `CADETS_20180406_1121_1208_01` 一样，这里推荐补 `attempted`，不推荐改 `confirmed`。

风险：

- 低到中。

---

### 4. `CADETS_20180413_0904_0915_04`

当前状态：

- 当前 `confirmed_tactics`：`INITIAL_ACCESS, EXECUTION, PRIVILEGE_ESCALATION, COMMAND_AND_CONTROL, DISCOVERY`
- 当前 `attempted_tactics`：空

建议修改：

- 保持 `confirmed_tactics / confirmed_techniques` 不变
- 在 `attempted_techniques` 中新增 `T1055`
- 在 `attempted_tactics` 中新增 `DEFENSE_EVASION`

修改依据：

- 原始报告在 `3.14` 节明确写了：
  - `The attacker then used the root drakon implant to try to inject into sshd once again but failed.`
  - 事件日志中有多次 `inject`
  - 交互列表中也列了三次不同文件名的注入动作
- 见 `TC_Ground_Truth_Report_E3_Update.md` 第 1110 至 1111 行、第 1138 至 1141 行、第 1161 至 1164 行。

理由：

- 这扇窗的成功战术本身已经标得比较完整。
- 但“重复进程注入失败”没有体现在 `attempted_*` 字段里，导致窗口对失败型行为表达偏弱。

风险：

- 低到中。

## 中置信可选修订

这些修订的共同特点是：原始报告里有一定依据，但如果你的目标是保持主基准高精度、低歧义，可以先不动。

### 5. `TRACE_20180413_1243_1253_04`

当前状态：

- 当前 `confirmed_tactics`：`INITIAL_ACCESS, EXECUTION, COMMAND_AND_CONTROL, DISCOVERY, DEFENSE_EVASION`
- 当前 `attempted_tactics`：空

可选修改：

- 可选在 `attempted_tactics` 中新增 `PRIVILEGE_ESCALATION`
- 不建议强行新增 `attempted_techniques`，因为仅凭报告文本很难稳定落到一个精确 technique

修改依据：

- 原始报告在 `3.15` 节明确写了：
  - `We were unable to elevate micro`
  - 事件日志里也出现 `elevate ztmp`
- 见 `TC_Ground_Truth_Report_E3_Update.md` 第 1198 至 1200 行、第 1209 至 1211 行。

为什么只是“可选”：

- 这里确实存在提权尝试失败，但失败对象到底是 drakon、micro，还是某个中间落地物，报告写法没有前面几个 CADETS 注入窗那么直接。
- 如果你希望 benchmark 更强调“窗口内失败型阶段也要明确表达”，可以加。
- 如果你希望 benchmark 保持更硬的可复核性，可以先不加。

---

### 6. `TRACE_20180413_1350_1428_05`

当前状态：

- 当前 `confirmed_tactics`：`INITIAL_ACCESS, EXECUTION, COMMAND_AND_CONTROL, DISCOVERY`
- 当前 `confirmed_techniques`：`T1566.001, T1204.002, T1071.001, T1046`

可选修改：

- 可选在 `confirmed_tactics` 中新增 `COLLECTION`
- 不建议直接补 `confirmed_techniques`，除非后续能统一确定这一类本地邮件窃取/落地行为在本项目里的 technique 映射规则

修改依据：

- 原始报告在 `4.9` 节说明：
  - 脆弱 pine 客户端会把被窃取的邮件数据写入 `tcexfil`
  - 交互列表中也有 `tcexfil file written to tmp directory`
- 见 `TC_Ground_Truth_Report_E3_Update.md` 第 1667 至 1669 行、第 1709 至 1711 行。

为什么只是“可选”：

- 这里更像“明确发生了本地数据收集/落地”，但报告没有继续写到外发，也没有把这部分当成主攻击成果来强调。
- 如果主 benchmark 想继续保持保守，可以不补。
- 如果后面发现模型在 TRACE 上稳定打出 `COLLECTION`，而评估总把它算成误报，这一窗是优先考虑放宽的地方。

## 建议保持不动

### 7. `TRACE_20180410_0946_1109_01`

建议：

- 保持不动。

原因：

- 当前 `INITIAL_ACCESS, EXECUTION, PRIVILEGE_ESCALATION, COMMAND_AND_CONTROL` 与报告文字基本一致。
- 这一窗没有明确成功的发现、清理或外传，不建议为了“阶段更全”而硬补。

---

### 8. `TRACE_20180410_1228_1230_02`

建议：

- 保持不动。

原因：

- 当前 `INITIAL_ACCESS, EXECUTION, CREDENTIAL_ACCESS` 与报告高度一致。
- 这窗本质是 phishing link + credential submission，不应扩展成 C2、驻留、发现。

---

### 9. `TRACE_20180412_1336_1336_03`

建议：

- 保持不动。

原因：

- 当前 `attempted_failed`、`attempted_tactics = INITIAL_ACCESS, EXECUTION` 的表达已经很干净。
- 该节没有稳定形成 C2、落地执行或后续链条，不建议扩展。

---

### 10. `CADETS_20180406_1500_1500_05`

建议：

- 保持不动。

原因：

- 这窗是 CADETS 作为 postfix 邮件基础设施被利用，不是 CADETS 被攻陷。
- 当前 `insufficient` 的处理是正确的。

---

### 11. `CADETS_20180412_1400_1438_03`

建议：

- 保持不动。

原因：

- 这窗当前已经包含 `INITIAL_ACCESS, EXECUTION, PRIVILEGE_ESCALATION, COMMAND_AND_CONTROL, DISCOVERY, DEFENSE_EVASION`。
- 报告中失败的 micro elevate 与成功的 drakon elevate 并存，但窗口级 confirmed 已经覆盖了主要成功阶段。
- 再继续补 attempted 字段，收益不大，反而容易把窗口语义搞得太繁琐。

---

### 12. `THEIA_20180410_1342_1342_02`

建议：

- 保持不动。

原因：

- 当前 `INITIAL_ACCESS, EXECUTION, CREDENTIAL_ACCESS` 与报告一致。
- 不应扩展成驻留、C2 或后续主机入侵。

---

### 13. `THEIA_20180412_1244_1326_03`

建议：

- 保持不动。

原因：

- 这窗当前已经覆盖 `INITIAL_ACCESS, EXECUTION, PRIVILEGE_ESCALATION, COMMAND_AND_CONTROL, DISCOVERY, DEFENSE_EVASION`。
- 虽然窗内有失败注入，但当前 confirmed 已经完整表达了实际成功链。

---

### 14. `THEIA_20180413_1350_1404_04`

建议：

- 保持不动。

原因：

- 当前 `attempted_failed`、`attempted_tactics = INITIAL_ACCESS, EXECUTION` 与报告完全一致。
- 该窗没有形成成功的后续链条。

## 推荐修改顺序

建议按下面顺序执行，并在每步后保存一个中间版本：

1. 先改高置信的 4 个窗口：
   - `THEIA_20180410_1341_1455_01`
   - `CADETS_20180406_1121_1208_01`
   - `CADETS_20180411_1508_1515_02`
   - `CADETS_20180413_0904_0915_04`
2. 跑一轮基于当前 JSON 的 tactic 评估，观察 recall / false positive 变化。
3. 如果仍然觉得 benchmark 对失败型阶段过于保守，再考虑加入两个中置信可选修订：
   - `TRACE_20180413_1243_1253_04`
   - `TRACE_20180413_1350_1428_05`

## 最后建议

如果这次修订的目标是“让评估基准更真实表达原始报告中的窗口语义”，推荐采用下面的停线标准：

- 成功行为可以补齐，但必须有报告中的直接动作或结果语句支持。
- 失败行为只补 `attempted_*`，不要因为失败动作而改写 `confirmed_*`。
- 不要为了提高模型分数而给所有窗统一加阶段；那样会把这份 GT 从“偏保守但可信”改成“看起来更全但边界变松”。
