# APT-Fusion TRACE 实验方案：将 ATT&CK 技战术口径切换为 APTShield 阶段口径

## 1. 目标

本方案的目标不是改 `module5` 的成链逻辑，而是单独开一条 **APTShield 阶段实验线**：

- 把当前 TRACE 攻击窗口的 GT 标签，从 `ATT&CK tactic/technique` 改成 **APTShield 的阶段标签**。
- 把 `module6_reason` 的大模型输出，从 “选择 ATT&CK tactic/technique” 改成 “从固定的 APTShield 阶段集合里选择”。
- 把 `path_reason_eval` 的语义评估，从 `technique/tactic recall` 改成 `APTShield stage recall/precision`。
- 保留现有 `module1` 到 `module5` 产物，**不在这一步改候选链生成**。

这一步是一个 **评估口径实验**，不是主线替换。另一个窗口跑 TRACE 时，应该：

1. 复用现有 `module5_paths` 产物；
2. 只重新跑 `module6_reason`；
3. 再跑新的 `path_reason_eval`；
4. 对比 ATT&CK 口径和 APTShield 阶段口径的结果。

## 2. 为什么这一步应该单独做成实验线

动机：

- 当前项目的链条和标签系统正在向 APTShield 靠拢，但最终语义输出仍然是 ATT&CK tactic/technique。
- ATT&CK 口径更细、更碎，容错更差。很多链条虽然能反映 “远控 / webshell / 数据外传” 这种攻击阶段，但映射到具体 ATT&CK 技术时容易丢分。
- APTShield 的阶段更粗、更贴近其标签传播规则，理论上更适合当前项目当前阶段的能力边界。

目的：

- 验证 “当前项目如果不继续细化 ATT&CK 技术识别，而是改用更粗的 APTShield 阶段口径”，语义检测效果会不会明显提升。
- 让另一个窗口能够在 **不改 module5** 的前提下，快速验证这条假设。

必须强调：

- **不要覆盖现有 ATT&CK GT 文件。**
- **不要删除现有 ATT&CK evaluator。**
- **不要把这次实验线直接并入主线。**

原因：

- APTShield 阶段口径比 ATT&CK 粗得多，结果不可直接和当前 ATT&CK 指标等价比较。
- 如果直接替换主线，会丢掉现有 ATT&CK 评估能力，后续无法做并行对照。

## 3. APTShield 阶段集合：这次实验只允许使用这 6 个阶段

本实验的大模型和 GT 窗口，统一只使用下面 6 个阶段。

### 3.1 固定阶段 ID 与中文含义

1. `DOWNLOAD_EXECUTION`
   - 中文：下载并执行
   - 含义：从外部获得文件或载荷，并在本机执行。

2. `WEBSHELL`
   - 中文：Webshell
   - 含义：攻击以 web-facing 服务为入口，通过上传/脚本/命令执行形成服务器端控制。

3. `RAT`
   - 中文：远控 / 远程控制木马
   - 含义：攻击已形成交互式控制、回连、控制通道或下载执行后的远控语义。

4. `LIVING_OFF_THE_LAND`
   - 中文：系统原生命令滥用
   - 含义：依赖本地现成工具、异常文件交互或非正常控制流进行攻击，而不是明显的独立落地样本。

5. `SUSPICIOUS_BEHAVIOR`
   - 中文：可疑行为
   - 含义：敏感文件读取、计划任务/权限配置修改、历史命令读取、主机内高价值行为等。

6. `DATA_EXFILTRATION`
   - 中文：数据外传
   - 含义：已出现本地收集后对外发送，或者报告中明确确认的数据外传行为。

### 3.2 这次实验明确不把 `APT` 当作窗口级主标签

APTShield 论文里还定义了最终复合语义 `APT`，但这次实验 **不把它作为窗口级 GT 标签，也不让大模型直接输出它**。

原因：

- `APT` 在 APTShield 里更像 “复合告警结论”，不是基础阶段。
- 我们现在做的是 **窗口级别评估**，窗口更适合用基础阶段来标记。
- 否则会出现 “一个窗口既有 RAT 又有 Data Exfiltration，又再来一个 APT” 的重复标注，评估口径会变乱。

所以这次实验的大模型和 GT 都只在上述 6 个阶段中选择。

## 4. 证据来源优先级：窗口阶段不是从 ATT&CK 机械替换，而是重新裁定

这一步不能简单把 ATT&CK 技术机械映射到 APTShield 阶段。必须按下面的优先级裁定。

### 4.1 证据优先级

阶段裁定时，证据优先级固定如下：

1. **原始攻击报告**
   - `D:\download\TC_Ground_Truth_Report_E3_Update.pdf`
2. **严格映射文件**
   - `D:\download\ALL_HOSTS_ATTCK_STRICT_MAPPING.md`
3. **宽松映射文件**
   - `D:\download\ALL_HOSTS_ATTACK_ATTCK_MAPPING.md`
4. **现有 GT JSON 里的 `coarse_chain_tags`**
   - 只用于辅助，不作为主依据

### 4.2 不能做的事

- 不能只看 ATT&CK tactics/techniques 就直接决定阶段。
- 不能只看 `coarse_chain_tags` 就决定阶段。
- 不能因为一个窗口里有 `INITIAL_ACCESS` 就强行给 `DOWNLOAD_EXECUTION` 或 `RAT`。

### 4.3 必须做的事

每个窗口都要回答下面 3 个问题：

1. 原始报告里，这个窗口是否已经体现出 **主机侧恶意载荷/控制语义**？
2. 如果体现了，它最接近 APTShield 的哪一种阶段？
3. 如果没有体现，只是钓鱼、凭证提交、失败尝试或弱前置活动，这个窗口是否应该 **排除出阶段主评估**？

## 5. TRACE 这次实验的窗口重标方案

这一步只做 TRACE 实验，因此先给 TRACE 的 5 个窗口一个明确的阶段裁定表。

另一个窗口 **不要自己重新发明这 5 个窗口的阶段标签**，先按下表执行。

### 5.1 新增字段

在新的 TRACE 阶段 GT JSON 里，每个窗口新增下面字段：

- `confirmed_stages`
- `attempted_stages`
- `stage_eval_status`
- `stage_notes`

其中：

- `confirmed_stages`
  - 该窗口已确认的 APTShield 阶段
- `attempted_stages`
  - 该窗口只到尝试、失败、未闭环的阶段
- `stage_eval_status`
  - `scorable`
  - `support_only`
  - `insufficient`
- `stage_notes`
  - 解释为什么这样裁定

### 5.2 TRACE 5 个窗口的固定裁定表

#### `TRACE_20180410_0946_1109_01`

- `status`: `confirmed`
- `confirmed_stages`: `["RAT"]`
- `attempted_stages`: `[]`
- `stage_eval_status`: `scorable`
- `stage_notes`：
  - 浏览器 compromise 后获得回连与植入物传输，已经形成远控语义；
  - 不标 `DOWNLOAD_EXECUTION`，因为窗口重点不是“单次下载执行”，而是形成持久控制通道后的 RAT 语义。

#### `TRACE_20180410_1228_1230_02`

- `status`: `confirmed`
- `confirmed_stages`: `[]`
- `attempted_stages`: `[]`
- `stage_eval_status`: `support_only`
- `stage_notes`：
  - 该窗口只有 phishing link 和凭证提交；
  - 原始报告没有给出明确的主机侧恶意载荷、回连、下载执行、数据外传语义；
  - 这个窗口保留在时间 GT 中，但 **不进入 APTShield 阶段主评估分母**。

#### `TRACE_20180412_1336_1336_03`

- `status`: `attempted_failed`
- `confirmed_stages`: `[]`
- `attempted_stages`: `["RAT"]`
- `stage_eval_status`: `scorable`
- `stage_notes`：
  - 原始报告描述的是浏览器扩展攻击尝试，目标仍是形成控制通道；
  - 因为没有拿到 operator console/callback，阶段记为 attempted；
  - 不标 `DOWNLOAD_EXECUTION`，因为报告重点仍是远控闭环失败，而非明确的独立下载执行闭环。

#### `TRACE_20180413_1243_1253_04`

- `status`: `confirmed`
- `confirmed_stages`: `["RAT"]`
- `attempted_stages`: `[]`
- `stage_eval_status`: `scorable`
- `stage_notes`：
  - 浏览器利用后拿到 shell，执行 `execfile /tmp/ztmp`，出现 micro APT callback 和后续扫描；
  - 这是典型的远控控制阶段；
  - `scan/cleanup` 只是辅助行为，不单独把主阶段改成 `SUSPICIOUS_BEHAVIOR`。

#### `TRACE_20180413_1350_1428_05`

- `status`: `confirmed`
- `confirmed_stages`: `["RAT"]`
- `attempted_stages`: `[]`
- `stage_eval_status`: `scorable`
- `stage_notes`：
  - 恶意附件经用户打开后，micro APT 自动执行并回连，再进行扫描；
  - 对 APTShield 口径来说，这更接近 RAT，而不是单纯 `DOWNLOAD_EXECUTION`。

### 5.3 TRACE 试验的一个重要现实

这 5 个窗口里，按 APTShield 阶段重标后会出现：

- 3 个 `confirmed RAT`
- 1 个 `attempted RAT`
- 1 个 `support_only`

这是预期行为，不是 bug。

原因：

- TRACE 的原始攻击报告本来就以浏览器 compromise、恶意附件、回连、micro APT 为主；
- 用 APTShield 阶段口径后，多个 ATT&CK 技术会被压缩到同一个更粗的 RAT 阶段。

这也意味着：

- **APTShield 阶段实验线的准确率可能显著上升**
- 但这不等于当前项目对 ATT&CK 的真实解析能力也同步提升

## 6. GT 文件如何落地：不要覆盖原文件，新增 TRACE 阶段版 GT

### 6.1 必须新增的文件

另一个窗口必须新增两个文件：

1. `D:/daima/APT-Fusion/docs/trace_aptshield_stage_ground_truth_2026-06-04.md`
2. `D:/daima/APT-Fusion/docs/trace_aptshield_stage_ground_truth_2026-06-04.json`

### 6.2 不允许做的事

- 不允许直接覆盖：
  - `D:/daima/APT-Fusion/docs/darpa_attack_eval_ground_truth_2026-05-26_zh.md`
  - `D:/daima/APT-Fusion/docs/darpa_attack_eval_ground_truth_2026-05-26.json`

### 6.3 新 JSON 的最小结构

新 JSON 只需要包含 TRACE 窗口，建议结构如下：

```json
{
  "schema_version": "trace_aptshield_stage_gt.v1",
  "generated_at": "2026-06-04T00:00:00Z",
  "source_documents": {
    "primary_attack_report_path": "D:\\download\\TC_Ground_Truth_Report_E3_Update.pdf",
    "strict_mapping_path": "D:\\download\\ALL_HOSTS_ATTCK_STRICT_MAPPING.md",
    "broad_mapping_path": "D:\\download\\ALL_HOSTS_ATTACK_ATTCK_MAPPING.md"
  },
  "host": "TRACE",
  "windows": [
    {
      "window_id": "TRACE_20180410_0946_1109_01",
      "status": "confirmed",
      "start_time": "2018-04-10T09:46:00",
      "end_time": "2018-04-10T11:09:00",
      "confirmed_stages": ["RAT"],
      "attempted_stages": [],
      "stage_eval_status": "scorable",
      "stage_notes": "..."
    }
  ]
}
```

### 6.4 为什么单独做 TRACE 版 GT

动机：

- 这次实验只跑 TRACE。
- TRACE 是当前最重要的对照数据集。

目的：

- 减少另一个窗口一次性修改过多 GT 文件的风险。
- 先验证 “阶段口径实验” 是否有价值。

## 7. module6_reason：不要再做 ATT&CK mapping，改成 APTShield 阶段选择

这一部分是这次实验线最关键的代码改动。

### 7.1 总原则

当前 `module6_reason` 是两段式：

1. 从 dossier 提取 claims / iocs
2. 再做 ATT&CK tactic/technique mapping

这次实验线保留两段式结构，但把第二段换成：

1. 提取 claims / iocs
2. 从固定的 APTShield 阶段集合里选阶段

### 7.2 这一步不允许做的事

- 不允许让 stage 实验线继续依赖 `attack_kb.py`
- 不允许继续走 `retrieve_attack_candidates(...)`
- 不允许继续输出 ATT&CK `tactic_id/technique_id` 作为主结果

原因：

- APTShield 阶段集合是固定的，不需要 ATT&CK KB 检索。
- 如果 stage 实验线还混着 ATT&CK 检索，会让结果既不纯，也难解释。

### 7.3 必须新增的配置开关

在 [D:/daima/APT-Fusion/src/apt_fusion/config.py](D:/daima/APT-Fusion/src/apt_fusion/config.py) 里新增：

- `reason_taxonomy_mode: str = "attack"`
  - 允许值：
    - `attack`
    - `aptshield_stage`

默认值必须保持 `attack`，这样主线行为不变。

加载配置时也必须加入这一字段。

### 7.4 module6 里必须新增的阶段 schema

在 [D:/daima/APT-Fusion/src/apt_fusion/path_reason/module6_attack_reason.py](D:/daima/APT-Fusion/src/apt_fusion/path_reason/module6_attack_reason.py) 里新增一个阶段 schema，例如：

```python
def _stage_mapping_schema() -> Dict[str, Any]:
    return {
        "stage_mappings": [
            {
                "stage_id": "DOWNLOAD_EXECUTION|WEBSHELL|RAT|LIVING_OFF_THE_LAND|SUSPICIOUS_BEHAVIOR|DATA_EXFILTRATION",
                "stage_label": "string",
                "status": "confirmed|attempted",
                "evidence_claim_ids": ["claim_id"],
                "confidence": 0.0,
                "gaps": ["string"]
            }
        ],
        "gaps": ["string"]
    }
```

### 7.5 module6 里必须新增的阶段 prompt

新增一个专门的用户提示函数，例如：

- `_user_prompt_stage_map(...)`

它必须明确告诉模型：

- 只能从这 6 个阶段中选择
- 不能输出 ATT&CK tactic/technique
- `support_only` 窗口不应该硬选阶段
- 如果证据只支持 attempted，就必须标 `status=attempted`

提示词必须显式写出 6 个阶段的中文定义，避免模型自行扩展。

### 7.6 claim 提取阶段这次不需要大改

当前第一段 claim 提取可以基本保留，只做一处小补充：

- 在 prompt 里提醒模型，后续会把 claim 用于 APTShield stage 选择；
- 不要把 claim 写成 ATT&CK 术语驱动的陈述，尽量写成行为事实。

### 7.7 report JSON 结构必须新增 `stage_mappings`

当 `reason_taxonomy_mode == "aptshield_stage"` 时，最终 report JSON 必须新增：

- `taxonomy_mode`
- `stage_mappings`

例如：

```json
{
  "taxonomy_mode": "aptshield_stage",
  "summary": "...",
  "claims": [...],
  "iocs": [...],
  "stage_mappings": [
    {
      "stage_id": "RAT",
      "stage_label": "远控 / 远程控制木马",
      "status": "confirmed",
      "evidence_claim_ids": ["c1", "c2"],
      "confidence": 0.92,
      "gaps": []
    }
  ]
}
```

### 7.8 markdown 报告也必须显示阶段而不是 ATT&CK

当前 markdown 会输出 `## ATT&CK Mappings`。  
在 stage 模式下必须改成：

- `## APTShield Stage Mappings`

并输出：

- `stage_id`
- `stage_label`
- `status`
- `evidence_claim_ids`
- `confidence`

## 8. path_reason_eval：保持时间匹配逻辑不变，只替换语义评估口径

这次 evaluator 改动的原则是：

- **时间窗匹配逻辑不动**
- **只替换语义对比口径**

### 8.1 为什么不动时间匹配逻辑

动机：

- 这次实验要验证的是语义标准变更，不是时间匹配算法变更。

目的：

- 保持和当前 ATT&CK 实验可比较。
- 让 “变化来自阶段语义，而不是时间窗定义变化”。

### 8.2 必须新增的配置开关

同样在配置里新增：

- `eval_taxonomy_mode: str = "attack"`
  - 允许值：
    - `attack`
    - `aptshield_stage`

默认仍然是 `attack`。

### 8.3 GTWindow 必须新增的字段

在 [D:/daima/APT-Fusion/src/apt_fusion/evaluation/path_reason_eval.py](D:/daima/APT-Fusion/src/apt_fusion/evaluation/path_reason_eval.py) 的 `GTWindow` 中新增：

- `confirmed_stages: list[str]`
- `attempted_stages: list[str]`
- `stage_eval_status: str`
- `stage_notes: str`

这些字段在 ATT&CK 模式下允许为空。

### 8.4 PredictedPath 必须新增的字段

在同文件的 `PredictedPath` 中新增：

- `predicted_stages: list[str]`

来源是 `module6_reason` 的 `stage_mappings`。

### 8.5 必须新增的解析函数

新增一个类似：

- `_report_stage_set(report: dict[str, Any]) -> list[str]`

规则固定为：

- 只读取 `stage_mappings`
- 只收集 `status == "confirmed"` 的 `stage_id`
- 去重并保持稳定顺序

如果后面要单独分析 attempted，再额外做一个：

- `_report_attempted_stage_set(...)`

### 8.6 stage 模式的主指标

在 `eval_taxonomy_mode == "aptshield_stage"` 下，新增并输出下面这些指标：

1. `confirmed_stage_window_recall`
   - 分母：`stage_eval_status == scorable` 且 `status == confirmed` 的窗口数
   - 分子：窗口时间匹配成功且 `predicted_stages ∩ confirmed_stages != empty` 的窗口数

2. `strict_stage_recall_macro`
   - 对每个 `scorable + confirmed` 窗口计算
   - `|pred ∩ gt| / |gt|`
   - 再做宏平均

3. `strict_stage_precision_macro`
   - 对每个有预测阶段的 matched window 计算
   - `|pred ∩ gt| / |pred|`
   - 再做宏平均

4. `attempted_stage_hit_rate`
   - 对 `attempted_failed` 且 `stage_eval_status == scorable` 的窗口计算
   - 如果 `predicted_stages ∩ attempted_stages != empty` 则算 hit

5. `support_only_high_risk_rate`
   - `support_only` 窗口中，如果被高风险 path/report 命中并且模型还输出了阶段，则计入该误报率

### 8.7 ATT&CK 指标这次不要删除

即使做 stage 实验线，也不要删除原有：

- `strict_technique_recall_macro`
- `strict_tactic_recall_macro`

处理方式：

- ATT&CK 模式下照常输出
- stage 模式下允许填空或不计算
- 但代码不要删

原因：

- 后面还要和主线 ATT&CK 口径做并行对照。

## 9. TRACE 这次实验不改 module5，不重跑 module1 到 module5

这是这份方案里最重要的执行边界。

### 9.1 不允许改的模块

这次实验中，另一个窗口 **不要改**：

- `module3_evidence_recover.py`
- `module4_semantic_compact.py`
- `module5_path_finder.py`
- `path_search.py`
- `path_scoring.py`

### 9.2 为什么不能改这些

动机：

- 这次实验只想验证语义标准从 ATT&CK 改成 APTShield 阶段后，指标会不会明显改善。

目的：

- 把变量收窄到：
  - GT 标签标准
  - LLM 输出标准
  - evaluator 语义标准

如果同时改 `module5`，结果就没法解释了。

### 9.3 TRACE 实验应该如何运行

这次实验应尽量复用已有 TRACE `module5` 产物。

建议流程：

1. 准备新的 TRACE 阶段 GT 文件
2. 修改 `module6_reason`，加入 `aptshield_stage` 模式
3. 修改 `path_reason_eval`，加入 `aptshield_stage` 模式
4. 基于已有 TRACE artifact，只重跑：
   - `module6_reason`
   - `path_reason_eval`

只有当已有 `module5_paths` 产物不存在或不一致时，才考虑重跑更上游模块。

## 10. 另一个窗口的具体执行顺序

下面的顺序必须严格遵守，不要跳。

### Step A：先写 GT 文件

必须完成：

1. 新建 TRACE 阶段版 markdown 说明文件
2. 新建 TRACE 阶段版 JSON GT 文件
3. 把 5 个 TRACE 窗口按第 5 节固定表写死

这一阶段不改任何 Python 代码。

### Step B：再加配置开关

必须完成：

1. 在 `config.py` 增加：
   - `reason_taxonomy_mode`
   - `eval_taxonomy_mode`
2. 更新 `load_config(...)`
3. 给默认 example config 加注释，但不要改主线现有配置的默认行为

这一阶段不改 module6 主逻辑，只把开关接进来。

### Step C：改 module6 的 stage 模式

必须完成：

1. 新增 stage schema
2. 新增 stage mapping prompt
3. 在 `reason_taxonomy_mode == "aptshield_stage"` 时：
   - 跳过 ATT&CK KB 检索
   - 跳过 ATT&CK mapping 校验
   - 输出 `stage_mappings`
4. 在 markdown/report 中显示 stage mappings

这一阶段改完后，可以做一次小范围 smoke test，但先不跑全 TRACE。

### Step D：改 evaluator 的 stage 模式

必须完成：

1. GTWindow/PredictedPath 新增 stage 字段
2. 支持读取 TRACE 阶段 GT JSON
3. 实现 stage 集合提取
4. 实现新的 stage 指标
5. 保留现有时间匹配逻辑不动

### Step E：跑 TRACE 实验

建议：

- 先用已有 `module5_paths` 产物
- 只重跑 `module6_reason`
- 再跑 `path_reason_eval`

### Step F：结果汇总必须同时看这几类东西

1. `confirmed_stage_window_recall`
2. `strict_stage_recall_macro`
3. `strict_stage_precision_macro`
4. `attempted_stage_hit_rate`
5. `support_only_high_risk_rate`
6. 旧的时间窗命中指标
   - 看是否保持不变

## 11. 这次实验的预期与判断标准

### 11.1 合理预期

如果当前项目的链条与标签体系已经相当接近 APTShield，那么把最终语义输出改成 APTShield 阶段后：

- `strict_stage_recall_macro`
- `confirmed_stage_window_recall`

理论上应该显著高于 ATT&CK 技术口径。

### 11.2 必须避免的误判

不要把下面两件事混为一谈：

1. **APTShield 阶段准确率升高**
2. **当前系统真正变强了**

原因：

- 阶段标签比 ATT&CK 粗得多；
- 多个不同 ATT&CK 技术会被折叠到同一个阶段；
- 因此阶段准确率天然更容易高。

### 11.3 对“90% 以上准确率”的处理方式

这次实验里，`90%+` 应该被当作 **待验证假设**，不是实现时的硬编码目标。

更准确地说：

- 如果 TRACE 的 `support_only` 窗口被正确排除，
- 且其余 scorable 窗口大多都被模型判成 `RAT`，
- 那阶段级准确率确实可能接近或超过 90%。

但如果没有达到，也不能说明方案完全失败，可能原因包括：

- 候选 path 本身仍然偏噪
- dossier 里的证据不够让模型稳定选阶段
- 某些窗口的 APTShield 阶段本身就存在人工裁定歧义

## 12. 明确禁止做的事

另一个窗口执行时，以下事情全部禁止：

1. 禁止覆盖现有 ATT&CK GT 文件
2. 禁止删除 ATT&CK evaluator 逻辑
3. 禁止修改 `module5` 成链和评分逻辑
4. 禁止在 stage 模式里继续依赖 `attack_kb.py`
5. 禁止把 `APT` 复合告警当作窗口级主标签
6. 禁止为了追求高指标，临时把 `support_only` 窗口偷偷删除

`support_only` 窗口必须保留在 GT 中，只是 **不纳入 stage 主评估分母**。

## 13. 改完后的最小验收条件

另一个窗口改完后，至少要满足下面 6 条，否则视为未完成：

1. 新的 TRACE 阶段 GT markdown 和 JSON 都存在
2. `config.py` 支持 `reason_taxonomy_mode` 和 `eval_taxonomy_mode`
3. `module6_reason` 在 `aptshield_stage` 模式下不再输出 ATT&CK mapping，而是输出 `stage_mappings`
4. `path_reason_eval` 能读取 `confirmed_stages / attempted_stages / stage_eval_status`
5. TRACE 实验只重跑 `module6_reason + path_reason_eval` 就能完成
6. 实验结果里能看到新的 stage 指标输出

## 14. 这次方案最核心的一句话

**这不是“把 ATT&CK 名字换个壳”，而是新开一条 APTShield 阶段实验线：GT、LLM 输出、evaluator 同时切换到同一个更粗、更贴近当前项目能力边界的阶段口径。**
