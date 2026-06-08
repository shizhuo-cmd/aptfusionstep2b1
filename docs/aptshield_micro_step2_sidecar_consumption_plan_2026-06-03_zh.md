# APT-Fusion 微小步第二阶段施工单：分步消费 sidecar，不直接改主成链

## 0. 文档定位

这份文档是给**另一个执行窗口**的严格施工单。

它建立在下面这个前提上：

- 代码已经回退到“第一步修改之前”的基线；
- 然后按上一份微小步施工单，把这些结构补了回来：
  - `TaskLocalEvidenceGraph`
  - `ObjectVersion`
  - `LabelProvenanceRecord`
  - `support_event_ids / support_object_keys / support_relations / context_ids / chain_kind`

而当前真实状态是：

1. `module3` 新 sidecar 已经生成；
2. `module4` 的 `object_versions` 已经生成；
3. `module4` 的 `label_provenance` 已经生成；
4. `module5` 的 `support_* / context_ids / chain_kind` 已经进 dossier；
5. 但这些东西还**没有真正进入机器判别层**。

换句话说，现状是：

**人类能在 artifact 里看见这些新结构，系统自己却几乎没真正利用它们。**

这份文档的目标就是：

**让 sidecar 从“落盘产物”一步一步变成“被主流程轻量消费的信号”。**

注意：

这次仍然不是重写检测器。  
这次是**分三小步逐步接入 sidecar**，并且每一步都必须单独跑实验。

---

## 1. 为什么不能一次全接进去

之前我们已经见过一次风险：

- 一旦同时改成链、排序、传播、上下文；
- 很容易出现候选链暴涨；
- 误报比收益涨得更快；
- `task_0546` 这种图会首先出问题。

所以这次必须严格分步：

1. 先只改 `module6_reason` prompt，让 LLM 真正吃到 support/context；
2. 再让 `label_provenance` 进入 `module5`，但**只做轻量重排，不做成链**；
3. 最后再让 `TaskLocalEvidenceGraph` 进入 `module5`，但**只做图一致性惩罚，不做图搜索**。

只要其中任一步效果不对，就必须停下来，不得继续叠下一步。

---

## 2. 这次的总体原则

## 2.1 必须遵守的原则

1. 不改 `path_search.py`
2. 不改 `path_propagator.py`
3. 不让 `ObjectVersion` 直接参与成链
4. 不让 `LabelProvenance` 直接决定成链
5. 不让 `TaskLocalEvidenceGraph` 直接接管搜索
6. 每次只改一个消费层
7. 每次改完先跑实验，再决定要不要进入下一步

## 2.2 本次的核心目标

不是立刻追求：

- recall 大涨
- technique recall 大涨
- 高风险链条数量大涨

而是追求：

1. 新增 sidecar 真的进入机器判别层；
2. 不因为接入 sidecar 而显著放大误报；
3. 每一步实验归因清楚，知道是哪一层带来了变化。

---

## 3. 先总结“上一步哪些地方没有符合设想”

这部分必须先写清楚，因为下一步就是围绕这些缺口补。

## 3.1 `module3` 的 `TaskLocalEvidenceGraph` 没有消费者

当前代码里：

- `module3_evidence_recover.py` 已经生成了
  - `entity_index`
  - `process_event_index`
  - `object_event_index`
  - `task_evidence_frontier`
  - `task_local_evidence_graph`

但后续 `module5` 没有读取 `task_local_evidence_graph_path`。

这意味着：

- 它目前只是落盘产物；
- 还不是 path 校验信号。

## 3.2 `object_versions` 只进了 support 说明层

当前代码里：

- `module5` 会读 `object_versions_path`
- 但只在 `_augment_candidate_support(...)` 里生成 `support_relations`

它没有影响：

- path 是否成立
- path 排序
- LLM prompt

## 3.3 `label_provenance` 已生成，但主流程没消费

当前代码里：

- `module4` 会输出 `label_provenance/<task>.jsonl`
- 但 `module5` 没有加载它
- `module6` 也没有基于它组织上下文

这意味着：

- provenance 现在只存在于 artifact
- 还没有进入“机器怎么判断链条质量”的层

## 3.4 `support_* / context_ids / chain_kind` 已进 dossier，但 prompt 没吃

这是当前最直接的断点。

`path_report.py` 已经在 dossier 里放了：

- `chain_kind`
- `context_ids`
- `support_event_ids`
- `support_object_keys`
- `support_relations`

但 `module6_attack_reason.py` 的 `_render_compact_path_dossier(...)` 当前只输出：

- `PATH`
- `summary`
- `PROCESSES`
- `BRIDGES`
- `TIMELINE`
- `WARNINGS`

也就是说：

**大模型根本没看到这批新增字段。**

这一步是当前最该先补的地方。

---

## 4. 本次分三小步，每一步都必须单独跑实验

本次严格分成：

1. **Step 2A：Prompt 消费层**
2. **Step 2B：Provenance 轻量重排层**
3. **Step 2C：TaskLocalEvidenceGraph 图一致性惩罚层**

这三步必须按顺序执行。

---

## 5. Step 2A：先让 `module6_reason` 真正看到 support/context

## 5.1 Step 2A 的目标

目标只有一个：

**让 `support_* / context_ids / chain_kind` 真正进入 LLM prompt。**

这一小步：

- 不改候选链数量
- 不改候选链排序
- 不改 evaluator
- 只改大模型看到的 path 压缩上下文

## 5.2 为什么先做这一步

这是风险最低、验证最直接的一步。

因为当前最明显的浪费是：

- dossier 里已经有新证据；
- 大模型却还在看旧版精简上下文。

如果这一步都不先做，后面继续加 provenance / graph-check，LLM 仍然可能看不见关键证据。

---

## 5.3 Step 2A 只允许改哪些文件

只允许改：

1. `D:/daima/APT-Fusion/src/apt_fusion/path_reason/module6_attack_reason.py`
2. `D:/daima/APT-Fusion/tests/test_attack_reason_context.py`

不允许改其他文件。

---

## 5.4 Step 2A 具体怎么改

### 5.4.1 改 `_render_compact_path_dossier(...)`

文件：

`D:/daima/APT-Fusion/src/apt_fusion/path_reason/module6_attack_reason.py`

函数：

- `_render_compact_path_dossier(dossier: dict[str, Any]) -> str`

### 5.4.2 必须新增 `SUPPORT` 段

在 `summary` 后面、`PROCESSES` 前面，新增一个固定段：

```text
SUPPORT
- chain_kind=...
- contexts=...
- support_objects=...
- support_relations
  - ...
- support_events=...
```

### 5.4.3 每个字段怎么取

#### `chain_kind`

来源：

- `dossier["chain_kind"]`

要求：

- 如果为空，不输出该行

#### `contexts`

来源：

- `dossier["context_ids"]`

要求：

- 最多输出前 6 个
- 用逗号连接
- 如果为空，不输出该行

#### `support_objects`

来源：

- `dossier["support_object_keys"]`

要求：

- 最多输出前 8 个
- 用逗号连接
- 如果为空，不输出该行

#### `support_relations`

来源：

- `dossier["support_relations"]`

要求：

- 最多输出前 8 条
- 每条独占一行
- 如果为空，不输出该子段

#### `support_events`

来源：

- `dossier["support_event_ids"]`

要求：

- 最多输出前 10 个 event ID
- 只输出 ID，不展开原文
- 如果为空，不输出该行

### 5.4.4 严禁做的事

1. 不要把完整 `support_event_ids` 事件内容全塞进 prompt
2. 不要在 Step 2A 就引入 provenance chain 展开
3. 不要改 `_user_prompt_extract(...)` 的行为规则
4. 不要改 mapping prompt 的 schema

原因：

- 这一步只验证“support/context 被看见后有没有增益”
- 不要一口气把 prompt 结构改得太多，避免归因困难

---

## 5.5 Step 2A 要补的测试

修改：

`D:/daima/APT-Fusion/tests/test_attack_reason_context.py`

至少新增 1 个测试：

- 构造一个 dossier，填入：
  - `chain_kind`
  - `context_ids`
  - `support_object_keys`
  - `support_relations`
  - `support_event_ids`
- 调 `_render_compact_path_dossier(...)`
- 断言输出里包含：
  - `SUPPORT`
  - `chain_kind=`
  - `contexts=`
  - `support_objects=`
  - `support_relations`

---

## 5.6 Step 2A 改完后怎么跑实验

只需要重跑：

1. `module6_reason`
2. evaluator

不需要重跑：

- `module3_evidence`
- `module4_compact`
- `module5_paths`

因为 path 和 dossier JSON 已经在。

---

## 5.7 Step 2A 的验收标准

### 通过标准

满足下面任一条，即可进入 Step 2B：

1. tactic recall 有提升；
2. technique recall 有提升；
3. 即使指标不涨，但 report 内容明显更聚焦，且没有误报显著恶化。

### 停止标准

如果出现下面任一情况，先不要进入 Step 2B：

1. `off_window_high_risk_rate` 明显恶化；
2. report 文本变得更泛、更啰嗦；
3. LLM 明显开始过拟合 `support_relations` 文本描述。

如果发生这些问题，先回调 Step 2A 的 prompt 密度，而不是继续叠下一步。

---

## 6. Step 2B：让 `label_provenance` 进入 `module5`，但只做轻量重排

## 6.1 Step 2B 的目标

目标是：

**让 provenance 第一次进入机器判别层，但不参与成链，只参与小幅 rerank。**

也就是说：

- path 还是旧 `search_candidate_paths()` 找出来
- provenance 只负责告诉我们“这条 path 的标签支撑是不是紧凑、是不是可信”

---

## 6.2 为什么 Step 2B 不能直接改成 provenance-first search

因为当前 provenance 还不完整：

- `module4` 里有不少 record
- 但 `path_propagator` 那层很多传播还没完整记 provenance

所以现在直接做 provenance-first search，风险太大。  
这一步只允许 provenance 做：

- 路径质量修正
- 不是路径发现器

---

## 6.3 Step 2B 只允许改哪些文件

只允许改：

1. `D:/daima/APT-Fusion/src/apt_fusion/path_reason/module5_path_finder.py`
2. `D:/daima/APT-Fusion/src/apt_fusion/path_reason/label_provenance.py`
3. `D:/daima/APT-Fusion/tests/test_label_provenance.py`

不允许改：

- `path_search.py`
- `path_scoring.py`
- `path_propagator.py`

---

## 6.4 Step 2B 具体要新增什么

### 6.4.1 在 `module5_path_finder.py` 里新增 `_load_label_provenance(...)`

函数签名建议：

```python
def _load_label_provenance(path: Path) -> list[LabelProvenanceRecord]:
```

要求：

- 路径不存在或为空时返回空列表
- 绝对不能抛异常中断 task

### 6.4.2 新增 `_score_path_support_quality(...)`

函数签名建议：

```python
def _score_path_support_quality(
    path: CandidatePath,
    provenance_records: list[LabelProvenanceRecord],
    retained_events: list[dict[str, Any]],
) -> tuple[float, list[str]]:
```

返回值：

1. `support_quality_score`
2. `support_quality_reasons`

### 6.4.3 这一步只计算 3 个指标

#### 指标 A：`support_compactness`

中文名：**支撑时间紧凑度**

计算思路：

- 看 `path.support_event_ids` 对应事件的时间跨度
- 如果事件特别散，扣分
- 如果事件比较集中，加少量分

建议分值范围：

- `[-3, +2]`

目的：

- 抑制那种“同一条 path 其实是长时间散落上下文拼起来”的假链

#### 指标 B：`provenance_density`

中文名：**标签来源覆盖度**

计算思路：

- 看 path 的关键标签中，有多少能在 provenance record 中找到
- 关键标签建议只看：
  - `B_*`
  - `P_UNTRUSTED_CTX`
  - `P_HIGH_VALUE_CTX`
  - `A_BRIDGED_BY_SUSPICIOUS_OBJECT`

如果关键标签很多但 provenance 支撑很少，扣分。

建议分值范围：

- `[-3, +3]`

目的：

- 让“标签很多但来路不清”的 path 降权

#### 指标 C：`support_coherence`

中文名：**支撑关系一致性**

计算思路：

- 看 `support_object_keys` 数量
- 看 `support_relations` 数量
- 如果对象很多、关系很少，说明 path 很散，扣分
- 如果对象少、关系集中，加少量分

建议分值范围：

- `[-2, +2]`

目的：

- 抑制“对象很多但因果很弱”的 path

---

## 6.5 Step 2B 如何接到主流程

在 `module5_path_finder.py` 里：

1. 保持原有：
   - `paths = search_candidate_paths(...)`
   - `paths = score_candidate_paths(...)`
2. 在 `score_candidate_paths(...)` 之后、`_augment_candidate_support(...)` 之后，新增一层：

```python
path.support_quality_score = ...
path.support_quality_reasons = ...
path.risk_score += small_adjustment
```

### 6.5.1 小调整的硬约束

这一步只允许：

- 在旧 `risk_score` 基础上加一个**很小的**修正项

建议：

- 总修正范围控制在 `[-8.0, +8.0]`

绝对不允许：

- 覆盖旧 `risk_score`
- 重新定义 `risk_level`
- 重新做全排序公式

### 6.5.2 必须输出的新字段

在 `CandidatePath` 上新增字段：

- `support_quality_score: float = 0.0`
- `support_quality_reasons: list[str] = field(default_factory=list)`

并确保：

- dossier 顶层也写进去
- markdown 可以简单展示 1 行摘要

---

## 6.6 Step 2B 要补的测试

至少新增 2 组测试：

1. provenance 覆盖高的 path，`support_quality_score` 应该更高
2. 时间跨度特别散的 path，`support_quality_score` 应该更低

不要求做全量 path 排序测试，但至少要验证：

- 小修正项确实生效
- 不会抛异常

---

## 6.7 Step 2B 改完后怎么跑实验

需要重跑：

1. `module5_paths`
2. `module6_reason`
3. evaluator

不需要重跑：

- `module3_evidence`
- `module4_compact`

前提是：

- `label_provenance` sidecar 已经在

---

## 6.8 Step 2B 的验收标准

### 通过标准

满足下面任一条，可以进入 Step 2C：

1. `off_window_high_risk_rate` 降了
2. 高风险 report 总数下降但 recall 不掉
3. `task_0546` 这类重上下文会话链明显后移或消失

### 停止标准

如果出现下面任一情况，先不要进入 Step 2C：

1. 候选链数量明显异常波动
2. 真阳性链被 provenance 覆盖不足误杀
3. 风险分变化过大，导致 top-N 全洗牌

如果发生这些问题，先缩小 rerank 修正范围，再重跑。

---

## 7. Step 2C：让 `TaskLocalEvidenceGraph` 做图一致性惩罚，不做图搜索

## 7.1 Step 2C 的目标

目标是：

**让任务局部证据图第一次进入主流程，但只做 graph-check penalty。**

也就是说：

- 不从图里重新搜链
- 不替代 `search_candidate_paths()`
- 只回答一个问题：
  - “这条 path 的支撑事件和支撑对象，在 task 局部图里是不是像一个相对紧凑的连通子结构？”

---

## 7.2 为什么 Step 2C 不能直接做 graph-search

因为一旦直接做 graph-search，就不是微步了。  
那会把这次改动升级成：

- 新搜索器
- 新候选对象
- 新评分器

这不符合当前“一点一点改”的要求。

---

## 7.3 Step 2C 只允许改哪些文件

只允许改：

1. `D:/daima/APT-Fusion/src/apt_fusion/path_reason/module5_path_finder.py`
2. `D:/daima/APT-Fusion/src/apt_fusion/path_reason/path_schemas.py`
3. 新增一个测试文件或补现有 `test_path_search.py`

不允许改：

- `module3_evidence_recover.py`
- `path_search.py`
- `path_scoring.py`

---

## 7.4 Step 2C 具体要新增什么

### 7.4.1 新增 `_load_task_local_evidence_graph(...)`

签名建议：

```python
def _load_task_local_evidence_graph(path: Path) -> TaskLocalEvidenceGraph | None:
```

要求：

- 文件缺失返回 `None`
- 不抛异常

### 7.4.2 新增 `_graph_consistency_penalty(...)`

签名建议：

```python
def _graph_consistency_penalty(
    path: CandidatePath,
    local_graph: TaskLocalEvidenceGraph | None,
) -> tuple[float, list[str]]:
```

返回：

1. `graph_penalty`
2. `graph_reasons`

---

## 7.5 Step 2C 只做 2 类检查

### 检查 A：连通性检查

中文名：**支撑子图连通性**

思路：

- 看 `path.process_chain` 和 `support_object_keys` 在 `local_graph` 里是否能形成较小连通块
- 如果散成多个明显无关小块，扣分

建议范围：

- `[-4, 0]`

### 检查 B：跨度检查

中文名：**支撑子图跨度惩罚**

思路：

- 如果 path 支撑了太多不同对象、太多不同边，但关系非常稀疏，扣分

建议范围：

- `[-3, 0]`

---

## 7.6 Step 2C 如何接到主流程

在 `module5_path_finder.py` 里：

1. 读取 `task_local_evidence_graph_path`
2. 在 Step 2B 的 `support_quality_score` 之后，再叠一个小的 `graph_penalty`
3. 继续保持总修正幅度很小

建议：

- Step 2B + Step 2C 总体对 `risk_score` 的修正，仍然控制在 `[-12, +8]` 内

这一步必须遵守：

- 图一致性只做 penalty，不做 bonus 优先奖励

原因：

- 当前图消费刚开始，保守做惩罚比做奖励更稳

---

## 7.7 Step 2C 要补的测试

至少补 2 组：

1. 支撑子图明显分散时，`graph_penalty < 0`
2. 支撑子图较紧凑时，`graph_penalty == 0` 或接近 0

不要现在写复杂图搜索测试。

---

## 7.8 Step 2C 改完后怎么跑实验

需要重跑：

1. `module5_paths`
2. `module6_reason`
3. evaluator

不需要重跑：

- `module3_evidence`
- `module4_compact`

前提是已有 `task_local_evidence_graph` artifact。

---

## 7.9 Step 2C 的验收标准

### 通过标准

满足下面任一条，说明这次 sidecar 消费层初步成功：

1. `off_window_high_risk_rate` 进一步下降
2. `task_0546` 这类图的高风险错链明显减少
3. report 数量略降但 recall 基本不掉

### 停止标准

如果出现下面任一情况，就先停下来，不要继续更大的第三阶段：

1. 正常 task 大量被压没链
2. 真阳性 path 因图不完整被过度惩罚
3. 误报没降，反而 recall 继续掉

---

## 8. 每一步实验该怎么看，不要只看总分

每做完一步，都必须看 4 类东西：

## 8.1 总指标

- `confirmed_window_recall`
- `strict_window_recall`
- `high_risk_window_recall`
- `off_window_high_risk_rate`
- `strict_technique_recall_macro`
- `strict_tactic_recall_macro`

## 8.2 path 数量变化

- `candidate_path_count`
- `predicted_path_count`
- `predicted_path_with_report_count`

## 8.3 report 内容变化

随机抽：

- 一张已知真阳性图
- 一张已知高噪声图

看 report 是否更聚焦，而不是更泛。

## 8.4 单图对照

至少固定看：

- `task_0546`
- `task_0558`

原因：

- `0546` 更容易暴露“上下文太脏被误抬”的问题
- `0558` 更容易暴露“链条是否被过度压制”的问题

注意：

不是为它们写特判，而是拿它们做回归检查。

---

## 9. 如果某一步结果不符合预期，该怎么处理

## 9.1 Step 2A 不符合预期

如果 Prompt 改完后：

- tactic/technique 反而更泛
- 或 report 明显更长但没更准

处理方式：

1. 缩短 `support_relations` 的展示条数
2. 减少 `support_object_keys` 数量
3. 保留 `chain_kind` 和最关键 3-5 条 support relation

不要立刻进入 Step 2B。

## 9.2 Step 2B 不符合预期

如果 provenance rerank 后：

- top-N 大洗牌
- recall 明显掉

处理方式：

1. 缩小修正范围到 `[-4, +4]`
2. 先只保留 penalty，不做 bonus
3. 必要时只保留 `support_compactness`，先去掉 `provenance_density` 和 `support_coherence`

不要立刻进入 Step 2C。

## 9.3 Step 2C 不符合预期

如果 graph-check 后：

- 真阳性掉得太多

处理方式：

1. 只保留“明显分散才扣分”的规则
2. 取消跨度检查，只保留连通性检查
3. 最坏情况下完全回退 Step 2C，保留 2A + 2B

---

## 10. 给执行窗口的最终顺序

严格按下面顺序做：

1. 先做 Step 2A
2. 跑实验
3. 复盘结果
4. Step 2A 通过后，再做 Step 2B
5. 跑实验
6. 复盘结果
7. Step 2B 通过后，再做 Step 2C
8. 跑实验
9. 再决定要不要进入更大的第三阶段

不允许：

- 三步一起改完再跑
- 一边改 provenance rerank，一边顺手改 path_search
- 一边改 graph-check，一边顺手改 scorer 主公式

---

## 11. 这份文档真正想解决的问题

当前最大的浪费不是“sidecar 没生成出来”，而是：

**sidecar 已经有了，但系统自己没真正用。**

所以这次的目标不是再造新结构，而是：

**让系统一点一点真正消费这些新结构。**

只要按这份文档一步一步来，实验归因就会清楚很多，也更不容易再把系统带回“负优化但不知道是哪一层造成的”状态。
