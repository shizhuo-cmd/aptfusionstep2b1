# Holmes + APTShield Hybrid Reasoning Scheme (2026-05-28)

## 1. 目标

当前 `path_reason` 后半段已经比旧 `bundle + reason` 更稳定，但仍有两个明显问题：

1. 有些恶意任务图在 `module5_paths` 里根本产不出链条。
2. 产出的链条过于依赖窄化的 `P_* -> process_chain -> bridge` 逻辑，导致很多可以从日志识别出来的技战术没有进入候选链，也就无法被 `module6_reason` 正确映射。

本方案的目标不是继续微调现有少量 `P_* / B_* / O_*` 标签，而是把后半段升级为：

```text
恶意任务图
-> 回查原始日志
-> 构建任务局部事件证据图
-> APTShield 风格语义压缩
-> Holmes 风格 TTP/场景图
-> 场景 dossier
-> LLM ATT&CK 分析
```

核心思想：

- 用 APTShield 解决“证据太多、噪声太大”的问题。
- 用 Holmes 解决“攻击步骤之间怎么关联、怎么判断它们属于同一个攻击场景”的问题。
- 把当前过于窄的“进程链条”升级成“事件图上的攻击场景图”。

## 2. 当前实现的主要瓶颈

当前代码的关键瓶颈不是单个阈值，而是建模方式偏窄。

### 2.1 标签传播仍然是进程树中心化

当前真正的传播函数是 [src/apt_fusion/path_reason/path_propagator.py](D:/daima/APT-Fusion/src/apt_fusion/path_reason/path_propagator.py:10)。

- 传播只沿 `parent_process_guid -> child_process_guid`
- 只传播 `status_labels`
- 传播标签集合来自 `propagation.status_labels`
- 不沿对象边、网络边、会话边、权限变化边传播

也就是说，当前传播逻辑更接近：

```text
父进程上下文 -> 子进程上下文
```

而不是：

```text
网络输入 -> 进程 -> 落地文件 -> 新进程执行
凭证文件 -> 进程 -> 压缩/打包 -> 外发
持久化文件 -> 服务重启进程 -> 后续控制进程
```

### 2.2 候选链搜索只用“进程树边 + 窄 bridge”

当前搜链逻辑在 [src/apt_fusion/path_reason/path_search.py](D:/daima/APT-Fusion/src/apt_fusion/path_reason/path_search.py:12)：

- 进程树边：`parent -> child`
- bridge 边：对象先被前者写，再被后者读/执行

当前 bridge 构造在 [src/apt_fusion/path_reason/bridge_builder.py](D:/daima/APT-Fusion/src/apt_fusion/path_reason/bridge_builder.py:8)：

- 只接受少量对象标签白名单
- 只做 `write/create/rename -> read/exec/mmap/load`
- 不做网络接收后的跨进程语义桥接
- 不做会话/权限/认证类桥接
- 不做同一用户/同一 tty/同一 socket channel 的操作链关联

这会导致很多“真实可解释的攻击片段”无法形成路径。

### 2.3 现有标签库存太窄

当前真正实装的行为标签集中在 [src/apt_fusion/path_reason/path_labeler.py](D:/daima/APT-Fusion/src/apt_fusion/path_reason/path_labeler.py:10)。

主要集中在：

- 外网收发
- 临时文件/下载物执行
- shell / interpreter
- 读凭证/历史/业务数据
- 改持久化/权限配置
- 归档、删日志、内网横连

它们能覆盖一部分 Linux 主机攻击，但明显缺少以下重要语义：

- 服务端入口后的内存/解释执行链
- 账号滥用、认证尝试、会话继承
- 明确的发现类行为拆分
- 进程注入/模块加载/可疑 `LD_PRELOAD` / 可疑 service restart
- 文件打包、编码、加密、分块、出站联动
- 远程工具转移与后续执行的完整链
- 持久化对象被后续服务消费的链
- 单进程内多事件组合形成的 TTP

### 2.4 现有阶段模型太粗

当前候选链判断依赖 [configs/path_reason_default.yaml](D:/daima/APT-Fusion/configs/path_reason_default.yaml:176) 左右定义的五类阶段：

- `Entry`
- `ExecutionWeak`
- `ExecutionStrong`
- `TargetAccess`
- `FollowUp`

这会带来两个问题：

1. 阶段不够细，很多不同 ATT&CK 战术都被压到 `TargetAccess` 或 `FollowUp`。
2. 阶段组合门槛过粗，部分任务明明有明显恶意动作，但无法拼出合法组合，所以不出链。

### 2.5 同一组进程的不同攻击语义会被合并

当前路径去重键是：

```python
key = tuple(candidate.process_chain)
```

见 [src/apt_fusion/path_reason/path_search.py](D:/daima/APT-Fusion/src/apt_fusion/path_reason/path_search.py:75)。

这意味着：

- 相同 `process_chain`
- 但 bridge 不同
- 或关键对象不同
- 或证据组合不同

仍可能被合并成一条路径。

这对“同一组进程做了多类攻击动作”的任务非常不利。

## 3. 两篇论文最值得借鉴的部分

## 3.1 APTShield 提供的核心价值

APTShield 最值得迁移的不是“剪叶子”本身，而是三点：

1. `redundant semantics skipping`
   - 相同语义、没有带来状态变化的事件可以跳过
   - 关键是看实体语义有没有变化，而不是简单字符串去重

2. `non-viable entity pruning`
   - 先做标签和传播，再决定哪些退出叶子实体可以安全裁掉
   - 不是一上来就按叶子删

3. `state label + behavior label + transfer + aggregation`
   - 标签既可以打在进程，也可以打在文件
   - 标签既能沿控制流传播，也能沿数据流传播
   - 最后在关键实体上聚合出较高层攻击语义

APTShield 的弱点也很明显：

- 攻击阶段设计偏窄
- 更偏 Linux 主机行为总结
- 距 ATT&CK tactic/technique 仍有明显距离
- 不够适合直接做复杂多阶段场景关联

## 3.2 Holmes 提供的核心价值

Holmes 最值得迁移的是“从低层日志到高层场景图”的那一层。

它的核心不是简单多打几个标签，而是：

1. 先把低层事件匹配成高层 TTP 节点
2. 再用可疑信息流把这些 TTP 节点关联起来
3. 构造高层场景图 `High-level Scenario Graph`
4. 再用先决条件、因果依赖、祖先覆盖、良性前置条件抑制等机制降噪

Holmes 的强项在于：

- 能把“事件很多但分散”的证据升维成“攻击步骤之间的因果场景”
- 比纯路径搜索更适合解释多阶段 APT
- 比纯标签传播更能控制误关联

它对我们最关键的启发是：

> 后半段不应只搜“进程链”，而应构建“任务局部攻击场景图”。

## 4. 最终推荐架构

推荐把当前后半段改成下面这条主线：

```text
module1/module2 任务图检测
-> module3_evidence
-> module4_event_graph_compact
-> module5_ttp_graph
-> module6_scenario_search
-> module7_reason
```

如果不想立刻改 stage 名，也可以保留现有 `module4_compact/module5_paths/module6_reason` 外壳，但内部逻辑按这条架构重做。

### 4.1 每层职责

#### `module3_evidence`

保留现有“按恶意任务图回查原始日志”的入口，但要做两点增强：

1. 回查结果不只服务于 `ProcessState/ObjectState`
2. 回查时直接准备事件图构建所需字段

增强后，`NormalizedEvent` 需要尽量补齐：

- `subject_process_guid`
- `object_key`
- `object_version_hint`
- `uid/euid`
- `tty/session`
- `local_ip/local_port/remote_ip/remote_port`
- `bytes_in/bytes_out`，如果日志可得
- `cwd`
- `result/error_code`
- `exec_image`
- `fd or socket id`，如果日志可得

#### `module4_event_graph_compact`

这层取代当前“轻标签 + skip + episodes”的窄定义，改为：

1. 构建任务局部事件证据图
2. 做 APTShield 风格语义压缩
3. 保留对象版本和关键因果边

这里的核心产物不再只是 `retained_events + process_states + object_states`，而是：

- `event_graph.json`
- `retained_events.jsonl`
- `semantic_episodes.json`
- `entity_states.json`
- `object_versions.json`
- `flow_edges.json`

#### `module5_ttp_graph`

这层是 Holmes 的核心对应层。

职责：

1. 从压缩后的事件图里匹配 TTP 原子节点
2. 构造 TTP 之间的依赖边和信息流边
3. 形成任务局部 `TTP Scenario Graph`

输出：

- `ttp_matches.json`
- `scenario_graph.json`
- `scenario_components.json`

#### `module6_scenario_search`

职责：

1. 从 `TTP Scenario Graph` 提取候选攻击场景
2. 做 dedup、评分、置信分层
3. 形成给 LLM 的 dossier

输出：

- `candidate_scenarios.json`
- `candidate_scenarios.md`
- `scenario_dossiers/*.json`

#### `module7_reason`

职责：

1. 对单个场景 dossier 做 ATT&CK 分析
2. 明确 tactic/technique、证据、缺口、不确定性
3. 输出更结构化的战术总结

## 5. 新的核心数据模型

## 5.1 事件证据图而不是单纯进程链

推荐采用“实体节点 + 事件节点”的二部图模型。

### 节点类型

- `process_version`
  - 例：`proc:1234@ctrl2`
- `file_version`
  - 例：`file:/tmp/a.sh@v3`
- `socket_endpoint`
  - 例：`net:8.8.8.8:443`
- `session`
  - 例：`tty:pts/0`
- `user_context`
  - 例：`user:uid1000`
- `event`
  - 例：`evt:task_001:000042`
- `ttp`
  - 例：`ttp:TTP_EXEC_DOWNLOADED#1`

### 边类型

- `subject_of`
- `object_of`
- `spawn`
- `exec_image_of`
- `read_from`
- `write_to`
- `recv_from`
- `send_to`
- `load_from`
- `rename_to`
- `chmod_on`
- `same_object_version`
- `same_session`
- `same_user`
- `causal_flow`
- `ttp_supports`
- `ttp_depends_on`

### 为什么要引入事件节点

因为很多当前丢失的技战术，恰恰发生在：

- 同一进程不同时间的多事件组合
- 同一对象不同版本的前后因果
- 同一会话/同一凭证上下文下的多进程行为

只靠 `process_chain` 很难表示这些关系。

## 5.2 对象版本化

当前对象状态只有一个 `semantic_epoch`，已经是个好起点，但不够表达复杂版本链。

建议显式建立对象版本：

```json
{
  "object_key": "/tmp/a.sh",
  "versions": [
    {
      "version_id": "file:/tmp/a.sh@v1",
      "created_by_event": "evt_0012",
      "mutated_by_events": ["evt_0012", "evt_0019"],
      "labels": ["O_FILE_TEMP", "O_DOWNLOAD_ARTIFACT"]
    },
    {
      "version_id": "file:/tmp/a.sh@v2",
      "created_by_event": "evt_0031",
      "labels": ["O_FILE_TEMP", "O_EXEC_STAGER"]
    }
  ]
}
```

这样后续：

- bridge 不再只是“同一个 object_key”
- 而是“同一个对象版本或相邻版本”

这会显著减少误关联。

## 6. 压缩层怎么升级

## 6.1 保留 APTShield 风格 `semantic skip`

保留现有 [src/apt_fusion/path_reason/semantic_skip.py](D:/daima/APT-Fusion/src/apt_fusion/path_reason/semantic_skip.py) 思路，但键要从当前偏窄定义升级为：

```text
task_id
+ subject_entity_version
+ event_type_family
+ object_entity_version
+ process_context_signature
+ object_role_signature
+ session/user signature
```

只有当下面都不变时，才允许 skip：

- 主体控制语义不变
- 对象语义版本不变
- 上下文标签不变
- 没有触发新的 TTP 原子
- 没有跨关键时间窗

## 6.2 从“事件 episode”升级到“语义 flow segment”

当前 episode 仍偏事件桶聚合。

建议新增一层：

- `semantic_episode`: 同进程、同对象、同语义桶
- `flow_segment`: 一段连续的数据/控制流片段

例子：

```text
nginx RECV ext
-> nginx WRITE /var/www/upload/a.php
-> php-fpm EXEC /var/www/upload/a.php
```

这三条即使来自不同进程，也应能被折叠成一个更高层 `flow_segment`：

```json
{
  "segment_id": "seg_0007",
  "type": "remote_upload_to_exec",
  "events": ["evt_11", "evt_15", "evt_21"],
  "entities": ["proc:nginx", "file:/var/www/upload/a.php", "proc:php-fpm"],
  "labels": ["O_UPLOAD_ARTIFACT", "T_REMOTE_TOOL_TRANSFER", "T_EXECUTION_FROM_UPLOAD"]
}
```

这一步是后续 TTP 图的关键中间层。

## 6.3 裁剪规则不要只盯叶子进程

推荐把当前 APTShield 式裁剪扩成三类：

1. `event pruning`
   - 语义不变重复事件
2. `entity pruning`
   - 无关键标签、无版本变化、无 TTP 支撑的叶子实体
3. `segment pruning`
   - 不支撑任何高层 TTP 的低价值 flow segment

裁剪顺序必须是：

```text
先打初始标签
-> 再匹配 TTP 原子
-> 再做裁剪
```

不要在 TTP 建立之前粗暴删掉很多看似“普通”的中继节点。

## 7. 标签体系怎么扩展

推荐把当前单层 `P_* / B_* / O_* / A_*` 扩成四层。

## 7.1 上下文标签 `C_*`

替代现在过窄的 `P_*`。

示例：

- `C_WEB_ENTRY`
- `C_REMOTE_SESSION`
- `C_EXTERNAL_INPUT`
- `C_DOWNLOADER`
- `C_INTERPRETER`
- `C_SERVICE_PROCESS`
- `C_PRIV_USER`
- `C_HIGH_VALUE_DATA_SCOPE`
- `C_INTERNAL_ADMIN_SCOPE`
- `C_C2_REACHABLE`

这些标签主要表达“这个实体目前处在哪种攻击上下文中”。

## 7.2 对象角色标签 `O_*`

扩展当前对象标签。

示例：

- `O_UPLOAD_ARTIFACT`
- `O_DOWNLOAD_ARTIFACT`
- `O_TEMP_EXEC_ARTIFACT`
- `O_SCRIPT_ARTIFACT`
- `O_TOOL_BINARY`
- `O_CREDENTIAL_STORE`
- `O_AUTH_CONFIG`
- `O_PERSISTENCE_ARTIFACT`
- `O_LOG_ARTIFACT`
- `O_ARCHIVE_ARTIFACT`
- `O_DISCOVERY_TARGET`
- `O_COLLECTION_TARGET`
- `O_STAGING_ARTIFACT`

## 7.3 行为能力标签 `B_*`

比现在更细，明确“谁做了什么”。

推荐至少覆盖：

- `B_EXTERNAL_RECV`
- `B_EXTERNAL_CALLBACK`
- `B_REMOTE_SERVICE_ACCEPT`
- `B_DROP_UPLOAD_ARTIFACT`
- `B_DROP_DOWNLOAD_ARTIFACT`
- `B_EXEC_UNTRUSTED_BINARY`
- `B_EXEC_SCRIPT`
- `B_EXEC_INTERPRETER_FETCH`
- `B_LOAD_SUSPECT_MODULE`
- `B_SHELL_CONTROL`
- `B_DISCOVERY_USER_HOST_NET`
- `B_READ_CREDENTIAL`
- `B_READ_AUTH_CONFIG`
- `B_READ_HISTORY`
- `B_READ_BUSINESS_DATA`
- `B_MASS_COLLECTION`
- `B_CREATE_ARCHIVE`
- `B_ENCODE_OR_ENCRYPT_STAGING`
- `B_MOD_PERSISTENCE`
- `B_MOD_AUTHZ_OR_SUDO`
- `B_TAMPER_LOG`
- `B_PRIV_ESC_SIGNAL`
- `B_INTERNAL_SCAN`
- `B_LATERAL_CONNECT`
- `B_LATERAL_AUTH_ATTEMPT`
- `B_C2_BEACON`
- `B_EXFIL_SEND`

## 7.4 TTP 原子标签 `T_*`

这是 Holmes 层真正需要的新层。

每个 `T_*` 不是简单事件标签，而是一个小型“高层攻击原子”。

示例：

- `T_WEBSHELL_ENTRY`
- `T_REMOTE_TOOL_TRANSFER`
- `T_EXECUTION_FROM_UPLOAD`
- `T_EXECUTION_FROM_DOWNLOAD`
- `T_COMMAND_SHELL`
- `T_SYSTEM_DISCOVERY`
- `T_NETWORK_DISCOVERY`
- `T_CREDENTIAL_ACCESS`
- `T_COLLECTION`
- `T_STAGING_ARCHIVE`
- `T_PERSISTENCE_CRON`
- `T_PERSISTENCE_AUTHKEY`
- `T_PRIVILEGE_ESCALATION`
- `T_LATERAL_SSH`
- `T_C2_CHANNEL`
- `T_EXFILTRATION`
- `T_DEFENSE_EVASION_LOG_TAMPER`

`T_*` 是场景图的节点，不直接等于 ATT&CK 技术，但应有较强 prior 映射。

## 8. 标签传播必须从“只沿父子树传 P_*”升级

推荐把传播拆成四种。

## 8.1 控制流传播

沿：

- `fork`
- `clone`
- `exec`
- `setuid/sudo/su`
- `service restart`

传播的不是所有标签，而是“上下文标签”和“会话控制标签”。

例如：

- `C_WEB_ENTRY`
- `C_REMOTE_SESSION`
- `C_EXTERNAL_INPUT`
- `C_C2_REACHABLE`

## 8.2 数据流传播

沿：

- `recv -> process`
- `process -> write file`
- `file -> exec/load process`
- `process -> archive`
- `process -> send external`

传播的核心是：

- 对象角色标签
- 可疑来源标签
- collection / staging / exfil 语义

例如：

```text
外部 RECV
-> 进程带 C_EXTERNAL_INPUT
-> 进程写出文件
-> 文件拿到 O_DOWNLOAD_ARTIFACT
-> 其他进程执行该文件
-> 触发 T_EXECUTION_FROM_DOWNLOAD
```

## 8.3 会话/身份传播

这是当前项目几乎缺失的一层。

沿：

- 同一 `tty/session`
- 同一 `uid/euid`
- 认证前后进程
- `sshd -> shell -> scp/curl`

传播的核心是：

- `C_REMOTE_SESSION`
- `C_INTERNAL_ADMIN_SCOPE`
- lateral movement 相关上下文

## 8.4 场景依赖传播

这是 Holmes 部分。

不是把标签直接传给实体，而是把：

- `T_EXECUTION_FROM_UPLOAD`
- `T_COMMAND_SHELL`
- `T_CREDENTIAL_ACCESS`
- `T_EXFILTRATION`

之间建立依赖边：

```text
T_WEBSHELL_ENTRY -> T_EXECUTION_FROM_UPLOAD
T_EXECUTION_FROM_UPLOAD -> T_COMMAND_SHELL
T_COMMAND_SHELL -> T_SYSTEM_DISCOVERY
T_COMMAND_SHELL -> T_CREDENTIAL_ACCESS
T_CREDENTIAL_ACCESS -> T_EXFILTRATION
```

这一步决定的不是“某个子进程也有标签”，而是“这几个攻击步骤应属于同一攻击场景”。

## 9. Holmes 式场景图怎么落地

## 9.1 引入 `TTPMatch`

建议新增结构：

```json
{
  "ttp_id": "ttp_00017",
  "task_id": "task_0042",
  "ttp_type": "T_EXECUTION_FROM_DOWNLOAD",
  "stage_family": "Execution",
  "subject_process_guid": "2012",
  "support_event_ids": ["evt_101", "evt_108"],
  "support_entity_ids": ["proc:2012", "file:/tmp/a.sh@v2"],
  "prerequisites_satisfied": ["C_EXTERNAL_INPUT", "O_DOWNLOAD_ARTIFACT"],
  "confidence": 0.91,
  "severity": 0.84
}
```

## 9.2 引入 `ScenarioEdge`

```json
{
  "src_ttp_id": "ttp_00011",
  "dst_ttp_id": "ttp_00017",
  "edge_type": "causal_flow",
  "shared_entities": ["file:/tmp/a.sh@v2"],
  "shared_events": ["evt_101"],
  "dependency_reason": "downloaded artifact was later executed",
  "confidence": 0.95
}
```

## 9.3 引入 `ScenarioGraph`

```json
{
  "scenario_id": "scenario_0004",
  "task_id": "task_0042",
  "ttp_nodes": ["ttp_00011", "ttp_00017", "ttp_00021"],
  "edges": ["edge_0003", "edge_0004"],
  "covered_stages": ["InitialAccess", "Execution", "CredentialAccess"],
  "risk_score": 92.3
}
```

## 9.4 用先决条件和覆盖约束降噪

借鉴 Holmes，新增以下约束：

1. `prerequisite gating`
   - 例如 `T_EXFILTRATION` 至少应有 `Collection/Staging` 或高价值读取支撑

2. `ancestral cover`
   - 场景中的高层 TTP 应被至少一个上游可疑 TTP 或高风险上下文覆盖

3. `benign prerequisite suppression`
   - 例如仅有 `scp`、仅有 shell、仅有 archive tool，不应自动升级为高风险场景

4. `flow continuity requirement`
   - 两个 TTP 之间必须共享实体版本、共享会话、共享认证上下文、或存在明确时间因果

这套机制会明显优于当前单纯的：

```text
process tree + bridge + stage set
```

## 10. 为什么这样能解决“有些任务图不出链”

当前“不出链”最常见的原因是：

1. 没有足够强的 `process_chain`
2. 没有命中少量 stage 组合
3. 同一恶意片段主要发生在单进程内部多事件组合
4. 关键关系存在于对象/会话/权限链，而不是父子进程链

新方案下，即使没有好看的进程树链，也可以靠：

- 单进程多事件形成 `TTPMatch` 序列
- 同一对象版本形成 `causal_flow`
- 同一会话形成 `remote session subgraph`
- 同一用户上下文形成 `credential/lateral scenario`

只要能组成高层 `ScenarioGraph`，就可以输出候选场景，不再依赖当前狭义路径。

## 11. 为什么这样能提升技战术识别

当前 `module6_reason` 看到的是偏窄的 `CandidatePath` dossier。

新方案下，LLM 看到的应该是：

1. 场景级 TTP 节点
2. TTP 之间的因果/信息流边
3. 每个 TTP 的关键支撑事件
4. 对象版本与会话上下文
5. 已经做过规则侧降噪的候选 ATT&CK prior

这会把 LLM 的任务从：

```text
在一堆路径事件里猜 ATT&CK
```

变成：

```text
对一个已结构化的攻击场景做 tactic/technique 映射和解释
```

这是更适合 LLM 的工作分配。

## 12. 推荐的 ATT&CK 中间阶段体系

不要继续只用：

- `Entry`
- `ExecutionWeak`
- `ExecutionStrong`
- `TargetAccess`
- `FollowUp`

建议改成 11 类中间阶段：

- `InitialAccess`
- `Execution`
- `Persistence`
- `PrivilegeEscalation`
- `DefenseEvasion`
- `CredentialAccess`
- `Discovery`
- `LateralMovement`
- `Collection`
- `CommandAndControl`
- `Exfiltration`

这些中间阶段不一定直接等于 ATT&CK tactic 输出，但必须足够细，能承接更丰富的日志可见行为。

## 13. 对当前代码文件的改造建议

## 13.1 保留但增强

- [src/apt_fusion/path_reason/module3_evidence_recover.py](D:/daima/APT-Fusion/src/apt_fusion/path_reason/module3_evidence_recover.py)
  - 保留作为回查入口
  - 增加会话、用户、字节数、对象版本提示等字段

- [src/apt_fusion/path_reason/module4_semantic_compact.py](D:/daima/APT-Fusion/src/apt_fusion/path_reason/module4_semantic_compact.py)
  - 保留 semantic skip 思路
  - 升级为事件图压缩器

## 13.2 建议重写/拆分

- `path_labeler.py`
  - 当前是窄行为标签器
  - 建议拆成：
    - `context_labeler.py`
    - `behavior_labeler.py`
    - `ttp_matcher.py`

- `path_propagator.py`
  - 当前只做父子 BFS
  - 建议重写为：
    - `graph_propagator.py`
  - 支持控制流、数据流、会话流、身份流传播

- `bridge_builder.py`
  - 当前只是窄桥接器
  - 建议改成：
    - `flow_linker.py`
  - 支持多种 `causal_flow`

- `path_search.py`
  - 建议从进程链搜索器升级为：
    - `scenario_search.py`
  - 搜索对象应是 `TTPMatch` 图而非进程序列

- `module5_path_finder.py`
  - 建议变成 TTP/场景图总控

- `module6_attack_reason.py`
  - 建议改为消费 `ScenarioDossier`
  - 不再以 `CandidatePath` 为主输入

## 13.3 推荐新增结构

建议在 [src/apt_fusion/path_reason/path_schemas.py](D:/daima/APT-Fusion/src/apt_fusion/path_reason/path_schemas.py) 新增：

- `EvidenceNode`
- `EvidenceEdge`
- `ObjectVersion`
- `FlowSegment`
- `TTPMatch`
- `ScenarioEdge`
- `ScenarioGraph`
- `ScenarioCandidate`

## 14. 迁移策略

不要一次性把当前后半段全部推倒重来。推荐三阶段迁移。

### Phase 1: 并行生成事件图和 TTP 原子

保留现有 `CandidatePath` 输出，同时并行生成：

- `event_graph.json`
- `ttp_matches.json`

先验证：

- 原先不出链的任务，现在是否至少能产出 TTP 原子或小场景组件

### Phase 2: 用场景图替代当前 `path_search`

让 `ScenarioGraph` 成为主候选输出，保留旧 `CandidatePath` 仅做调试对照。

重点验证：

- strict ATT&CK recall
- candidate scenario count
- off-window high-risk rate
- duplicate collapse rate

### Phase 3: 让 LLM 只看 `ScenarioDossier`

`module7_reason` 改为只消费：

- TTP 节点
- 场景边
- 支撑事件
- ATT&CK candidate priors

而不是旧式进程路径 dossier。

## 15. 评估重点

除了现有窗口级指标，建议新增：

1. `NonEmptyScenarioRate`
   - 检出的恶意任务中，有多少能产出至少一个候选场景

2. `ScenarioSupportDensity`
   - 每个场景中，真正支撑 TTP 的事件占比

3. `ScenarioDuplicationRate`
   - 多个候选场景是否只是同证据轻微变体

4. `TTPCoverage`
   - 每个官方攻击窗口，系统至少恢复了多少不同攻击步骤

5. `LLMReasoningYield`
   - 每个场景 dossier 输入后，LLM 是否产出有效 tactic/technique

## 16. 推荐的最小可行版本

如果只做第一版 MVP，我建议先做这五件事：

1. 把 `module4_compact` 输出从“状态表 + retained events”扩成“事件证据图 + 对象版本表”
2. 把 `path_labeler.py` 扩成更完整的 `B_*` 与 `T_*` 匹配器
3. 把 `path_propagator.py` 从“父子 BFS”扩成“控制流 + 数据流”传播
4. 用 `TTPMatch + ScenarioEdge` 替代当前单纯 `process_chain` 路径
5. 把 dedup key 从 `process_chain` 改成：
   - `scenario_signature = ttp_types + key_entities + key_object_versions + time_bucket`

这是最小但最有收益的一步。

## 17. 最终结论

当前后半段的问题，不是“标签太少”这么简单，而是：

- 事件表示过弱
- 传播路线过窄
- 候选链构造仍然是进程树中心化
- 缺少 Holmes 式高层场景图

最合理的升级方向不是继续在现有 `P_* / B_* / path_search` 上小修小补，而是：

1. 用 APTShield 把日志压成更干净的任务局部事件证据图
2. 用更完整的标签体系把低层事件升维成高层 TTP 原子
3. 用 Holmes 的场景图思想把这些 TTP 关联成攻击场景
4. 最后把场景 dossier 交给 LLM 做 ATT&CK 分析

这条路线最有希望同时解决：

- “有些任务图不出链”
- “出的链条技战术识别效果一般”

这两个当前最核心的问题。
