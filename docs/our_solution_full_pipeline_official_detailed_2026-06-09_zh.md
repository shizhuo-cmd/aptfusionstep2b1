# 我们方案全流程详解：从原始日志到 ATT&CK 战术输出

本文面向汇报、答辩和方案说明，目标不是只给一个高层概览，而是把“系统现在实际上是怎么做的”讲清楚，包括：

1. 全流程一共分成哪几块。
2. 每一块的输入、输出、主要方法和设计动机。
3. 候选链是怎么构造的。
4. 中间行为 `claims` 是怎么生成的。
5. `claims` 是怎么进一步映射成 ATT&CK 战术的。
6. 代码里一些自造词到底是什么意思。

为了对外表达统一，本文不使用内部实验代号。另一个需要说明的点是：代码内部仍保留了一些历史命名，例如 `holmes_claims.py`、`holmes_matched_atoms`。本文统一把这一层叫作“中间行为 claim 层”或“行为原子层”，它们说的是同一件事，不代表系统里还有另一条独立算法分支。

## 0. 先看主线：全流程一共 7 块

我们方案的完整主线可以拆成 7 个连续模块：

1. 任务图构建
2. 任务图恶意检测
3. 围绕可疑任务回查原始日志
4. 语义压缩、标签赋值和状态维护
5. 候选攻击链恢复与补强
6. 中间行为 claim 生成与 claim graph 构建
7. ATT&CK 战术映射与评估

把它们连起来就是：

```text
原始日志
-> module1 任务图构建
-> module2 任务图恶意检测
-> module3 围绕可疑任务回查原始日志
-> module4 语义压缩、标签和状态维护
-> module5 候选攻击链恢复、打分和补强
-> module6 中间行为 claim 生成
-> module6 ATT&CK tactics-only + LLM 映射
-> evaluation
```

这条主线背后的核心思想是：

- 全量日志太大，不能直接端到端做解释，必须先缩小范围。
- 图级恶意检测只能告诉我们“哪个任务图值得看”，不能直接告诉我们“里面发生了哪条攻击链”。
- 原始日志太碎，必须在进入推理前做语义压缩、状态维护和对象传递恢复。
- 在 ATT&CK 之前插入一层“中间行为 claim”可以把证据组织得更稳定，也更方便定位误差到底出在“链条恢复”还是“ATT&CK 映射”。

## 1. 第一块：任务图构建

### 1.1 这一块要解决什么问题

这一块的任务，是把全量原始日志切成许多可分析的局部任务图。后续的恶意检测不是直接在整机全时段日志上做，而是在这些任务图上做。

这里的“任务图”可以理解为：

> 从全局进程关系图里切出的一张局部子图，它代表一组彼此关联、时空上相对连续的进程活动。

### 1.2 它读什么输入

这一块主要利用原始日志中的：

- 进程或 subject 记录
- 父子进程关系
- 进程之间的图连接关系
- 进程相关的事件上下文

### 1.3 它怎么切任务图

我们方案对外只讲当前实际使用的 `fanout` 分割规则。

默认思路是：

> 如果一个节点下面有效子节点太多，就把它看作一个新的分割点，不再把它下面所有分支都塞进同一张任务图。

常见配置是：

- `task_component_split_mode = fanout`
- `task_component_child_threshold = 2`

`fanout` 规则可以拆成 4 步：

1. 从原始关系中建立父到子的映射。
2. 在所有有父节点的进程里寻找候选分割点。
3. 反复迭代，统计每个候选点的 `effective_children`。
4. 如果一个节点的 `effective_children > child_threshold`，就把它标为分割点。

这里的 `effective_children` 不是简单的“孩子总数”，而是：

> 去掉那些本身已经被判成分割点的子节点之后，当前节点还剩多少个继续向下展开的有效子节点。

分割点稳定之后，再开始正式构建任务图：

- 没有已知父节点的自然根，会成为任务图根。
- 分割点本身也会成为新的任务图根。
- 从每个任务图根往下做 DFS。
- 如果 DFS 走到某个子节点，而这个子节点本身也是分割点，那么它会被纳入当前任务图，但不会继续沿着它往下展开。

因此它会留下一个很重要的概念：

- `boundary_node`

它表示：

> 这个节点被当前任务图看见了，但它也是通往另一个子任务图的边界节点。

### 1.4 这一块还做了哪些表示准备

任务图切好之后，每个进程节点还要有一个可用于图模型的向量表示。当前实现里默认有两类信息：

- 进程表示向量
- 进程统计特征

其中：

- 进程表示向量主要用于 GraphSAGE 主干。
- 进程统计特征默认不再拼接进 GraphSAGE 节点输入，而是单独留给后面的图统计 late fusion 分支。

这是当前方案的一个明确设计点：

- 默认 `GraphSAGE` 只吃进程表示向量。
- 统计特征只在后面的图级 sidecar 分支使用。
- 只有显式打开 `graphsage_append_ocr_stat_features=true` 时，才恢复成“统计特征拼接到 GraphSAGE 节点输入”的旧式做法。

### 1.5 进程统计特征是什么

这组特征是重新扫描日志得到的进程级统计量，典型包括：

- `stat_out_*`：该进程向外触发各种行为的次数
- `stat_in_*`：其他实体对该进程触发各种行为的次数
- `stat_avg_idle_time`
- `stat_max_idle_time`
- `stat_min_idle_time`
- `stat_cumulative_active_time`
- `stat_lifespan`

### 1.6 这一块的主要输出

常用输出包括：

- `process_embeddings.csv`
- `task_subgraphs.json`
- `process_segmentation_edges.csv`
- `tapas_native_graphs.pt`
- `tapas_native_module1_summary.json`

## 2. 第二块：任务图恶意检测

### 2.1 这一块要解决什么问题

这一块不是恢复攻击链，而是先从所有任务图里找出“值得进一步回查原始日志”的可疑任务图。

### 2.2 它的总体结构

当前方案采用双分支加 late fusion：

1. `GraphSAGE` 主分支
2. 图统计 `sidecar` 分支
3. 最后做概率融合

### 2.3 GraphSAGE 主分支在学什么

GraphSAGE 主分支的输入是：

- 任务图结构
- 每个进程节点的表示向量

它回答的问题是：

> 只从图结构和节点表示出发，这张任务图整体像不像恶意图。

当前默认实现里，这里的节点表示不包含进程统计特征，只包含进程表示向量本身。

### 2.4 图统计 sidecar 分支在学什么

图统计 sidecar 不替代 GraphSAGE，而是从“整张图的聚合统计画像”再给一个分数。

它对每张任务图的统计表示构造方式是：

1. 收集该任务图中所有进程的统计特征向量。
2. 分别做逐列聚合：`mean`、`max`、`std`。
3. 再拼上 3 个图级统计量：
   - `active_node_ratio`
   - `nonzero_entry_ratio`
   - `log_node_count`

如果进程统计特征维度是 `d`，那么图统计 sidecar 的图级输入维度就是：

```text
d * 3 + 3
```

这一分支优先使用：

- `XGBClassifier`

如果运行环境没有 `xgboost`，才退化到：

- `HistGradientBoostingClassifier`

### 2.5 late fusion 怎么做

当前默认融合公式是：

```text
fused_prob = (1 - weight) * graphsage_prob + weight * stats_prob
```

其中：

- `graphsage_prob` 是 GraphSAGE 输出的恶意概率
- `stats_prob` 是图统计 sidecar 输出的恶意概率
- `weight` 是 `task_graph_stat_fusion_weight`

这意味着：

- `weight` 越大，统计分支影响越大
- `weight` 越小，GraphSAGE 主分支影响越大

### 2.6 任务图内部的重点归因是怎么做的

这一块除了给图打分，还会给后面模块准备“任务先验”。

它会输出任务内重点进程和重点边，供后面回查原始日志时当锚点使用。常见做法是：

- 给每个进程节点打一个显式加权分数
- 再从图里导出 `top_processes`
- 再给关键边导出 `top_edges`

典型的进程打分形式可以概括成：

```text
node_score =
  0.45 * feature_norm
  + 0.20 * degree
  + 0.15 * out_degree
  + 0.10 * in_degree
  + 0.10 * max(root_bonus, bridge_degree_norm)
```

这里的含义是：

- `feature_norm`：节点向量范数
- `degree`：总度数
- `out_degree`：出度
- `in_degree`：入度
- `root_bonus`：如果该节点是图根，就给额外奖励
- `bridge_degree_norm`：与跨分割边界相关的归一化程度

### 2.7 这一块的主要输出

常用输出包括：

- `suspicious_tasks.json`
- `process_scores.csv`
- `task_meta_rich.json`
- `task_attribution.json`
- `task_subgraph_summary.json`

## 3. 第三块：围绕可疑任务回查原始日志

### 3.1 这一块要解决什么问题

模块 2 只告诉我们“哪张任务图可疑”，但它没有保留足够丰富的原始事件细节。要恢复攻击链，就必须回到原始日志里重新取数。

### 3.2 什么是 `TaskPrior`

在回查开始之前，系统会把任务图检测阶段的结果合并成一个 `TaskPrior`。它本质上是：

> 一份关于“该任务图哪里最值得看”的先验摘要。

它通常包含：

- 任务图分数和概率
- `root_process_ids`
- `task_root_id`
- `boundary_node_ids`
- `top_processes`
- `top_edges`
- `graphsage_probability`
- `stats_probability`

### 3.3 回查入口是怎么定的

回查不是从全量日志无差别扫描，而是围绕任务图里的若干锚点做局部恢复。

常用锚点来源是：

- `prior.root_process_ids`
- 如果没有 root，则退化到 `prior.task_root_id`
- `boundary_node_ids`
- `top_processes`

### 3.4 回查的核心逻辑

它可以概括为：

1. 为每个任务建立一个 `frontier`
2. 扫描原始日志
3. 只保留能匹配当前 `frontier` 的事件
4. 遇到新相关进程或对象，就把它们加入下一轮 `frontier`
5. 重复若干跳，直到达到 `local_context_hops`

这一步决定了什么事件会被重新拉回当前任务的局部证据图里。

### 3.5 标准化事件做了什么

回查得到的原始事件，在进入后续模块前都会标准化为统一结构。标准化后的事件通常包含：

- 统一的 `event_id`
- 原始日志标识 `raw_log_id`
- `task_id`
- 时间戳和顺序号
- `process_guid`
- 进程名、可执行文件、命令行
- `parent_process_guid`
- `event_type`
- `object_key`
- `object_class`
- `semantic_flow_direction`
- 网络四元组信息

### 3.6 什么是局部证据图

这一块会把任务内恢复出来的证据组织成一个 `task_local_evidence_graph`。它通常包括：

- `process_nodes`
- `object_nodes`
- `event_edges`
- `anchor_processes`
- `boundary_node_ids`
- `cross_task_link_refs`

它的作用是：

> 为后面的标签传播、对象版本恢复和候选链搜索提供一个任务内的局部证据空间。

### 3.7 这一块的主要输出

常用输出包括：

- `normalized_events/*.jsonl`
- `entity_index/*.json`
- `process_event_index/*.json`
- `object_event_index/*.json`
- `task_evidence_frontier/*.json`
- `task_local_evidence_graph/*.json`

## 4. 第四块：语义压缩、标签赋值和状态维护

### 4.1 这一块要解决什么问题

原始回查事件仍然太碎，不能直接做攻击链推理。必须把它们压缩成一组更稳定的中间状态：

- 进程状态
- 对象状态
- 对象版本
- 事件级标签

### 4.2 规则的总来源

这一层大部分规则来自：

- `configs/path_reason_default.yaml`

也就是说，下面几类东西基本都由这份规则文件控制：

- 进程词典
- 对象类别
- 标签赋值
- 语义去重
- bridge 允许与否
- 候选链打分阈值

### 4.3 进程词典有哪些

当前规则文件中维护了多组进程词典，典型包括：

- `web_services`
- `remote_services`
- `shells`
- `interpreters`
- `downloaders`
- `network_tools`
- `archive_tools`
- `common_daemons`

这些词典会反复被复用，用来判断：

- 某进程是不是 Web 上下文
- 某进程是不是远程登录上下文
- 某进程是不是 shell 或 interpreter
- 某进程是不是下载器、归档器、网络工具

### 4.4 对象类别有哪些

当前对象语义分类常见包括：

- `temp_file`
- `credential_file`
- `history_file`
- `business_file`
- `persistence_file`
- `privilege_file`
- `auth_config_file`
- `log_file`
- `archive_file`
- `external_ip`
- `internal_ip`

它们通常通过以下线索识别：

- 路径前缀
- 路径包含关系
- 路径后缀
- 网络角色

例如：

- `/tmp/`、`/var/tmp/`、`/dev/shm/` 会偏向 `temp_file`
- `/etc/passwd`、`/etc/shadow` 会偏向 `credential_file`
- `/var/log` 会偏向 `log_file`
- `.zip`、`.tar`、`.gz`、`.7z` 会偏向 `archive_file`

### 4.5 进程上下文标签是怎么打的

这一步会给进程打轻量上下文标签，核心包括：

| 标签 | 阶段映射 | 含义 |
| --- | --- | --- |
| `P_WEB_CTX` | `Entry` | 进程处在 Web 服务或 Web 写路径上下文 |
| `P_REMOTE_CTX` | `Entry` | 进程处在远程登录或远程服务上下文 |
| `P_NET_CTX` | `Entry` | 进程和网络通信有明显关联 |
| `P_UNTRUSTED_CTX` | `Entry` | 进程接触过外部输入、下载物或可疑写入对象 |
| `P_HIGH_VALUE_CTX` | `TargetAccess` | 进程碰到高价值文件或敏感对象 |
| `P_SUSPECT_CTRL_CTX` | `ExecutionWeak` | 进程执行过可疑控制链动作 |

这里的阶段 `Entry / ExecutionWeak / ExecutionStrong / TargetAccess / FollowUp` 不是 ATT&CK，也不是论文原生阶段，而是我们用来组织候选链结构的内部阶段桶。

### 4.6 关键行为标签是怎么打的

候选链最依赖的一组行为标签如下：

| 标签 | 阶段映射 | 典型含义 |
| --- | --- | --- |
| `B_EXTERNAL_RECV` | `Entry` | 从外部接收内容 |
| `B_EXTERNAL_SEND` | `FollowUp` | 向外部发送内容 |
| `B_EXEC_TEMP` | `ExecutionStrong` | 执行临时文件 |
| `B_EXEC_DOWNLOADED` | `ExecutionStrong` | 执行下载文件 |
| `B_EXEC_UPLOADED` | `ExecutionStrong` | 执行上传文件 |
| `B_EXEC_SUSPECT_WRITTEN` | `ExecutionStrong` | 执行先写后执行的可疑对象 |
| `B_SHELL_SPAWN` | `ExecutionWeak` | 可疑 shell 启动 |
| `B_SCRIPT_EXEC` | `ExecutionWeak` | 可疑脚本或解释器执行 |
| `B_INTERPRETER_LAUNCH` | `ExecutionWeak` | 解释器启动 |
| `B_READ_CRED` | `TargetAccess` | 读取凭据类文件 |
| `B_READ_HISTORY` | `TargetAccess` | 读取历史类文件 |
| `B_READ_BUSINESS` | `TargetAccess` | 读取业务数据 |
| `B_MASS_FILE_ACCESS` | `TargetAccess` | 大规模读文件 |
| `B_WRITE_PERSISTENCE` | `FollowUp` | 写持久化位置 |
| `B_WRITE_PRIV_CONFIG` | `TargetAccess` | 修改提权配置 |
| `B_ARCHIVE_DATA` | `FollowUp` | 归档数据 |
| `B_DELETE_LOG` | `FollowUp` | 删日志、重命名日志或清理痕迹 |
| `B_LATERAL_CONNECT` | `FollowUp` | 内网连接或横向连接 |
| `B_REMOTE_LOGIN_SERVICE` | `Entry` | 远程服务入口 |
| `B_WEB_WRITE` | `Entry` | 写 Web / upload 路径 |

### 4.7 对象标签是怎么打的

关键对象标签包括：

| 标签 | 阶段映射 | 典型含义 |
| --- | --- | --- |
| `O_NET_EXTERNAL` | `Entry` | 对象是外部 IP |
| `O_FILE_TEMP` | `ExecutionWeak` | 对象是临时文件 |
| `O_FILE_UPLOADED` | `Entry` | 对象是上传文件 |
| `O_FILE_DOWNLOADED` | `Entry` | 对象是下载文件 |
| `O_FILE_NONEXIST` | `ExecutionWeak` | 访问不存在文件 |
| `O_SUSPECT_WRITTEN_EXECUTABLE` | `ExecutionStrong` | 对象先被写，后被执行或加载 |
| `O_CREDENTIAL` | `TargetAccess` | 对象是凭据文件 |
| `O_HISTORY` | `TargetAccess` | 对象是历史文件 |
| `O_BUSINESS_DATA` | `TargetAccess` | 对象是业务文件 |
| `O_AUTH_CONFIG` | `TargetAccess` | 对象是认证配置 |
| `O_PERSISTENCE` | `FollowUp` | 对象是持久化位置 |
| `O_PRIV_CONFIG` | `TargetAccess` | 对象是提权相关配置 |
| `O_ARCHIVE` | `FollowUp` | 对象是归档文件 |
| `O_SECURITY_LOG` | `FollowUp` | 对象是安全日志 |

### 4.8 语义去重是怎么做的

语义去重，也就是 `semantic skip`，目的是避免大量重复、同义、没有新增信息的事件把时间线淹没。

默认思路是：

> 如果同一进程对同一对象又做了一次语义上等价、且上下文状态没有发生关键变化的访问，那么后一个事件可以不再保留到下游推理时间线里。

常见默认参数是：

- 启用：`true`
- TTL：`600` 秒
- 最大表大小：`100000`
- 表满后清空：`true`

它不会无条件去重，而是要求一组条件同时成立，例如：

- 同一 `semantic_key`
- 进程标签签名没变
- 对象标签签名没变
- 对象语义 epoch 没变
- 进程控制 epoch 没变
- 事件发生在 TTL 窗口内

### 4.9 哪些事件强制保留

有些事件默认不走普通语义去重，因为它们太关键。典型包括：

- `EXEC`
- `FORK`
- `CLONE`
- `CONNECT`
- `ACCEPT`
- `SEND`
- `RECV`
- `EXIT`
- `CHMOD`
- `CHOWN`
- `RENAME`
- `DELETE`

一些高价值对象类别也会倾向于强制保留，例如：

- `temp_file`
- `credential_file`
- `history_file`
- `business_file`
- `persistence_file`
- `privilege_file`
- `external_ip`

### 4.10 对象版本和语义失效是怎么维护的

系统会维护对象版本与语义 epoch。一旦发生关键变化，旧语义就会失效，后续访问不能再和之前视为同一个稳定语义状态。

常见触发条件包括：

- 对象发生 `WRITE / CREATE / TRUNCATE / CHMOD / CHOWN / RENAME / DELETE`
- 进程收到外部 `RECV`
- 进程发生 `EXEC / LOAD / MMAP`

这一步的作用是：

> 把“同一个路径名下的不同时刻版本”区分开，避免把先前的正常对象和后续被篡改的对象混成一个对象语义。

### 4.11 状态传播做了什么

部分进程上下文标签会沿父子进程传播，例如：

- `P_WEB_CTX`
- `P_REMOTE_CTX`
- `P_NET_CTX`
- `P_UNTRUSTED_CTX`
- `P_HIGH_VALUE_CTX`
- `P_SUSPECT_CTRL_CTX`

传播的目的，是把“这个子进程从哪里来”的上下文补到后代进程上，帮助候选链恢复时保住攻击前因。

另外，如果某个子进程已经明显可疑，父进程还可能得到一个聚合标签：

- `A_CHILD_SUSPICIOUS`

## 5. 第五块：候选攻击链恢复与补强

### 5.1 这一块要解决什么问题

经过模块 4 之后，我们已经有：

- 保留下来的关键事件
- 进程状态
- 对象状态
- 对象版本
- 标签来源

这一块的目标，是把这些离散证据恢复成少量高价值的候选攻击链。

### 5.2 什么是 `BridgeEdge`

候选链不仅依赖父子进程边，还依赖对象桥接边 `BridgeEdge`。

它表达的含义是：

> 某对象先被进程 A 写入、修改或生产，随后被进程 B 读取、执行或消费，因此 A 和 B 之间存在一条可能的语义传播边。

这对恢复“下载文件被执行”“落地文件被另一个进程消费”“归档后外发”等跨进程关系非常重要。

### 5.3 bridge 是怎么建的

一条 bridge 要成立，通常要同时满足：

1. 对象类别不能属于禁止桥接类别
2. 对象标签不能属于禁止桥接标签
3. 对象标签至少命中一个允许桥接标签
4. 前后访问必须满足时序因果
5. 对象语义 epoch 要前后衔接

当前常见默认约束是：

- 最大时间间隔：`30` 分钟
- 每个对象最多桥接边数：`20`
- 写者事件类型：`WRITE / CREATE / RENAME`
- 读者或执行者事件类型：`READ / EXEC / MMAP / LOAD`

允许桥接的高价值对象标签，常见包括：

- `O_FILE_TEMP`
- `O_FILE_DOWNLOADED`
- `O_FILE_UPLOADED`
- `O_SUSPECT_WRITTEN_EXECUTABLE`
- `O_ARCHIVE`
- `O_PERSISTENCE`
- `O_PRIV_CONFIG`

不允许桥接的对象类别，常见包括：

- `system_library`
- `system_resource`
- `proc_status`

### 5.4 候选链搜索是不是按种子回溯

不是按“末端恶意节点反向回溯”。

当前主搜索更准确地说是：

> 在任务内证据图中，先挑一批可疑 seed 进程，然后沿父子进程边和 bridge 边向前展开，构造成有阶段覆盖的进程链。

这里要区分两个概念：

- 任务图锚点：用于回查原始日志、确定任务局部证据范围
- 候选链搜索 seed：用于在这个局部证据空间里启动链搜索

当前搜索 seed 典型包括：

- 带行为标签的进程
- 或带 `P_WEB_CTX / P_REMOTE_CTX / P_UNTRUSTED_CTX / P_SUSPECT_CTRL_CTX` 的进程

### 5.5 搜索空间是什么

候选链搜索运行在两类边共同组成的空间里：

- 父子进程边
- `BridgeEdge`

默认约束通常是：

- `max_depth = 6`
- `max_total_span_minutes = 180`
- `max_time_gap_minutes = 120`
- `top_k = 20`

### 5.6 什么路径才算有效候选链

不是所有进程链都会进入后续推理。当前系统要求一条链至少满足一定的阶段覆盖组合。

内部阶段桶包括：

- `Entry`
- `ExecutionWeak`
- `ExecutionStrong`
- `TargetAccess`
- `FollowUp`

强候选链组合常见有：

- `Entry + ExecutionStrong + TargetAccess`
- `Entry + ExecutionStrong + FollowUp`
- `ExecutionStrong + TargetAccess + FollowUp`

中档升级组合常见有：

- `Entry + ExecutionWeak + TargetAccess`
- `Entry + ExecutionWeak + FollowUp`

弱候选链组合常见有：

- `Entry + ExecutionWeak`
- `Entry + TargetAccess`
- `ExecutionWeak + FollowUp`

这一步的设计动机是：

> 避免把任何一条零散路径都送去解释，而是要求它至少在“入口、执行、碰目标、继续动作”这些方面具有基本攻击结构。

### 5.7 候选链怎么打分

当前风险分数可以概括为：

```text
risk_score =
  label_score
  + combo_score
  + stage_score
  + bridge_score
  + prior_score
  - penalties
```

各项大致含义是：

- `label_score`：标签本身的分值
- `combo_score`：关键标签组合的额外奖励
- `stage_score`：阶段覆盖越完整，加分越高
- `bridge_score`：bridge 越强、越多，加分越高
- `prior_score`：来自任务图恶意检测的任务先验
- `penalties`：对弱证据链、孤立读链等情况的惩罚

常见奖励包括：

- `B_EXTERNAL_RECV + B_EXEC_TEMP/B_EXEC_DOWNLOADED`
- `B_EXTERNAL_RECV + B_SHELL_SPAWN`
- `B_EXEC_* + B_READ_CRED`
- `B_READ_* + B_EXTERNAL_SEND`
- `B_EXEC_* + B_WRITE_PERSISTENCE`
- `B_EXEC_* + B_LATERAL_CONNECT`

常见惩罚包括：

- 只有弱执行没有强执行
- 过度依赖高复用对象
- 只有单点敏感读取，没有前因和后果

### 5.8 什么是 `dossier`

候选链不是直接丢给后面模块，而是先被整理成一份 `dossier`。它可以理解为：

> 一份面向解释模块的结构化案卷。

它通常包括：

- `task_id`
- `path_id`
- `path_type`
- `risk_level`
- `risk_score`
- `stage_coverage`
- `chain_kind`
- `context_ids`
- `support_event_ids`
- `support_object_keys`
- `support_relations`
- `family_tags`
- `precursor_event_ids`
- `followup_event_ids`
- `network_support_summary`
- `object_lineage_summary`
- `holmes_matched_atoms`
- `missed_truth_like_hints`
- `core_processes`
- `bridge_edges`
- `evidence_timeline`
- `warnings`
- `summary`

这份 `dossier` 是后面 claim 提取和战术映射的直接输入，不再重新扫整条原始日志。

### 5.9 family 保留机制是什么

为了避免只按风险分数排序时，把“前因短、尾巴长”的真实攻击前因挤掉，当前实现增加了 `family` 保留机制。

这里的 `family` 不是 ATT&CK，也不是标签，而是我们对“链段类型”的一个内部分组。常见包括：

- `short_lived_precursor`
- `attachment_or_tcexec_exec`
- `initial_or_drop_exec`
- `callback_c2`
- `scan_discovery`
- `cleanup_delete`
- `mail_browser_context_tail`

它的作用是：

> 在 top-k 裁剪之前，尽量保住不同类型的关键链段，不让长尾上下文把真正的恶意前因完全淹没。

### 5.10 family 是怎么判的

当前 family 的典型判定线索如下：

| family | 典型线索 |
| --- | --- |
| `attachment_or_tcexec_exec` | 事件或对象文本中出现 `attachment`、`tcexec`、`pine`、`mail` |
| `initial_or_drop_exec` | `/tmp/`、`/dev/shm/`、`ztmp` 等落地执行，或可疑执行标签 |
| `callback_c2` | 命中 `B_EXTERNAL_SEND`、`B_EXTERNAL_RECV`，或网络摘要显示远程目标 |
| `scan_discovery` | 命中 `B_LATERAL_CONNECT`，或网络摘要显示内部连接爆发 |
| `short_lived_precursor` | 命中 `tcexec`、`command-not-found`、`/dev/pts/3`、`python3`、`chmod`、`bash` |
| `cleanup_delete` | 命中 `B_DELETE_LOG`，或事件文本里出现 `delete`、`unlink`、`ztmp` |
| `mail_browser_context_tail` | 事件或进程文本里出现 `firefox`、`thunderbird`、`pine`、`mail`、`browser` |

### 5.11 precursor rescue 是什么

如果正常候选集中没有保住前因短链，而局部证据图里又明显存在短命可疑前因，系统会尝试做一次 `precursor rescue`。

它的含义是：

> 从当前任务的局部证据图里，额外补出一条短命前因链，防止后续解释只看见后果，看不见前因。

它不是凭 GT 硬编码生成，而是仍然只能用当前证据图中已存在的进程、事件和对象关系来构造。

## 6. 第六块：中间行为 claim 生成

### 6.1 这一块要解决什么问题

候选链虽然已经比原始日志规整很多，但它仍然不是 ATT&CK 语义。直接从候选链映射 ATT&CK，容易把“证据层”和“语义层”混在一起。

因此我们在 ATT&CK 前插入一层中间行为 `claims`。

这层回答的问题是：

> 这条候选链到底支持了哪些更稳定的攻击行为原子。

### 6.2 claim 生成不是纯 LLM 自由发挥

当前实现不是让大模型自由总结。它是“两段式”的：

1. 先用规则从 `dossier` 里预匹配出一组候选行为原子
2. 再让 LLM 只对这组候选进行确认、细化或删减

也就是说，LLM 在这一层的自由度被刻意限制住了。

### 6.3 预匹配阶段会从 `dossier` 里取哪些证据

预匹配会用到：

- 时间线事件
- 事件标签
- bridge 边
- 对象 key 和对象类别
- `network_support_summary`
- `object_lineage_summary`
- `precursor_event_ids`
- `summary`

系统会先从 `dossier` 中提取几组关键事件 ID 集合，例如：

- 外部接收事件
- 外部发送事件
- 横向连接事件
- 执行类事件
- 敏感读取事件
- 日志删除事件
- 扫描事件
- attachment 类事件
- precursor 类事件
- bridge 执行事件
- 临时文件删除事件
- shell 或 interpreter 事件

### 6.4 当前有哪些中间行为原子

当前这层最核心的 `behavior_type` 包括：

| behavior_type | 语义 |
| --- | --- |
| `untrusted_read` | 接触到不可信外部输入 |
| `make_mem_exec` | 处理过不可信输入后使内存可执行 |
| `make_file_exec` | 把落地文件改成可执行 |
| `untrusted_file_exec` | 执行落地文件或不可信文件 |
| `attachment_user_exec` | 打开或执行附件类对象 |
| `shell_exec` | shell 或解释器执行控制命令 |
| `cnc_communication` | 与外部端点进行可疑 C2 通信 |
| `sudo_exec` | 通过 sudo 执行特权路径 |
| `switch_su` | 切换到更高权限身份 |
| `sensitive_read` | 读取凭据、历史或业务敏感数据 |
| `sensitive_command` | 执行系统信息或网络枚举命令 |
| `network_service_discovery` | 多主机或 bursty 连接，像扫描或服务发现 |
| `send_internal` | 发起可疑内网连接 |
| `sensitive_leak` | 敏感读取后伴随外发 |
| `clear_logs` | 清理日志或防御痕迹 |
| `sensitive_temp_rm` | 收集后清理临时敏感文件 |
| `untrusted_file_rm` | 执行后删除恶意落地对象 |
| `interpreter_precursor_chain` | 短命解释器前因链启动工具 |

### 6.5 这些 claim 是怎么触发的

下面列出当前默认的主要触发规则：

| claim | 主要触发证据 |
| --- | --- |
| `untrusted_read` | 命中 `B_EXTERNAL_RECV` |
| `make_mem_exec` | 时间线中出现 `mprotect`、`mem exec` 等，并且前面有外部输入或 precursor |
| `make_file_exec` | 出现 `chmod` 或改可执行属性，并且前面有外部输入、bridge 执行或 precursor |
| `untrusted_file_exec` | 存在 bridge 执行事件，如下载物、上传物、临时文件、可疑写出对象被执行 |
| `attachment_user_exec` | 时间线或对象文本出现 `attachment`、`tcexec`、`pine`、`mail` 等 |
| `shell_exec` | 时间线中出现 `bash`、`sh`、`python`、`perl`、`php`、`tcexec`、`command-not-found` 等 |
| `cnc_communication` | 有 `B_EXTERNAL_SEND`，或有外部收发并伴随网络支撑摘要 |
| `sudo_exec` | 文本中出现 `sudo` |
| `switch_su` | 文本中出现 `setuid`、`su`、`switch user` |
| `sensitive_read` | 命中 `B_READ_CRED`、`B_READ_HISTORY`、`B_READ_BUSINESS`、`B_MASS_FILE_ACCESS` |
| `sensitive_command` | 文本中出现 `whoami`、`hostname`、`uname`、`ifconfig`、`netstat`、`ss`、`ps`、`id` 等 |
| `network_service_discovery` | 至少两个扫描类连接，或扫描与 `B_LATERAL_CONNECT` 同时出现 |
| `send_internal` | 时间线出现面向 `internal_ip` 的连接或发送 |
| `sensitive_leak` | 有外发，同时有敏感读取 |
| `clear_logs` | 命中 `B_DELETE_LOG`，或对日志对象做 `DELETE / UNLINK / RENAME` |
| `sensitive_temp_rm` | 删除临时对象，且前面有敏感读取 |
| `untrusted_file_rm` | 删除临时或可疑对象，且前面有 bridge 执行 |
| `interpreter_precursor_chain` | 存在 `precursor_event_ids`，或文本中出现 `tcexec`、`command-not-found`、`/dev/pts/3`、`python3`、`chmod`、`bash` |

### 6.6 每个 claim 里会记录什么

每条 claim 不是一句自然语言，而是一条结构化记录，至少包括：

- `claim_id`
- `behavior_type`
- `statement`
- `evidence_event_ids`
- `confidence`
- `apt_stage`
- `prerequisite_claim_ids`
- `claim_source`
- `support_signals`

这些字段的含义分别是：

- `claim_id`：这条 claim 的唯一 ID
- `behavior_type`：行为原子类别
- `statement`：对这条行为的简短事实描述
- `evidence_event_ids`：支撑它的事件 ID
- `confidence`：规则层或确认层给出的置信度
- `apt_stage`：内部阶段语义，不是 ATT&CK tactic
- `prerequisite_claim_ids`：它依赖哪些更前序的 claim
- `claim_source`：是规则预匹配、前因补强，还是 LLM 确认后得到
- `support_signals`：触发它的核心信号标签

### 6.7 claim graph 是怎么连边的

claim graph 的边不是时序边，而是“前置依赖边”。含义是：

> 某条行为成立之前，通常应该先出现哪些更早的行为原子。

典型依赖规则如下：

| claim | 常见前置 claim |
| --- | --- |
| `make_mem_exec` | `untrusted_read` |
| `make_file_exec` | `untrusted_read` |
| `untrusted_file_exec` | `untrusted_read`、`make_file_exec`、`attachment_user_exec` |
| `attachment_user_exec` | `untrusted_read` |
| `shell_exec` | `untrusted_file_exec`、`attachment_user_exec`、`interpreter_precursor_chain` |
| `cnc_communication` | `untrusted_file_exec`、`attachment_user_exec`、`shell_exec`、`interpreter_precursor_chain` |
| `sudo_exec` | `shell_exec` |
| `switch_su` | `shell_exec` |
| `sensitive_read` | `untrusted_file_exec`、`shell_exec`、`cnc_communication`、`interpreter_precursor_chain` |
| `sensitive_command` | `untrusted_file_exec`、`shell_exec`、`cnc_communication`、`interpreter_precursor_chain` |
| `network_service_discovery` | `shell_exec`、`cnc_communication`、`attachment_user_exec` |
| `send_internal` | `shell_exec`、`cnc_communication` |
| `sensitive_leak` | `sensitive_read`、`cnc_communication` |
| `clear_logs` | `shell_exec`、`cnc_communication` |
| `sensitive_temp_rm` | `sensitive_read` |
| `untrusted_file_rm` | `untrusted_file_exec` |
| `interpreter_precursor_chain` | `attachment_user_exec`、`make_file_exec`、`untrusted_read` |

### 6.8 LLM 在 claim 阶段到底干什么

LLM 在 claim 阶段不是自己造新的行为类，而是只允许：

- 确认某条预匹配行为确实成立
- 细化它的 `statement`
- 调整 `evidence_event_ids`
- 删除证据不足的预匹配行为

当前 prompt 会明确要求：

- 只能使用 dossier 内证据
- 只能确认、细化或省略“预匹配行为原子”
- 不允许新造 `claim_id`
- 不允许新造 `behavior_type`
- 尽量保留已有的 `evidence_event_ids`
- 不允许生成“可能表示威胁的一系列系统调用”这类空泛表述

### 6.9 claim 会再校验一次吗

会。

LLM 返回 claim 后，系统还会做一层校验，主要包括：

- `claim_id` 不能为空
- `statement` 不能为空
- `evidence_event_ids` 必须真的存在于 dossier 中
- `behavior_type` 必须有对应的最小必要信号
- 过于泛化的空洞表述会被删掉

例如：

- `untrusted_read` 必须真的有 `B_EXTERNAL_RECV` 或明确外部输入
- `sensitive_read` 必须真的命中敏感读取类标签
- `network_service_discovery` 必须真的有扫描或横向连接类证据
- `cnc_communication` 必须真的有对外收发或外部网络对象

### 6.10 fallback 和 merge 是什么

如果 LLM 把本来应该保住的行为删掉了，系统还会做：

- `fallback_claims`

它会重新拿规则预匹配出的 claim 图回来，和 LLM 输出做合并。

合并逻辑大意是：

- 先保留规则层的 claim 集合
- 如果 LLM 对某个 claim 给了更好的 `statement` 或更多事件 ID，就覆盖进去
- 最终把该 claim 标记为 `holmes_rule+llm_confirmation` 这一类“规则加确认”的来源

这一步的目的，是减少 LLM 漏掉高价值行为原子的风险。

## 7. 第七块：ATT&CK tactics-only + LLM 映射

### 7.1 为什么不是直接输出 technique

当前这条汇报线只讲我们实际使用的下游路线：

- `attack_mapping_scope = tactics_only`
- `tactic_mapping_mode = llm`

也就是说，我们这次重点追求的是：

> 先把战术层看稳，而不是一开始就强行追 technique 粒度。

### 7.2 战术候选是怎么检索出来的

在映射之前，系统会先从 ATT&CK 知识库里检索候选战术。

它不是把整份 ATT&CK STIX 直接扔给模型，而是先构造一个 `query context`，常见成分包括：

- `action_families`
- `claim_terms`
- `behavior_types`
- `command_lexemes`
- `object_semantics`
- `os_hint`

这些信息来自哪里：

- `claim_terms` 来自 claim 文本和 claim 行为原子
- `behavior_types` 来自上一层 claim 的 `behavior_type`
- `command_lexemes` 来自命令、进程名、脚本名
- `object_semantics` 来自对象类别和对象线索
- `os_hint` 来自路径和命令风格

然后系统用这些上下文去 ATT&CK KB 做候选检索。当前常见的评分信号是：

- 稀疏检索分数，例如 TF-IDF
- 可选的向量检索分数
- 候选和 query context 之间的兼容性分数

在很多当前实验配置里，向量检索是关掉的，所以主要依赖：

- 稀疏检索
- 兼容性重排

### 7.3 tactic-only 模式下候选长什么样

在 `tactics_only` 模式下：

- 系统仍会检索 ATT&CK 候选
- 但是后续会把 `techniques` 清空
- 只保留 `TACTIC_CANDIDATES`

也就是说，后续映射 prompt 只给模型看战术候选，不再给 technique 候选。

### 7.4 LLM 在战术映射阶段看到什么

当前战术映射阶段的输入包含：

- `PATH`：候选链 dossier 的压缩摘要
- `CLAIMS`：已经确认过的中间行为 claims
- `CAUSAL_RELATIONS`：claim graph 的依赖边
- `MATCHED_TTP_ATOMS`：命中的中间行为原子
- `MISSING_TTP_ATOMS`：期望但没命中的关键原子
- `TACTIC_CANDIDATES`：从 ATT&CK KB 取回的候选战术

这里不会再给它任意自由发挥的空间，而是要求：

- 只能从给定候选战术里选
- 每条映射必须绑定 `evidence_claim_ids`
- 先选最有证据支撑的 tactic
- tactic-only 模式下 `technique_id` 和 `technique` 必须留空

### 7.5 当前映射 prompt 的核心规则是什么

当前 prompt 的核心约束大致是：

- 只能使用提供的 claims、时间线和 ATT&CK 候选
- 把 claims 看成已经预匹配好的中间行为原子
- 每条 claim 独立映射，不要把一个 claim 的 technique 语义借给另一个 claim
- 只能从候选列表里选
- tactic-only 时不得输出 technique
- `network_service_discovery`、`sensitive_command` 这类 claim，优先考虑 `Discovery`
- `clear_logs`、`sensitive_temp_rm`、`untrusted_file_rm` 这类 claim，优先考虑 `Defense Evasion`
- `attachment_user_exec` 这类 claim，优先考虑 `Initial Access` 和 `Execution`
- 置信度必须在 `0` 到 `1` 之间

### 7.6 映射结果还会再校验吗

会。

LLM 返回后，系统还会做一层映射校验，主要检查：

- `evidence_claim_ids` 必须真的存在
- `tactic_id` 格式必须合法
- tactic 必须能在候选列表中解析到
- tactic-only 模式下强制清空 `technique_id` 和 `technique`
- 没有 claim 支撑的映射会被丢弃

因此最终保留下来的不是“模型随便说的战术”，而是：

> 候选库允许、claim 支撑、格式合法、作用域匹配的战术映射。

### 7.7 report 最终长什么样

每条 reasoning 单元最终会形成一份 report，核心包括：

- `task_id`
- `path_id`
- `path_type`
- `risk_level`
- `risk_score`
- `summary`
- `claims`
- `claim_graph`
- `attack_candidates`
- `attack_mappings`
- `gaps`
- `evidence_support_rate`

其中：

- `claims` 说明“这条链里发生了什么行为”
- `attack_mappings` 说明“这些行为对应哪些 ATT&CK 战术”
- `evidence_support_rate` 说明最终结论有多大比例能回指到明确证据

## 8. 评估是怎么看的

当前评估主要从 3 个层面看：

### 8.1 窗口命中

看系统是否在应该报警的时间窗口里产出了足够高风险的结果。

常见指标包括：

- `confirmed_window_recall`
- `strict_window_recall`
- `high_risk_window_recall`

### 8.2 战术命中

看系统输出的战术和 GT 是否对得上。

常见指标包括：

- `strict_tactic_recall_macro`
- `strict_tactic_precision_macro`

### 8.3 非攻击窗口噪声

看系统是否在不该报警的窗口里也报了很多高风险结果。

常见指标包括：

- `off_window_high_risk_rate`

## 9. 代码里常见自造词释义

为了便于看代码，这里把几个高频内部名词统一解释一下。

| 名词 | 含义 |
| --- | --- |
| `task graph` | 从全局进程关系中切出来的局部任务图 |
| `boundary node` | 同时属于当前任务边界、又通往其他子任务的节点 |
| `TaskPrior` | 来自模块 2 的任务先验摘要 |
| `task_local_evidence_graph` | 围绕某个任务回查出的局部证据图 |
| `semantic skip` | 语义去重，避免重复同义事件淹没时间线 |
| `object version` | 同一路径对象在不同语义阶段下的版本状态 |
| `BridgeEdge` | 对象生产者到消费者之间的桥接边 |
| `CandidatePath` | 从局部证据中恢复出来的候选攻击链 |
| `dossier` | 面向推理模块的候选链结构化案卷 |
| `claim` | 中间行为原子，一条比原始事件更稳定的攻击行为表述 |
| `claim graph` | claim 之间的前置依赖图 |
| `family tag` | 对链段类型的内部分组，如 callback、scan、precursor |
| `precursor rescue` | 在前因短链容易丢失时额外补回一条前因链 |
| `TACTIC_CANDIDATES` | 从 ATT&CK 知识库检索出的候选战术列表 |

## 10. 一句话总结这套方法

如果只用一句话概括，我们方案的核心不是“直接从日志猜 ATT&CK”，而是：

> 先把全量日志切成任务图，再找出可疑任务，回查原始日志恢复局部证据，对事件做语义压缩和标签化，恢复少量高价值候选攻击链，再把这些链组织成中间行为 claims，最后将 claims 稳定映射为 ATT&CK 战术输出。

这也是为什么我们方案既能做检测，又能解释“为什么是这个结论”，还能分清问题到底出在：

- 上游任务图没召回
- 中游链条没保住
- 还是下游战术映射出了偏差
