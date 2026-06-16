# APT-Fusionstep2b1 攻击分析部分全流程详解

## 1. 这份文档讲什么

这份文档只讲 `D:\daima\APT-Fusionstep2b1` 里真正用于“攻击分析”的那条主链路，也就是：

1. 前置检测模块先挑出可疑任务图。
2. `module3` 回查原始日志，把任务图变成标准化事件。
3. `module4` 做事件压缩、维护进程/对象状态、打第一批轻量标签。
4. `module5` 生成完整攻击标签、传播上下文、构造跨对象因果边、搜索候选攻击链、打分重排。
5. `module6` 把候选链整理成证据包，先做一层 Holmes 风格行为归纳，再调用大模型和 ATT&CK 知识库输出战术技战术结论。

这不是严格复现 APTShield 的版本，也不是 Holmes 攻击图原样复现版本。它本质上仍然是本项目自己的 `path_reason` 路线。

## 2. 先给结论：这版攻击分析到底是什么结构

这版项目的攻击分析，本质上是一个“先从任务图回查日志，再从日志里抽事件，再从事件里拼路径，最后再做行为解释”的流程。

它依赖三类信息：

1. 前序检测模块输出的“可疑任务图”和任务属性。
2. 原始审计日志。
3. 规则文件 `configs/path_reason_default.yaml` 提供的标签定义、阶段映射、打分权重和阈值。

但是要特别注意：

1. 规则文件里定义了很多标签和规则。
2. 当前实现并不是“通用规则引擎按 YAML 自动执行”。
3. 真正触发标签的逻辑，大部分是硬编码在 `module4_semantic_compact.py` 和 `path_labeler.py` 里的。

所以，理解这版代码时，必须区分两层：

1. 规则文件里“声明了什么”。
2. 代码里“真正执行了什么”。

## 3. 整条主流程的输入、输出和阶段边界

### 3.1 上游输入

攻击分析并不是从全量日志直接开始，而是吃前序模块产物：

1. `module2/suspicious_tasks.json`
2. `module2/task_meta_rich.json`
3. `module2/task_attribution.json`

这三个文件分别提供：

1. 哪些任务图被认为可疑。
2. 每个任务图的根进程、边界节点等结构信息。
3. 哪些进程、哪些边在前序模型里贡献较大。

### 3.2 攻击分析主线入口

主入口在 `src/apt_fusion/pipeline.py`，阶段名是：

`full_path_reason`

它实际顺序是：

1. `run_module3_evidence`
2. `run_module4_compact`
3. `run_module5_paths`
4. `run_module6_reason`

### 3.3 各阶段输出目录

1. `module3_evidence`：标准化事件和各种索引。
2. `module4_compact`：压缩后的保留事件、对象访问记录、进程状态、对象状态、对象版本、标签来源记录。
3. `module5_paths`：跨对象因果边、候选攻击链、候选链摘要。
4. `module6_reason`：最终攻击报告、证据包、声明图、大模型输入输出。

## 4. 攻击分析里最重要的“数据对象”是什么

为了方便理解，下面把核心对象都用中文解释一遍。

### 4.1 任务先验

含义：前序模块对某个任务图的先验判断结果。

主要内容：

1. 任务编号。
2. 任务分数、任务概率。
3. 根进程集合。
4. 任务根节点。
5. 边界节点集合。
6. 前序模型认为最重要的进程。
7. 前序模型认为最重要的边。
8. 任务时间范围。

作用：

1. 决定哪些任务进入攻击分析。
2. 给候选链打“前序模型先验加分”。

### 4.2 标准化事件

含义：把不同数据集原始日志统一成同一种事件格式。

一条标准化事件至少包含：

1. 事件编号。
2. 原始日志位置。
3. 所属任务编号。
4. 时间戳。
5. 进程编号、进程名、可执行路径、命令行、父进程编号。
6. 事件类型。
7. 对象类型、对象键、对象显示名、对象类别。
8. 系统调用方向。
9. 语义流向。
10. 结果码。
11. 网络四元组信息。

### 4.3 进程状态

含义：某个进程在当前任务里被分析后积累出来的状态。

包含：

1. 进程基本信息。
2. 生命周期起止时间。
3. 父进程。
4. 上下文标签集合。
5. 行为标签集合。
6. 聚合标签集合。
7. 控制纪元计数。
8. 来自前序模型的先验分数。
9. 证据事件编号列表。
10. 重要对象集合。
11. 标签来源编号列表。

### 4.4 对象状态

含义：某个文件、网络流、注册表项、管道等对象在当前任务里的状态。

包含：

1. 对象类型和对象类别。
2. 对象标签集合。
3. 语义纪元计数。
4. 所有对象访问记录。
5. 首末出现时间。
6. 是否允许成为跨进程因果桥对象。
7. 读/写/执行次数。
8. 当前版本编号。
9. 标签来源编号列表。

### 4.5 对象访问记录

含义：某个进程在某个时间对某个对象做了一次访问，并把访问前后的“进程标签签名、对象标签签名、对象纪元、进程控制纪元”一起记下来。

作用：

1. 为跨对象因果边构造提供依据。
2. 为对象版本跟踪提供依据。
3. 为后续语义去重提供上下文。

### 4.6 对象版本

含义：同一个对象被写改之后，视为进入了新版本。

记录：

1. 版本编号。
2. 创建该版本的事件。
3. 该版本上的标签。
4. 哪些进程写过它。
5. 哪些进程读过它。
6. 哪些进程执行过它。

### 4.7 标签来源记录

含义：记录“某个标签是怎么来的”。

字段包括：

1. 标签来源编号。
2. 标签名。
3. 标签类型。
4. 标签持有者是谁。
5. 创建时间。
6. 来源实体是谁。
7. 触发事件编号。
8. 触发事件类型。
9. 触发规则编号。
10. 前驱标签来源编号列表。
11. 分段编号。

但这版实现有一个关键特点：

1. 标签来源记录只在 `module4` 的轻量预标记和 `FORK/CLONE` 继承时生成。
2. `module5` 里后来补上的大部分行为标签，并不会继续写入这份标签来源记录。
3. 所以后面虽然有“标签来源密度重排”，但它看到的只是部分标签来源，而不是完整标签传播链。

### 4.8 候选攻击链

含义：由若干进程节点和若干跨对象因果边组成的一条“可能的攻击过程”。

包括：

1. 进程链。
2. 跨对象因果边集合。
3. 阶段覆盖。
4. 路径标签集合。
5. 风险分数与风险等级。
6. 时间范围。
7. 证据时间线。
8. 辅助证据对象和辅助关系。

## 5. 规则文件到底提供了什么

规则文件是：

`D:\daima\APT-Fusionstep2b1\configs\path_reason_default.yaml`

它主要提供六类信息：

1. 事件类型标准化映射。
2. 路径、文件、进程、端口等基础词典。
3. 标签的阶段映射和分数。
4. 状态传播深度。
5. 跨对象因果边的允许/禁止条件。
6. 候选链搜索阈值与打分权重。

但是它不是一个完整的“可执行规则引擎”。很多规则只是被代码部分使用。

## 6. Module3：从任务图回查原始日志

### 6.1 这一步的目标

把前序模块给出的“可疑任务图”，变成每个任务一份可直接分析的标准化事件流。

### 6.2 任务筛选规则

`module3` 支持三种任务选择模式：

1. `predicted_positive`：只取前序模块预测为可疑的任务。
2. `ground_truth_positive`：只取真实标签为恶意的任务。
3. `ground_truth_positive_base_only`：只取真实恶意且不是增强任务的基础任务。

当前配置默认是：

`predicted_positive`

### 6.3 任务严重等级规则

`module3` 会根据所有任务分数的百分位给任务一个严重等级：

1. 百分位 `>= 99`：`Critical`
2. 百分位 `>= 97`：`Significant`
3. 百分位 `>= 95`：`Moderate`
4. 百分位 `>= 90`：`Minor`
5. 其他：`Negligible`

但是实现里又做了一个强制修正：

1. `Minor` 会被改成 `Moderate`
2. `Negligible` 也会被改成 `Moderate`

也就是说，这一步最终不会给出低于 `Moderate` 的任务严重等级。

### 6.4 日志回查的种子是什么

种子来自每个任务图的 `process_ids`。

规则：

1. 把任务图里的所有进程编号放进前沿集合。
2. 扫描原始日志。
3. 只要日志事件的主体进程编号命中前沿集合，就把这条日志归入对应任务。
4. 如果 `include_object_side = true`，那么事件对象编号命中前沿集合也会归入任务。

当前默认：

`evidence_recover_include_object_side = true`

### 6.5 局部跳数扩展规则

当前只支持：

1. `local_context_hops = 1`
2. `local_context_hops = 2`

含义：

1. `1`：只拿种子直接命中的事件。
2. `2`：第一轮命中后，如果事件里出现了进程对象，还会把它加入下一轮前沿，再扫一遍日志。

当前默认是：

`1`

### 6.6 去重规则

同一个任务里，如果两条日志标准化后具有同样的下面六元组，就只保留一次：

1. 主体进程编号
2. 对象编号
3. 动作
4. 时间戳
5. 对象类型提示
6. 对象属性提示

### 6.7 每任务事件数量上限

每个任务最多保留：

`300000`

超过上限的事件会被丢弃，并记录丢弃计数。

### 6.8 跨数据集原始日志解析规则

当前代码支持：

1. DARPA TC3 / NODLINK 类日志。
2. OPTC 类日志。
3. NODLINK Windows 原始日志。

不同数据集会使用不同提取函数，但最后都会统一成标准化事件格式。

### 6.9 进程别名归一规则

这一步是为了把同一进程的不同编号形式统一起来。

#### trace 主机

1. 用 `cid` 作为规范进程编号。
2. 原始 `uuid -> cid`。
3. 同时尽量解析父进程编号和进程属性。

#### theia 主机

1. 用 `(父进程, tgid, path)` 组合去归并。
2. 相同组合视为同一个规范进程。

#### optc / windows raw

1. 基本按原始进程编号直接使用。

### 6.10 事件类型标准化规则

原始事件类型会先做标准化映射，典型规则如下：

1. `EXECUTE -> EXEC`
2. `CREATE_OBJECT -> CREATE`
3. `LOAD_ELF -> LOAD`
4. `LOADLIBRARY -> LOAD`
5. `SENDMSG -> SEND`
6. `SENDTO -> SEND`
7. `RECVMSG -> RECV`
8. `RECVFROM -> RECV`
9. `FORK_WITH_SHARED_OPEN_FILE -> FORK`
10. `MODIFY_PROCESS -> CHMOD`

### 6.11 进程名、可执行路径、命令行提取规则

1. 进程可执行路径：取进程属性字符串中第一个带路径分隔符的 token。
2. 进程名：优先取可执行路径 basename；否则取进程属性第一个 token 的 basename。
3. 命令行：只有原始属性里存在空格时才认为有命令行。

### 6.12 对象键和对象名规则

1. 如果对象是进程，直接用对象进程编号。
2. 如果对象不是进程，优先用对象属性；没有对象属性才退回对象编号。
3. 对象名通常取 basename；网络流对象则保留完整四元组形式。

### 6.13 网络端点解析规则

如果对象键长得像：

`源IP:源端口->目的IP:目的端口`

就解析出：

1. 本地 IP / 端口
2. 远端 IP / 端口

如果只有单个 `IP:端口`，就把它当远端。

### 6.14 系统调用方向规则

1. `FORK / CLONE / EXIT`：进程到进程。
2. `ACCEPT` 且对象是网络类：对象到进程。
3. 对象本身是进程：进程到进程。
4. 其他有对象的情况：进程到对象。

### 6.15 语义流向规则

1. `READ / EXEC / LOAD / MMAP`：对象流向进程。
2. `WRITE / CREATE / TRUNCATE / CHMOD / CHOWN / RENAME / DELETE / CONNECT / SEND`：进程流向对象。
3. `RECV`：对象流向进程。
4. `ACCEPT`：对象流向进程。
5. `FORK / CLONE` 或对象本身是进程：进程到进程。
6. `EXIT`：无流向。

### 6.16 对象分类规则

对象分类是这条链路非常关键的一步，因为后面的标签、桥边和打分都依赖对象类别。

#### 网络对象分类

1. 如果对象类型是 `flow / socket / network`，先尝试从对象键解析网络端点。
2. 远端或本地 IP 只要命中外部地址，就归为外部 IP。
3. 否则只要命中内网网段，就归为内部 IP。
4. 如果是 `unix:`、`localhost`、`127.*`，归为本地 IPC。

#### 文件/路径对象分类

按顺序匹配：

1. `/proc/*`：进程状态类对象。
2. `/tmp/`、`/var/tmp/`、`/dev/shm/`：临时文件。
3. 凭据路径：如 `/etc/passwd`、`/etc/shadow`、`.ssh/id_rsa`、`.aws/credentials`、`.kube/config`。
4. 历史记录路径：如 `.bash_history`、`.zsh_history`、`.mysql_history`、`.python_history`。
5. 持久化路径：如 `/etc/crontab`、`/etc/cron.d`、`/var/spool/cron`、`/etc/systemd/system`、`/lib/systemd/system`、`/etc/rc.local`。
6. 提权配置路径：如 `/etc/sudoers`、`/etc/sudoers.d`。
7. 认证配置路径：如 `/etc/ssh/`、`/etc/pam.d/`、`/etc/security/`、`/etc/login.defs`、`/root/.ssh/`。
8. 日志路径：如 `/var/log`、`/var/log/auth.log`、`/var/log/secure`、`/var/log/audit`。
9. 压缩归档后缀：`.zip`、`.tar`、`.gz`、`.tgz`、`.7z`、`.rar`。
10. 业务数据路径：如 `/data/business/`、`/opt/app/data/`、`/srv/data/`、`/home/*/Documents/`、`*.sql`、`*.db`、`*.sqlite`、`*.xlsx`、`*.docx`、`*.csv`。
11. 系统库：`/usr/lib`、`/lib`、`/lib64`。
12. 系统资源：`/usr/share`、`/usr/include`、`/usr/share/locale`。
13. 本地 IPC：`127.0.0.1`、`localhost`、`unix:`

如果都不命中：

1. 有绝对路径的一般归普通文件。
2. 否则退回原始对象类型。

### 6.17 `module3` 额外写出的索引和图

这一步还会为每个任务写出：

1. 实体索引：任务内出现过的进程和对象。
2. 进程到事件索引。
3. 对象到事件索引。
4. 证据前沿描述。
5. 任务局部证据图。

但要注意：

1. 这些 sidecar 文件在这版主流程里基本没有被后续核心逻辑直接消费。
2. 主流程真正继续往下用的，主要还是 `normalized_events` 和任务先验。

## 7. Module4：事件压缩、对象版本、轻量标签和标签来源

### 7.1 这一步的目标

把 `module3` 的标准化事件流压缩成更适合路径分析的状态表示。

### 7.2 `FORK/CLONE` 继承规则

如果一条事件是 `FORK` 或 `CLONE`，且对象是进程：

1. 子进程会继承父进程当前的全部上下文标签。
2. 如果子进程还不存在，就创建新的进程状态。
3. 如果子进程已经存在，就把父进程缺失的上下文标签补过去。
4. 这类继承会写标签来源记录。
5. 每次继承会生成一个新的分段编号。

### 7.3 轻量标签规则

这一步只做第一批较便宜的标签，不做完整行为分析。

下面把真正生效的轻量标签规则全部列出来。

#### 7.3.1 Web 服务上下文（`P_WEB_CTX`）

触发条件：

1. 进程名属于 Web 服务进程名单：`nginx`、`httpd`、`apache2`、`php-fpm`、`php-cgi`、`tomcat`、`uwsgi`、`gunicorn`、`node`。
2. 或者进程对带上传标记的路径执行 `WRITE / CREATE`，并且该路径落在 Web 根目录下。

#### 7.3.2 远程服务上下文（`P_REMOTE_CTX`）

触发条件：

1. 进程名属于远程服务名单：`sshd`、`dropbear`、`telnetd`、`xrdp`、`sftp-server`。

#### 7.3.3 外部网络对象（`O_NET_EXTERNAL`）

触发条件：

1. 对象类别是外部 IP。

#### 7.3.4 外部网络接触上下文（`P_NET_CTX`）

触发条件：

1. 事件对象类别是外部 IP。
2. 事件类型属于 `CONNECT / ACCEPT / SEND / RECV`。

#### 7.3.5 对象类别直标规则

如果对象类别已经被分类器识别成下面之一，就直接打同名对象标签：

1. 临时文件 -> `O_FILE_TEMP`
2. 凭据文件 -> `O_CREDENTIAL`
3. 历史文件 -> `O_HISTORY`
4. 业务数据 -> `O_BUSINESS_DATA`
5. 持久化文件 -> `O_PERSISTENCE`
6. 提权配置 -> `O_PRIV_CONFIG`

#### 7.3.6 上传文件（`O_FILE_UPLOADED`）

触发条件：

1. 事件类型是 `WRITE / CREATE`
2. 路径中包含上传标记：`upload`、`uploads`、`wwwroot`、`webapps`、`htdocs`

补充效果：

1. 如果此时路径还位于 Web 根目录，会顺便给进程加 `P_WEB_CTX`。

#### 7.3.7 不存在文件（`O_FILE_NONEXIST`）

触发条件：

1. 对象类别是临时文件。
2. 事件类型属于 `READ / OPEN / EXEC / LOAD / MMAP`。
3. 返回结果是 `ENOENT` 或 `NOT_FOUND`。

#### 7.3.8 下载文件（`O_FILE_DOWNLOADED`）

触发条件满足其一即可：

1. 进程命令行带有下载提示：`http://`、`https://`、`ftp://`、`-o`、`-O`，且事件是 `WRITE / CREATE`。
2. 进程名属于下载器名单：`curl`、`wget`、`scp`、`sftp`、`ftp`、`python`、`perl`、`php`、`node`，并且在 120 秒内曾有外联或外部接收，再发生 `WRITE / CREATE`。
3. 对象类别是临时文件，并且同一进程在 120 秒内有外部接收，再发生 `WRITE / CREATE`。

#### 7.3.9 不可信上下文（`P_UNTRUSTED_CTX`）

触发条件满足其一即可：

1. `RECV` 外部 IP。
2. `EXEC / LOAD / MMAP` 的对象已经带有 `O_FILE_DOWNLOADED`、`O_FILE_UPLOADED`、`O_SUSPECT_WRITTEN_EXECUTABLE` 之一。

### 7.4 对象版本推进规则

对象版本的推进规则是：

1. 某对象第一次出现时创建 `v0001`。
2. 如果事件类型属于 `WRITE / CREATE / TRUNCATE / RENAME / DELETE / CHMOD / CHOWN`，则推进到新版本。
3. 同一个版本上会累计：
   1. 该版本标签。
   2. 写者进程集合。
   3. 读者进程集合。
   4. 执行者进程集合。

### 7.5 语义去重规则

这一步会把语义上重复的事件压掉。

#### 7.5.1 语义键

语义键由下面六项拼接：

1. 任务编号
2. 进程编号
3. 事件类型
4. 对象键
5. 对象类别
6. 语义流向

#### 7.5.2 只有同时满足下面条件才会被判为“可跳过”

1. 语义键相同。
2. 进程标签签名相同。
3. 对象标签签名相同。
4. 对象语义纪元相同。
5. 进程控制纪元相同。
6. 与上次出现时间差不超过 `600` 秒。

#### 7.5.3 不会被压掉的强制保留事件

满足其一就强制保留：

1. `EXEC`，并且 `semantic_force_keep_exec = true`。
2. 外部网络事件 `CONNECT / ACCEPT / SEND / RECV`，并且 `semantic_force_keep_external_network = true`。
3. `WRITE / CREATE / RENAME / CHMOD / CHOWN / DELETE` 写到敏感对象，且 `semantic_force_keep_write_sensitive = true`。敏感对象类别包括：
   1. 临时文件
   2. 持久化文件
   3. 提权配置
   4. 凭据文件
   5. 业务数据
4. 事件类型属于强制保留名单：`EXEC`、`FORK`、`CLONE`、`CONNECT`、`ACCEPT`、`SEND`、`RECV`、`EXIT`、`CHMOD`、`CHOWN`、`RENAME`、`DELETE`。
5. 对象类别属于强制保留类别：临时文件、凭据文件、历史文件、业务文件、持久化文件、提权配置、外部 IP。
6. 本次事件触发了任何标签。

#### 7.5.4 去重表失效规则

出现下面情况会使相关语义记忆失效：

1. 对象被改写、创建、重命名、删除、改权限时，对象纪元加一。
2. 进程收到外部网络数据时，进程控制纪元加一。
3. 进程执行、加载、映射新对象时，进程控制纪元加一。

### 7.6 重要对象规则

只要满足其一，对象会被记到进程的“重要对象”集合里：

1. 这条事件触发了任何标签。
2. 对象类别属于：
   1. 凭据文件
   2. 历史文件
   3. 业务文件
   4. 持久化文件

### 7.7 桥接允许对象规则

对象如果带有以下对象标签之一，就会被标记为“允许用于跨进程因果桥”：

1. `O_FILE_TEMP`
2. `O_FILE_DOWNLOADED`
3. `O_FILE_UPLOADED`
4. `O_SUSPECT_WRITTEN_EXECUTABLE`
5. `O_ARCHIVE`
6. `O_PERSISTENCE`
7. `O_PRIV_CONFIG`

### 7.8 事件聚合规则

`module4` 还会把保留事件聚合成“事件片段”。

聚合键包括：

1. 时间桶
2. 进程编号
3. 事件类型
4. 对象类型
5. 对象类别
6. 对象键
7. 语义流向
8. 进程标签签名
9. 对象标签签名
10. 对象语义纪元
11. 进程控制纪元

时间桶大小默认是：

`1` 分钟

每个聚合片段最多保留：

`5` 个代表事件编号

### 7.9 这一步的实现特点

这一版 `module4` 有几个必须知道的特点：

1. 标签来源记录主要只覆盖轻量标签，不覆盖 `module5` 后续生成的大部分行为标签。
2. `context_id` 这个字段虽然存在，但当前实现没有真正写入非空上下文编号。
3. `episodes` 文件会被写出来，但主路径搜索并不直接消费它。

## 8. Module5：完整标签、上下文传播、跨对象因果边、候选攻击链

### 8.1 这一步的目标

这是整条攻击分析链路里最核心的一步：

1. 给事件和进程补完整行为标签。
2. 沿进程树向下传播上下文标签。
3. 通过同一对象的“先写后读/执行”关系构造跨进程因果边。
4. 在“父子边 + 跨对象因果边”组成的图上搜索候选攻击链。
5. 按风险分数、支撑证据质量、行为家族覆盖等规则重排。

### 8.2 先补一个关键对象标签：疑似落地后执行对象（`O_SUSPECT_WRITTEN_EXECUTABLE`）

规则：

1. 对象不能是系统库、系统资源。
2. 如果同一个对象先发生过 `WRITE / CREATE / RENAME`，后面又发生过 `EXEC / LOAD / MMAP`。
3. 则把该对象标记为疑似“先落地再执行”对象。

### 8.3 完整行为标签规则

下面这些是真正会在 `module5` 生效的完整行为标签规则。

#### 8.3.1 外部接收（`B_EXTERNAL_RECV`）

1. 事件类型是 `RECV`
2. 对象类别是外部 IP

#### 8.3.2 外部发送（`B_EXTERNAL_SEND`）

1. 事件类型是 `SEND`
2. 对象类别是外部 IP

#### 8.3.3 临时目录执行（`B_EXEC_TEMP`）

1. 事件类型是 `EXEC`
2. 对象类别是临时文件

#### 8.3.4 执行下载文件（`B_EXEC_DOWNLOADED`）

1. 事件类型是 `EXEC / LOAD`
2. 对象已经带 `O_FILE_DOWNLOADED`

#### 8.3.5 执行上传文件（`B_EXEC_UPLOADED`）

1. 事件类型是 `EXEC / LOAD`
2. 对象已经带 `O_FILE_UPLOADED`

#### 8.3.6 执行疑似落地对象（`B_EXEC_SUSPECT_WRITTEN`）

1. 事件类型是 `EXEC / LOAD`
2. 对象已经带 `O_SUSPECT_WRITTEN_EXECUTABLE`

#### 8.3.7 可疑 Shell 执行（`B_SHELL_SPAWN`）

必须先满足：

1. 进程名属于 Shell：`sh`、`bash`、`zsh`、`dash`

然后再满足其一：

1. 当前进程已经有 `P_WEB_CTX`、`P_REMOTE_CTX`、`P_SUSPECT_CTRL_CTX` 任意一个上下文标签。
2. 事件里父进程名属于 Web 服务。
3. 命令行中含有：` -c `、`curl`、`wget`、`nc `、`socat`、`/tmp/`、`/dev/shm/`

#### 8.3.8 可疑解释器执行（`B_SCRIPT_EXEC`）

必须先满足：

1. 进程名属于解释器：`python`、`python3`、`perl`、`php`、`node`、`ruby`、`lua`

然后再满足其一：

1. 命令行中含有：`http://`、`https://`、`/tmp/`、`/dev/shm/`、`-c `
2. 进程已有 `P_WEB_CTX`、`P_REMOTE_CTX`、`P_SUSPECT_CTRL_CTX` 任意一个上下文标签。
3. 当前事件已经带有 `O_FILE_DOWNLOADED`、`O_FILE_UPLOADED`、`O_SUSPECT_WRITTEN_EXECUTABLE` 触发信息。

#### 8.3.9 解释器启动（`B_INTERPRETER_LAUNCH`）

1. 进程名属于解释器即可。

#### 8.3.10 读取凭据（`B_READ_CRED`）

1. 事件类型是 `READ`
2. 对象类别是凭据文件

附带效果：

1. 进程会追加高价值访问上下文 `P_HIGH_VALUE_CTX`

#### 8.3.11 读取历史记录（`B_READ_HISTORY`）

1. 事件类型是 `READ`
2. 对象类别是历史文件

附带效果：

1. 进程会追加 `P_HIGH_VALUE_CTX`

#### 8.3.12 读取业务数据（`B_READ_BUSINESS`）

1. 事件类型是 `READ`
2. 对象类别是业务文件

附带效果：

1. 进程会追加 `P_HIGH_VALUE_CTX`

#### 8.3.13 大量文件访问（`B_MASS_FILE_ACCESS`）

当前代码的真实实现是：

1. 以“进程 + 分钟桶”为统计窗口。
2. 统计该分钟内被这个进程 `READ` 过的文件对象去重数量。
3. 如果达到 `100` 个不同对象，就给该进程打这个标签。

要特别注意：

1. YAML 里写的是“5 分钟内 100 个文件或 100MB 读取量”。
2. 当前代码并没有实现 5 分钟滑窗。
3. 也没有实现读取字节数条件。
4. 它只实现了“同一分钟内读取 100 个不同对象”。

#### 8.3.14 写持久化位置（`B_WRITE_PERSISTENCE`）

1. 事件类型是 `WRITE / CREATE / RENAME`
2. 对象类别是持久化文件

#### 8.3.15 修改提权配置（`B_WRITE_PRIV_CONFIG`）

1. 事件类型是 `WRITE / CHMOD / CHOWN`
2. 对象类别是提权配置

#### 8.3.16 压缩归档行为（`B_ARCHIVE_DATA`）

满足其一即可：

1. 进程名属于归档工具：`tar`、`zip`、`gzip`、`bzip2`、`xz`、`7z`
2. 对象类别是归档文件

#### 8.3.17 清理日志（`B_DELETE_LOG`）

1. 事件类型是 `DELETE / RENAME / WRITE`
2. 对象类别是日志文件

#### 8.3.18 横向连接（`B_LATERAL_CONNECT`）

1. 事件类型是 `CONNECT / SEND`
2. 对象类别是内部 IP
3. 远端端口属于横向常见端口：`22`、`445`、`3389`、`3306`、`5432`、`6379`、`9200`、`27017`

#### 8.3.19 远程服务入口活动（`B_REMOTE_LOGIN_SERVICE`）

1. 进程名属于远程服务。
2. 事件类型是 `ACCEPT / RECV`

#### 8.3.20 Web 上传写入（`B_WEB_WRITE`）

1. 事件类型是 `WRITE / CREATE`
2. 对象键里包含字符串 `upload`

### 8.4 向下传播的上下文标签规则

这一步只传播“上下文标签”，不传播行为标签。

允许传播的上下文标签是：

1. `P_WEB_CTX`
2. `P_REMOTE_CTX`
3. `P_NET_CTX`
4. `P_UNTRUSTED_CTX`
5. `P_HIGH_VALUE_CTX`
6. `P_SUSPECT_CTRL_CTX`

各标签最大传播深度：

1. `P_HIGH_VALUE_CTX`：1 层
2. `P_NET_CTX`：2 层
3. `P_WEB_CTX`：2 层
4. `P_REMOTE_CTX`：4 层
5. `P_UNTRUSTED_CTX`：3 层
6. `P_SUSPECT_CTRL_CTX`：3 层

公共守护进程传播限制：

1. 如果父进程属于公共守护进程，如 `systemd`、`cron`、`sshd`、`nginx`、`apache2`、`httpd`、`mysqld`、`redis-server`、`rsyslogd`、`dbus-daemon`
2. 那么只有子进程类型属于下面集合时才允许传播：
   1. shell
   2. interpreter
   3. downloader
   4. network_tool
   5. unknown_binary

此外还有一个父节点聚合规则：

1. 如果某个父进程的任一子进程已经有行为标签，
2. 或者子进程具有 `P_UNTRUSTED_CTX / P_SUSPECT_CTRL_CTX`
3. 则父进程打上“子进程可疑”聚合标签 `A_CHILD_SUSPICIOUS`

### 8.5 跨对象因果边规则

这是这版链条系统的核心机制之一。

一条跨对象因果边的语义是：

同一个对象先被进程 A 改写，随后被进程 B 读取或执行，因此认为 A 和 B 之间存在一条通过该对象传递的因果联系。

#### 8.5.1 哪些对象允许参与

对象必须同时满足：

1. 对象类别不能属于：
   1. 系统库
   2. 系统资源
   3. `/proc` 状态对象
2. 对象标签不能命中禁止集合：
   1. `O_CREDENTIAL`
   2. `O_HISTORY`
   3. `O_BUSINESS_DATA`
   4. `O_NET_EXTERNAL`
   5. `O_NET_INTERNAL`
   6. `O_AUTH_CONFIG`
   7. `O_SECURITY_LOG`
3. 对象标签必须命中允许集合：
   1. `O_FILE_TEMP`
   2. `O_FILE_DOWNLOADED`
   3. `O_FILE_UPLOADED`
   4. `O_SUSPECT_WRITTEN_EXECUTABLE`
   5. `O_ARCHIVE`
   6. `O_PERSISTENCE`
   7. `O_PRIV_CONFIG`

#### 8.5.2 哪些访问可当“写端”

1. `WRITE`
2. `CREATE`
3. `RENAME`

#### 8.5.3 哪些访问可当“读/执行端”

1. `READ`
2. `EXEC`
3. `MMAP`
4. `LOAD`

#### 8.5.4 还必须满足的约束

1. 写者进程和读者/执行者进程不能是同一个进程。
2. 读者/执行者时间不能早于写者时间。
3. 时间差不能超过 `30` 分钟。
4. 写后对象纪元必须等于读前对象纪元，也就是两边必须指向同一语义版本。
5. 每个对象最多生成 `20` 条这样的跨进程因果边。

#### 8.5.5 因果边类型

1. 如果后续事件是 `EXEC / LOAD / MMAP`：写后执行。
2. 如果对象带 `O_PERSISTENCE`：持久化后续使用。
3. 如果对象带 `O_ARCHIVE`：归档后续使用。
4. 否则：写后读取。

#### 8.5.6 因果边置信度

1. 后续是执行，并且对象属于临时文件、下载文件、上传文件、疑似落地执行对象：`0.93`
2. 对象属于持久化或提权配置：`0.78`
3. 对象属于归档文件：`0.66`
4. 其他：`0.55`

#### 8.5.7 桥接后补的聚合标签

如果一条因果边的对象标签命中：

1. `O_FILE_DOWNLOADED`
2. `O_FILE_UPLOADED`
3. `O_SUSPECT_WRITTEN_EXECUTABLE`

那么边两端进程都会补一个聚合标签：

`A_BRIDGED_BY_SUSPICIOUS_OBJECT`

### 8.6 候选攻击链搜索规则

搜索图由两类边组成：

1. 父子进程边。
2. 跨对象因果边。

#### 8.6.1 起始种子规则

某进程只要满足其一，就可以作为起点：

1. 有任何行为标签。
2. 有 `P_WEB_CTX`
3. 有 `P_REMOTE_CTX`
4. 有 `P_UNTRUSTED_CTX`
5. 有 `P_SUSPECT_CTRL_CTX`

#### 8.6.2 深度和时间约束

1. 最大进程链长度：`6`
2. 整条链最大时间跨度：`180` 分钟
3. 相邻扩展最大时间间隔：`120` 分钟
4. 不能回到已经在链里的进程，避免成环。

#### 8.6.3 阶段覆盖规则

每个标签在规则表里都有一个阶段映射：

1. `Entry`：初始入口或初始外联/接入迹象
2. `ExecutionWeak`：较弱执行迹象
3. `ExecutionStrong`：较强执行迹象
4. `TargetAccess`：敏感目标访问或收集
5. `FollowUp`：后续动作，如持久化、横向、外传、清理

只有阶段集合满足下面任意一种，链条才会被保留。

##### 强规则

1. `Entry + ExecutionStrong + TargetAccess`
2. `Entry + ExecutionStrong + FollowUp`
3. `ExecutionStrong + TargetAccess + FollowUp`

##### 中等升级规则

1. `Entry + ExecutionWeak + TargetAccess`
2. `Entry + ExecutionWeak + FollowUp`

##### 弱规则

1. `Entry + ExecutionWeak`
2. `Entry + TargetAccess`
3. `ExecutionWeak + FollowUp`

#### 8.6.4 候选链去重规则

这版实现的去重键是：

只看“进程链本身”，也就是完整的进程序列。

因此：

1. 如果两条链的进程序列完全一样，只是来自不同 seed，或者是通过不同桥边搜出来的，会视为同一条，只保留一条。
2. 如果两条链只是前半段相同、后半段不同，例如 `A -> B -> C` 和 `A -> B -> D`，会同时保留。
3. 如果一条链是 `A -> B`，另一条链是 `A -> B -> C`，因为进程序列不同，也会同时保留。
4. 同一条进程序列如果被搜索到多次，会优先保留阶段覆盖更丰富的那条。

### 8.7 候选链基础打分规则

总分公式是：

`标签分 + 组合分 + 阶段分 + 因果边分 + 前序模型先验分 - 惩罚分`

#### 8.7.1 标签分

各标签分值如下：

| 中文含义 | 标签 | 分值 |
|---|---:|---:|
| 外部网络接触上下文 | `P_NET_CTX` | 3 |
| 不可信上下文 | `P_UNTRUSTED_CTX` | 5 |
| Web 服务上下文 | `P_WEB_CTX` | 3 |
| 远程服务上下文 | `P_REMOTE_CTX` | 4 |
| 高价值访问上下文 | `P_HIGH_VALUE_CTX` | 8 |
| 可疑控制上下文 | `P_SUSPECT_CTRL_CTX` | 8 |
| 子进程可疑 | `A_CHILD_SUSPICIOUS` | 5 |
| 通过可疑对象桥接 | `A_BRIDGED_BY_SUSPICIOUS_OBJECT` | 8 |
| 外部接收 | `B_EXTERNAL_RECV` | 8 |
| 外部发送 | `B_EXTERNAL_SEND` | 20 |
| 临时目录执行 | `B_EXEC_TEMP` | 20 |
| 执行下载文件 | `B_EXEC_DOWNLOADED` | 30 |
| 执行上传文件 | `B_EXEC_UPLOADED` | 24 |
| 执行疑似落地对象 | `B_EXEC_SUSPECT_WRITTEN` | 28 |
| 可疑 Shell 执行 | `B_SHELL_SPAWN` | 8 |
| 可疑解释器执行 | `B_SCRIPT_EXEC` | 8 |
| 解释器启动 | `B_INTERPRETER_LAUNCH` | 6 |
| 读取凭据 | `B_READ_CRED` | 15 |
| 读取历史记录 | `B_READ_HISTORY` | 12 |
| 读取业务数据 | `B_READ_BUSINESS` | 18 |
| 大量文件访问 | `B_MASS_FILE_ACCESS` | 10 |
| 写持久化位置 | `B_WRITE_PERSISTENCE` | 30 |
| 修改提权配置 | `B_WRITE_PRIV_CONFIG` | 30 |
| 压缩归档 | `B_ARCHIVE_DATA` | 18 |
| 清理日志 | `B_DELETE_LOG` | 25 |
| 横向连接 | `B_LATERAL_CONNECT` | 20 |
| 远程服务入口活动 | `B_REMOTE_LOGIN_SERVICE` | 5 |
| Web 上传写入 | `B_WEB_WRITE` | 4 |

#### 8.7.2 阶段分

每覆盖一个阶段，加：

`12`

#### 8.7.3 因果边分

每条跨对象因果边按：

`边置信度 * 12`

加入总分。

#### 8.7.4 组合加分

当前代码真正实现了下面这些组合加分：

1. 外部接收 + 临时目录执行，或 外部接收 + 执行下载文件：`external_plus_temp_exec`
2. 外部接收 + Shell：`external_plus_shell`
3. 执行下载/疑似落地对象 + 读取凭据：`suspicious_exec_plus_sensitive_read`
4. 读取凭据/业务数据 + 外部发送：`sensitive_read_plus_external_send`
5. 执行下载/疑似落地对象 + 持久化写入：`suspicious_exec_plus_persistence`
6. 执行下载/疑似落地对象 + 横向连接：`suspicious_exec_plus_lateral`
7. 进程链长度至少 3 且阶段至少 3 个：`continuous_labeled_chain`

要特别注意：

规则文件里虽然还声明了 `downloaded_write_then_exec`，但当前代码并没有真正实现这个组合加分。

#### 8.7.5 前序模型先验加分

来源有三部分：

1. 任务分数乘以 `20`
2. 候选链里如果包含前序模块排序靠前的进程，按排名加分，默认上限约 `10`
3. 候选链里如果包含前序模块排序靠前的边，按排名加分，默认上限约 `10`

另外还有时间窗口一致性修正：

1. 如果链条时间包络完全落在任务先验时间范围里，加 `8`
2. 否则减 `12`

#### 8.7.6 惩罚项

当前代码真正实现的惩罚项只有三类：

1. 只有弱执行阶段、没有强执行阶段：`weak_execution_only`
2. 跨对象因果边数量达到 4 条及以上：`high_reuse_object`
3. 整条链只覆盖一个阶段，且这个阶段只表现为敏感读取：`single_point_sensitive_read`

规则文件里虽然还声明了下面这些惩罚项，但当前代码没有真正执行：

1. `common_daemon_normal_child`
2. `whitelist_process`
3. `time_gap_too_large`
4. `low_value_object`

### 8.8 候选链辅助证据整理规则

对每条候选链，会额外收集一套辅助证据，用于后续重排和最终报告。

#### 8.8.1 支撑事件

来源包括：

1. 链上所有进程的证据事件。
2. 所有跨对象因果边对应的写事件和读/执行事件。
3. 链上进程触发了路径标签的保留事件。

#### 8.8.2 支撑对象

来源包括：

1. 链上进程的重要对象。
2. 跨对象因果边涉及的对象。
3. 支撑事件里出现的对象。

#### 8.8.3 支撑关系

来源包括：

1. “进程 A 通过对象 X 影响进程 B”的桥边关系摘要。
2. 对象版本摘要，如某版本被多少写者、读者、执行者使用。

#### 8.8.4 前导事件集合

会扫描支撑事件文本，只要命中下列关键词，就把事件记为前导事件：

1. `tcexec`
2. `command-not-found`
3. `/dev/pts/3`
4. `python3`
5. `chmod`
6. `bash`

#### 8.8.5 后续动作事件集合

满足其一的事件会被记为后续动作事件：

1. 事件带 `B_EXTERNAL_SEND`、`B_LATERAL_CONNECT`、`B_DELETE_LOG`
2. 对象类别是外部 IP 或内部 IP，且事件属于网络发送/接收类
3. 删除了临时目录下的对象

#### 8.8.6 网络支撑摘要

会统计：

1. 外部接收次数
2. 外部发送次数
3. 内部连接次数
4. 唯一外部目标数
5. 唯一内部目标数

#### 8.8.7 对象脉络摘要

优先输出：

1. 所有“可疑桥对象”形成的进程间传播关系摘要

如果没有明显桥对象，就退回输出：

1. 前几个支撑对象最新版本的写者/读者/执行者数量

### 8.9 候选链补救规则

这版代码还有一个补救分支，用于保住短生命周期解释器前导链。

触发条件：

1. 当前任务所有候选链里还没有“短前导解释器分支”这种类型。
2. 保留事件中至少有 2 条事件命中了前导关键词。

然后会：

1. 把这些前导事件涉及的进程收集起来。
2. 再补一些共享父进程、且起始时间差不超过 10 分钟的近邻进程。
3. 按时间排成一条最多 6 个进程的链。
4. 作为一条“补救候选链”加入后续打分。

### 8.10 候选链多样性保留规则

最终进入前 `path_top_k` 的候选链，不完全按分数截断。

还有一个“多类行为至少各保一条”的保留逻辑。

它会优先尝试保住下列几类行为家族各自的第一名：

1. 短生命周期解释器前导分支
2. 附件或用户触发执行
3. 临时目录/落地后执行
4. 外连回连
5. 内部扫描或横向
6. 痕迹清理
7. 邮件/浏览器上下文尾部

这一层的目的不是改变路径内容，而是避免前几名都被同一种模式占满。

### 8.11 基于证据质量的二次重排

这版路径重排并不是用标签来源去真正“回溯构链”，而是只做一个小幅度加减分。

总修正分会被截断到：

`[-4, +4]`

#### 8.11.1 证据紧凑度

看支撑事件的总时间跨度：

1. `<= 5` 分钟：`+2`
2. `<= 15` 分钟：`+1`
3. `<= 45` 分钟：`0`
4. `<= 90` 分钟：`-1`
5. `<= 180` 分钟：`-2`
6. `> 180` 分钟：`-3`

#### 8.11.2 标签来源覆盖度

步骤：

1. 先取链上所有“关键标签”。
2. 关键标签定义为：
   1. 所有行为标签
   2. `P_UNTRUSTED_CTX`
   3. `P_HIGH_VALUE_CTX`
   4. `A_BRIDGED_BY_SUSPICIOUS_OBJECT`
3. 再看这些标签里有多少能在标签来源记录中找到对应该链进程或对象的记录。

打分：

1. 覆盖率 `>= 0.85`：`+3`
2. 覆盖率 `>= 0.6`：`+1.5`
3. 覆盖率 `>= 0.35`：`0`
4. 覆盖率 `> 0` 但很低：`-1.5`
5. 完全没有来源支撑：`-3`

但必须再强调一次：

1. 当前标签来源记录不是全量标签链。
2. 因而这一步只能算“局部证据密度修正”，不能算真正的标签回溯构链。

#### 8.11.3 证据关系一致性

看支撑对象数和支撑关系数是否协调：

1. 对象不超过 3 个，且至少 1 条关系：`+1`
2. 对象不超过 5 个，且关系数至少达到对象数的一半：`+0.5`
3. 对象达到 8 个以上但关系不超过 1 条：`-2`
4. 对象达到 6 个以上但关系不超过 2 条：`-1`
5. 对象数超过关系数 3 倍：`-1`

### 8.12 证据时间线裁剪规则

最终写入报告的事件时间线不是全量事件，而是经过优先级裁剪。

事件优先级规则：

1. 如果事件是跨对象因果边上的写事件或读/执行事件：`+100`
2. 如果事件带标签：
   1. 基础 `+40`
   2. 每多一个标签再加 `12`
   3. 如果含行为标签，再额外 `+20`
3. 事件类型如果属于高信号集合：`+8`
4. 对象类别如果属于高信号集合：`+8`
5. 路径在临时目录：`+10`
6. 是网络流对象或对象键里出现 `->`：`+6`

高信号事件类型包括：

1. `EXEC`
2. `CONNECT`
3. `SEND`
4. `RECV`
5. `WRITE`
6. `CREATE`
7. `READ`
8. `DELETE`
9. `RENAME`
10. `CHMOD`
11. `CHOWN`

高信号对象类别包括：

1. 临时文件
2. 外部 IP
3. 内部 IP
4. 凭据文件
5. 历史文件
6. 业务文件
7. 持久化文件
8. 提权配置
9. 日志文件

默认每条链最多保留：

`24` 条时间线事件

## 9. Module6：把候选链解释成攻击行为和 ATT&CK 结论

### 9.1 这一步的目标

这一阶段不是直接“看路径输出结果”，而是分两段：

1. 先把路径整理成证据包，并抽成一组行为声明。
2. 再把这些声明映射到 ATT&CK 战术/技术。

### 9.2 输入给大模型的并不是原始日志

而是一份压缩证据包，包含：

1. 路径编号、风险等级、风险分数、阶段覆盖。
2. 链上核心进程。
3. 跨对象因果边。
4. 裁剪后的证据时间线。
5. 辅助证据对象和辅助关系。
6. 前导事件、后续动作事件。
7. 网络摘要、对象脉络摘要。
8. 规则匹配出的 Holmes 风格候选行为声明。

### 9.3 Holmes 风格行为原子清单

这版代码先定义了一组固定的“行为原子”，每个原子都有：

1. APT 阶段归属。
2. 说明语句。
3. ATT&CK 先验战术。
4. ATT&CK 先验技术。

完整清单如下：

| 中文含义 | 原子代码 | APT 阶段 | ATT&CK 先验 |
|---|---|---|---|
| 接收不可信外部内容 | `untrusted_read` | Initial Compromise | `TA0001` |
| 内存变可执行 | `make_mem_exec` | Initial Compromise | `TA0002` |
| 文件被改成可执行 | `make_file_exec` | Initial Compromise | `TA0002` |
| 不可信落地文件被执行 | `untrusted_file_exec` | Initial Compromise | `TA0002`, `TA0011`, `T1105` |
| 用户打开或执行附件/阶段性对象 | `attachment_user_exec` | Initial Compromise | `TA0001`, `TA0002`, `T1566.001`, `T1566.002`, `T1204.002` |
| Shell 或解释器执行命令 | `shell_exec` | Establish Foothold | `TA0002`, `T1059` |
| 外部回连/C2 通信 | `cnc_communication` | Establish Foothold | `TA0011`, `T1071.001` |
| sudo 提权执行 | `sudo_exec` | Privilege Escalation | `TA0004` |
| 身份切换提权 | `switch_su` | Privilege Escalation | `TA0004` |
| 读取敏感本地信息 | `sensitive_read` | Internal Recon | `TA0006`, `TA0009`, `T1552.003`, `T1005` |
| 执行侦察命令 | `sensitive_command` | Internal Recon | `TA0007` |
| 网络服务发现/扫描 | `network_service_discovery` | Internal Recon | `TA0007`, `T1046` |
| 内网连接/横向 | `send_internal` | Move Laterally | `TA0008` |
| 敏感数据外泄 | `sensitive_leak` | Complete Mission | `TA0010`, `TA0011`, `T1041` |
| 清理日志 | `clear_logs` | Cleanup Tracks | `TA0005`, `T1070.004` |
| 删除敏感收集后留下的临时文件 | `sensitive_temp_rm` | Cleanup Tracks | `TA0005`, `T1070.004` |
| 删除落地或下载后的可疑文件 | `untrusted_file_rm` | Cleanup Tracks | `TA0005`, `T1070.004` |
| 短生命周期解释器前导链 | `interpreter_precursor_chain` | Establish Foothold | `TA0002`, `TA0001`, `T1059` |

### 9.4 Holmes 风格行为原子匹配规则

这一步是纯规则匹配，不需要大模型。

#### 9.4.1 基础证据集合

会先从证据时间线里抽出若干事件编号集合：

1. 外部接收事件。
2. 外部发送事件。
3. 横向连接事件。
4. 可疑执行事件。
5. 敏感读取事件。
6. 历史读取事件。
7. 业务读取事件。
8. 持久化写入事件。
9. 日志删除事件。
10. 侦察命令事件。
11. 扫描事件。
12. 内网连接事件。
13. 内存执行迹象事件。
14. `chmod` 迹象事件。
15. 附件迹象事件。
16. 前导事件。
17. 桥接到执行的事件。
18. 临时文件删除事件。
19. Shell/解释器执行事件。
20. sudo 迹象事件。
21. su/setuid 迹象事件。

#### 9.4.2 每个行为原子的具体触发规则

1. `untrusted_read`：存在外部接收事件。
2. `make_mem_exec`：存在内存执行迹象，并且之前已有外部接收或前导事件。
3. `make_file_exec`：存在 `chmod` 迹象，并且之前已有外部接收、桥接执行或前导事件。
4. `untrusted_file_exec`：存在桥接到执行事件。
5. `attachment_user_exec`：存在附件迹象事件。
6. `shell_exec`：存在 Shell/解释器执行事件。
7. `cnc_communication`：存在外部发送，或者“有外部接收并且证据包里存在网络摘要”。
8. `sudo_exec`：存在 sudo 迹象。
9. `switch_su`：存在 su/setuid 迹象。
10. `sensitive_read`：存在敏感读取、历史读取或业务读取。
11. `sensitive_command`：存在侦察命令事件。
12. `network_service_discovery`：扫描事件至少 2 个，或者同时存在扫描事件和横向连接事件。
13. `send_internal`：存在内网连接事件。
14. `sensitive_leak`：同时存在外部发送和敏感读取。
15. `clear_logs`：存在日志删除。
16. `sensitive_temp_rm`：存在临时文件删除，并且之前有敏感读取。
17. `untrusted_file_rm`：存在临时文件删除，并且之前有桥接到执行。
18. `interpreter_precursor_chain`：存在前导事件。

### 9.5 行为原子之间的前置依赖规则

这一步会构造一个有向因果图，前驱关系如下：

1. `make_mem_exec` 依赖 `untrusted_read`
2. `make_file_exec` 依赖 `untrusted_read`
3. `untrusted_file_exec` 依赖 `untrusted_read`、`make_file_exec`、`attachment_user_exec`
4. `attachment_user_exec` 依赖 `untrusted_read`
5. `shell_exec` 依赖 `untrusted_file_exec`、`attachment_user_exec`、`interpreter_precursor_chain`
6. `cnc_communication` 依赖 `untrusted_file_exec`、`attachment_user_exec`、`shell_exec`、`interpreter_precursor_chain`
7. `sudo_exec` 依赖 `shell_exec`
8. `switch_su` 依赖 `shell_exec`
9. `sensitive_read` 依赖 `untrusted_file_exec`、`shell_exec`、`cnc_communication`、`interpreter_precursor_chain`
10. `sensitive_command` 依赖 `untrusted_file_exec`、`shell_exec`、`cnc_communication`、`interpreter_precursor_chain`
11. `network_service_discovery` 依赖 `shell_exec`、`cnc_communication`、`attachment_user_exec`
12. `send_internal` 依赖 `shell_exec`、`cnc_communication`
13. `sensitive_leak` 依赖 `sensitive_read`、`cnc_communication`
14. `clear_logs` 依赖 `shell_exec`、`cnc_communication`
15. `sensitive_temp_rm` 依赖 `sensitive_read`
16. `untrusted_file_rm` 依赖 `untrusted_file_exec`
17. `interpreter_precursor_chain` 依赖 `attachment_user_exec`、`make_file_exec`、`untrusted_read`

### 9.6 第一次大模型调用：行为确认

这一步并不是让大模型自由发挥，而是严格要求它只在现有行为原子里做“确认、细化或放弃”。

提示词规则可以概括为：

1. 只能用证据包里的证据。
2. 只围绕攻击相关语义，不要总结无关宿主上下文。
3. 只能确认、细化或忽略已经预匹配好的 Holmes 风格行为原子。
4. 不能新造行为类型。
5. 不能新造声明编号。
6. 尽量保留已给出的证据事件编号。
7. 优先用桥边、支撑关系、带标签的网络/文件事件，不要只看时间顺序。
8. 不要写“可能有威胁”“一串系统调用显示异常”这类泛化废话。
9. 如果没有任何原子被支持，就返回空声明并解释缺口。
10. 置信度必须在 `0~1`。

### 9.7 行为声明校验规则

大模型吐出来的行为声明不会直接被信任，还要经过强校验。

#### 9.7.1 基本合法性

1. 必须有声明编号。
2. 必须有说明语句。
3. 证据事件编号必须都存在于证据包里。
4. 不能是明显空泛陈述。

#### 9.7.2 各行为类型的“必要证据”规则

下面这些规则全部在代码里硬编码：

1. `untrusted_read`：必须出现 `B_EXTERNAL_RECV`，或者对象类别是外部 IP 且事件属于 `RECV/CONNECT`
2. `make_mem_exec`：语句或事件描述里必须出现 `mprotect`、`mem exec`、`virtualalloc`
3. `make_file_exec`：语句或事件里必须出现 `chmod`、`executable`、`staged object`，或者事件类型属于 `CHMOD / MODIFY_FILE_ATTRIBUTES`
4. `untrusted_file_exec`、`attachment_user_exec`：必须有可疑执行标签，或者证据事件命中桥接到执行的事件
5. `shell_exec`、`interpreter_precursor_chain`：语句或事件里必须出现 `bash`、`shell`、`python`、`perl`、`php`、`tcexec`、`command-not-found`
6. `cnc_communication`：必须有外部收发标签，或者对象类别是外部 IP 且事件属于 `SEND / CONNECT / RECV`
7. `sudo_exec`：语句里必须有 `sudo`
8. `switch_su`：语句里必须有 `setuid`、` su `、`switch user`
9. `sensitive_read`：必须有敏感读取标签
10. `sensitive_command`：语句里必须有 `whoami`、`hostname`、`netstat`、`ifconfig`、`uname`、`system information`、`enumeration`
11. `network_service_discovery`：必须有横向连接标签，或者语句里有 `scan`、`discovery`、`connect burst`、`service discovery`
12. `send_internal`：必须出现内部 IP 或横向连接标签
13. `sensitive_leak`：必须同时具备外部发送和敏感读取
14. `clear_logs`、`sensitive_temp_rm`、`untrusted_file_rm`：必须有日志删除标签，或者事件类型属于 `DELETE / UNLINK / RENAME`

### 9.8 行为声明兜底合并规则

最终不会只保留大模型返回的声明，而是：

1. 先按上面规则校验大模型声明。
2. 再把规则匹配出的 Holmes 原子声明合并进来。
3. 如果同一行为类型同时存在规则声明和大模型确认声明，会做合并：
   1. 取更高置信度
   2. 合并证据事件编号
   3. 标记来源为“规则 + 大模型确认”

### 9.9 IOC 校验规则

IOC 只做基本清洗：

1. 必须有值。
2. 置信度裁剪到 `0~1`。
3. 证据事件编号只做保留，不做更复杂校验。

### 9.10 ATT&CK 候选检索规则

ATT&CK 候选不是直接问大模型生成，而是先从本地 STIX 知识库里检索一批候选。

#### 9.10.1 用来检索的查询上下文来自哪里

从证据包中提取：

1. 动作族
2. 行为类型
3. 命令词
4. 对象语义
5. 操作系统提示
6. 声明文本

#### 9.10.2 动作族提取规则

1. 看到 `CONNECT / SENDMSG / SENDTO / RECVMSG / RECVFROM`：加入网络通信族
2. 看到 `EXECUTE / CREATE_OBJECT / LOAD / MMAP / CLONE / FORK`：加入执行族
3. 看到 `WRITE / RENAME / TRUNCATE / MODIFY_PROCESS`：加入文件/持久化族
4. 声明或摘要里出现 `discover`、`discovery`、`enumerat`、`whoami`、`netstat`、`scan`、`find `、`ls `：加入侦察族
5. 出现 `credential`、`password`、`token`、`secret`：加入凭据族

#### 9.10.3 对象语义提取规则

从路径和描述中提炼出：

1. Shell profile 修改
2. 定时任务或服务工件
3. 临时可执行工件
4. 主机发现文件
5. 远端端点
6. 文件发现类工件

#### 9.10.4 检索排序方法

候选排序由三部分组成：

1. 稀疏检索分数：TF-IDF，权重 `0.45`
2. 稠密向量检索分数：Sentence Transformer，权重 `0.55`
3. 兼容性奖励分

默认：

1. 技术候选上限 `12`
2. 战术候选上限 `5~8`

#### 9.10.5 兼容性奖励规则

兼容性奖励主要看：

1. 动作族与 ATT&CK 描述是否语义一致
2. 对象语义是否重叠
3. 操作系统是否匹配
4. 声明词项是否有重叠
5. 某行为类型是否带有 ATT&CK 先验

典型奖励/惩罚：

1. 网络通信族匹配到通信类 ATT&CK：`+0.28`
2. 执行族匹配到脚本/执行类 ATT&CK：`+0.26`
3. 文件/持久化族匹配到持久化类 ATT&CK：`+0.28`
4. 侦察族匹配到侦察类 ATT&CK：`+0.28`
5. 凭据族匹配到凭据类 ATT&CK：`+0.28`
6. 对象语义词项重叠：每项 `+0.10`
7. Linux 语境匹配到明显 Windows/Mac 词：最高约 `-0.45`
8. 行为类型命中 ATT&CK 先验技术：`+0.75`
9. 行为类型命中 ATT&CK 先验战术：`+0.45`

### 9.11 行为先验提示规则

这版还会根据行为类型生成“软先验”，用来提醒大模型不要乱映射。

例如：

1. 下载并执行 -> 倾向 `TA0011 + T1105`
2. 读取凭据 -> 倾向 `TA0006`
3. 读取业务数据 -> 倾向 `TA0009 + T1005`
4. 持久化修改 -> 倾向 `TA0003`
5. 日志删除 -> 倾向 `TA0005 + T1070.004`
6. 远程发送 -> 倾向 `TA0011`
7. 横向连接 -> 倾向 `TA0008`
8. 远程服务入口 -> 倾向 `TA0001`
9. 执行链 -> 倾向 `TA0002`

对 `remote_send` 还有一个动态规则：

1. 如果同一声明里至少有 3 个相关事件，
2. 且其中至少 2 个目标端口属于 `80/443/8080/8443`
3. 则进一步倾向 `TA0011 + T1071.001`

### 9.12 第二次大模型调用：ATT&CK 映射

这一步的提示词也有严格限制。

核心要求：

1. 只能使用提供的声明、时间线和候选 ATT&CK 列表。
2. 要把声明当作已经预匹配好的行为原子，保留它们的因果顺序。
3. 每个声明独立映射，不要把一个声明的技术硬套给不相关声明。
4. 只能从候选列表里选。
5. 先选战术，再选技术。
6. 如果战术有支撑而技术支撑弱，可以技术留空。
7. `network_service_discovery` 和 `sensitive_command` 默认更偏向 Discovery。
8. `clear_logs`、`sensitive_temp_rm`、`untrusted_file_rm` 默认更偏向 Defense Evasion。
9. `attachment_user_exec` 默认偏向 Initial Access + Execution。
10. 对“读取凭据”而没有更强技术证据的情况，宁可只给 Credential Access 战术，也不要乱给技术。

### 9.13 ATT&CK 映射校验规则

大模型映射结果还要经过严厉校验。

#### 9.13.1 基本合法性

1. 必须至少引用一个有效声明编号。
2. tactic_id 必须匹配 `TA\d{4}`
3. technique_id 必须匹配 `T\d{4}` 或子技术形式
4. tactic / technique 必须能在候选列表中解析到

#### 9.13.2 候选约束

1. tactic 和 technique 都必须来自已经检索到的候选集
2. 如果只给了 technique，系统会尝试从该 technique 关联的 tactic 里补战术

#### 9.13.3 战术和技术一致性

如果同时给了 tactic 和 technique，则要求：

1. 该 technique 的 tactic_ids 中包含该 tactic
2. 或者知识库里能证明这个 technique 支持该 tactic

否则整条映射丢弃。

#### 9.13.4 行为类型允许战术集合

每个行为类型都有限制允许映射到哪些战术。

例如：

1. `download_and_exec`：只允许 `TA0011` 或 `TA0002`
2. `credential_read`：只允许 `TA0006` 或 `TA0009`
3. `business_data_access`：只允许 `TA0009` 或 `TA0010`
4. `persistence_change`：只允许 `TA0003` 或 `TA0005`
5. `log_deletion`：只允许 `TA0005`
6. `remote_send`：只允许 `TA0011` 或 `TA0010`
7. `lateral_connect`：只允许 `TA0008`
8. `remote_service_entry`：只允许 `TA0001`
9. `execution_chain`：只允许 `TA0002`

Holmes 风格行为原子也有自己的允许战术集合。

如果映射结果战术不在允许集合里，这条映射会被丢掉。

#### 9.13.5 先验技术一致性

如果某个行为类型有动态先验技术，例如 `remote_send -> T1071.001`，那么：

1. 大模型若给了不同技术，会被丢弃。
2. 如果先验只给了战术没有给技术，而大模型硬给了技术，也可能被压掉。

### 9.14 行为先验二次修正规则

在大模型映射校验后，系统还会做一层“行为先验修正”：

1. 如果某条映射与行为先验冲突，就抑制掉。
2. 如果先验映射尚未出现在结果里，就把先验映射补进去。

### 9.15 可切换的两种映射模式

#### 9.15.1 全量映射模式

默认模式：

1. 输出战术和技术。
2. 需要第二次大模型调用。

#### 9.15.2 只输出战术模式

当 `attack_mapping_scope = tactics_only` 时：

1. 技术字段会被清空。
2. 如果 `tactic_mapping_mode = deterministic`，则可以完全不调用第二次大模型，直接用 Holmes 行为原子的战术先验生成战术结果。

## 10. 这版攻击分析里“声明了但没真正实现”的地方

这一节非常重要，因为如果只看规则文件，很容易误以为这些逻辑都已经在跑。

### 10.1 不是通用规则引擎

虽然 YAML 里有 `labels.*.init_rules`、`propagation_rules`，但当前代码没有写一个通用解释器逐条执行它们。

真实情况是：

1. 标签触发逻辑主要硬编码在 `module4` 和 `path_labeler`。
2. YAML 更多是拿来提供：
   1. 名单
   2. 阶段映射
   3. 分值
   4. 允许/禁止集合
   5. 时间和数量阈值

### 10.2 规则表里的部分标签当前不会真正出现

至少下面这些标签在这版代码里没有实际生成逻辑：

1. `P_SUSPECT_CTRL_CTX`
2. `O_FILE_WRITTEN_BY_NET_CONTEXT`
3. `O_AUTH_CONFIG`
4. `O_ARCHIVE`
5. `O_SECURITY_LOG`

这意味着：

1. 它们虽然定义了阶段映射和分值，
2. 但当前主流程实际上很可能永远不会打出这些标签。

### 10.3 规则表和真实实现不一致的典型例子

下面这些差异很容易让人只看 YAML 时产生误解：

1. `P_WEB_CTX` 在规则表里声明了“入站 Web 端口命中”和“访问 Web 根目录”两类触发，但当前代码真正实现的是：
   1. 进程名属于 Web 服务
   2. 对上传路径执行写入，且该路径位于 Web 根目录
2. `P_REMOTE_CTX` 在规则表里声明了“远程管理端口入站”和“tty 来自远程父进程”等规则，但当前代码真正实现的只有“进程名属于远程服务”。
3. `P_WEB_CTX` 的传播规则里声明了“向可疑子进程传播时顺便补 `P_SUSPECT_CTRL_CTX`”，但当前传播器没有实现“按标签专属传播规则追加其他标签”这层逻辑，所以这条规则没有落地。
4. `B_SHELL_SPAWN` 在规则表里声明了“进程执行带特定对象标签的对象”这一条件，但代码里真正直接检查的是父进程上下文、父进程名和命令行特征。
5. `B_SCRIPT_EXEC` 在规则表里声明了“读取或执行了带特定对象标签的对象”，代码里只对当前事件自带的标签触发信息做了有限利用，不是严格的完整对象标签依赖判定。
6. `B_MASS_FILE_ACCESS` 的规则表定义是“5 分钟窗口、100 个文件或 100MB 读量”，但真实代码只实现了“1 分钟内读取 100 个不同对象”。
7. 规则表给很多标签写了 `ttl_minutes`，但当前实现没有在标签生命周期上真正执行 TTL 过期逻辑。

### 10.4 部分 YAML 规则与真实代码不一致

最典型的是：

1. `B_MASS_FILE_ACCESS`：YAML 写 5 分钟窗口和 100MB 读取量，代码只实现了“1 分钟内 100 个不同对象”。

### 10.5 部分打分项写了但没用

当前未真正执行的分数项包括：

1. 组合分：`downloaded_write_then_exec`
2. 惩罚分：`common_daemon_normal_child`
3. 惩罚分：`whitelist_process`
4. 惩罚分：`time_gap_too_large`
5. 惩罚分：`low_value_object`

### 10.6 标签来源没有真正参与构链

当前真实情况是：

1. 候选攻击链是通过“进程树边 + 同对象先写后读/执行边”搜索出来的。
2. 不是通过“从最终标签沿标签来源记录反向回溯”构出来的。
3. 标签来源目前只参与 `module5` 的一个小幅度重排分数。

### 10.7 一些辅助产物写出来了，但主流程没有真正消费

例如：

1. `module3` 的实体索引、事件索引、任务局部证据图
2. `module4` 的事件聚合片段

这些文件对人工分析有帮助，但不构成当前主链路的核心决策输入。

### 10.8 一些配置项存在但当前主链路没有真正使用

例如：

1. `evidence_recover_task_time_padding_minutes`
2. `evidence_recover_anchor_top_k`
3. `path_hot_process_threshold`
4. `path_require_execution_strong_for_high`
5. `path_allow_weak_execution_medium`
6. `reason_max_objects_per_path`
7. 标签元数据中的 `ttl_minutes`
8. 传播配置里的 `stop_after_consecutive_low_risk_layers`

## 11. 这版 step2b1 攻击分析的本质特点

如果用一句话概括，这版的攻击分析是：

“先围绕可疑任务图回查日志，把日志压成带标签的进程/对象状态，再靠父子关系和同对象先写后读/执行关系拼出候选攻击链，最后用 Holmes 风格行为原子 + ATT&CK 检索 + 大模型映射输出结论。”

它的强项是：

1. 结构清晰，容易调试。
2. 能把前序模型分数、事件证据、对象传播、行为归纳连起来。
3. 输出产物丰富，便于人工复盘。

它的弱点也很明显：

1. 标签规则和 YAML 声明并不完全一致。
2. 标签来源没有真正成为主构链机制。
3. 有些关键标签定义了但没真正落地。
4. 一部分路径后处理逻辑带有较强经验性。
5. 真正的“标签传播系统”仍然比 APTShield 那种基于规则链的传递要弱很多。

## 12. 各阶段对应的代码文件

### 12.1 主线入口

1. `src/apt_fusion/pipeline.py`

### 12.2 任务回查与标准化

1. `src/apt_fusion/path_reason/module3_evidence_recover.py`
2. `src/apt_fusion/path_reason/log_stream.py`
3. `src/apt_fusion/path_reason/evidence_normalizer.py`
4. `src/apt_fusion/path_reason/object_classifier.py`

### 12.3 事件压缩与轻量标签

1. `src/apt_fusion/path_reason/module4_semantic_compact.py`
2. `src/apt_fusion/path_reason/semantic_skip.py`
3. `src/apt_fusion/path_reason/episode_aggregation.py`
4. `src/apt_fusion/path_reason/label_provenance.py`

### 12.4 链条构造与重排

1. `src/apt_fusion/path_reason/path_labeler.py`
2. `src/apt_fusion/path_reason/path_propagator.py`
3. `src/apt_fusion/path_reason/bridge_builder.py`
4. `src/apt_fusion/path_reason/path_search.py`
5. `src/apt_fusion/path_reason/path_scoring.py`
6. `src/apt_fusion/path_reason/path_report.py`
7. `src/apt_fusion/path_reason/module5_path_finder.py`

### 12.5 行为解释与 ATT&CK 映射

1. `src/apt_fusion/path_reason/holmes_claims.py`
2. `src/apt_fusion/path_reason/attack_kb.py`
3. `src/apt_fusion/path_reason/module6_attack_reason.py`

## 13. 最后一句最重要的话

如果你接下来要改这版 `step2b1` 的攻击分析逻辑，优先级应该这样理解：

1. 真正决定“有没有候选链”的，是 `module5` 里的完整标签、传播规则、跨对象因果边和 DFS 搜索。
2. 真正决定“候选链长什么样”的，是 `path_labeler.py`、`path_propagator.py`、`bridge_builder.py`、`path_search.py`。
3. 真正决定“最后报告说成什么攻击行为”的，是 `holmes_claims.py` 和 `module6_attack_reason.py`。
4. `label_provenance` 在这版里还不是主构链机制，只是一个辅助证据质量因子。
