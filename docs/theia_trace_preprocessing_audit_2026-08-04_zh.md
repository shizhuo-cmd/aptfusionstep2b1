# THEIA 与 TRACE 任务图检测预处理审计

## 目的与范围

本次审计只检查模块 1、模块 2 前的日志读取、进程身份规范化、切图、GT 标注、节点特征和 normal-only 评估。比较对象是：

- THEIA：`artifacts_theia_normal_only_g0_tapas_paper_baseline_20260804`
- TRACE：`artifacts_trace_normal_only_tapas_paper_baseline_20260802`

两次都未运行模块 0，均为 `42` 维序列向量与 `15` 维安全统计的 G0 normal-only 原型检测配置。

## 已确认事实

| 项目 | THEIA | TRACE | 影响 |
| --- | ---: | ---: | --- |
| 任务图数 | 12,888 | 1,108 | 任务规模和正负构成不可直接类比。 |
| GT-positive 图数 | 459 | 4 | TRACE 的宏 F1 仅基于 4 张正图，不能作为 THEIA 适配成功的证据。 |
| 图节点数中位数 / P90 / 最大值 | 4 / 48 / 6,051 | 后续补充 | THEIA 同时包含大量极小图与少量超大图。 |
| 正图节点数中位数 / P90 / 最大值 | 4 / 5 / 2,058 | 后续补充 | 459 张正图中有 435 张只有 4 或 5 个节点，451 张只包含 1 个 GT 节点。 |
| 图节点零序列向量 | 46,132 / 173,988（26.5%） | 742 / 21,070（3.5%） | THEIA 大量进程没有可用的旧序列特征。 |
| 非零安全统计向量 | 0 / 173,988 | 20,328 / 21,070 | THEIA 的统计特征名义存在，实际全零。 |
| G0 宏 F1 | 0.4853 | 0.9271 | TRACE 的数值受极小正类样本量影响。 |
| G0 TP / FP / FN | 23 / 45 / 436 | 3 / 0 / 1 | THEIA 的核心问题是正类召回约 5%，不是 GNN 方向。 |

THEIA 正图的分数中位数为 `1.5106`，而 2% 良性验证分位数阈值为 `2.5227`；436 张漏报正图的节点数中位数为 4。23 张命中正图的分数中位数为 `5.0590`，且通常更大。因此当前阈值不是唯一根因，绝大多数小正图在表征空间中接近良性图。

## 已确认的代码差异

### 1. THEIA 使用旧的单遍 `filters()`，TRACE 使用两阶段解析

- TRACE 的 `parser_trace()` 会先收集 Subject 和事件，随后用 `_resolve_thread_subject_owners()` 统一把原始 Subject UUID 重映射到规范进程 ID；它还保存原始到规范节点的映射、完整事件类型统计、语义事件统计和事件时间范围。
- THEIA 的 `filters()` 一边读取日志一边依据 `(parent UUID, tgid, path)` 更新 `subjswap`，仅替换读到映射之后的事件 Subject。较早读到的事件不会在最后统一重映射。
- THEIA `filters()` 没有返回 `parser_metadata`，因此模块 1 无法进行 GT 规范化、保留线程归并审计信息或构造完整事件统计。

这会直接造成同一逻辑进程的事件被分散到不同 UUID，或者任务图节点没有对应的历史向量。THEIA 的 26.5% 零序列向量与此路径高度一致，但仍需原始日志扫描区分“别名错配”和“被过滤事件/对象”两类原因。

### 2. THEIA 的线程规则不符合当前采用的 TAPAS 条件

论文规则是：子 Subject 的父 Subject 已知，且父子 `tgid` 相同，则合并到父进程。TRACE 使用 `_resolve_thread_subject_owners()` 实现此规则。

THEIA 旧逻辑没有先确认父 Subject 是否存在，也没有以父 Subject 为 owner；它以 `(parent UUID, tgid, path)` 为键，把拥有相同三元组的 Subject 合并。这既可能漏掉真实线程，也可能把相同父、相同路径的独立进程混合。原始日志扫描将量化两种集合的差异。

### 3. THEIA 的序列事件白名单过窄，且输入文件顺序不稳定

- THEIA `filters()` 仅保留 10 类：`ACCEPT/CONNECT/EXECUTE/EXIT/READ/RECVFROM/RECVMSG/SENDTO/SENDMSG/WRITE`。
- 它忽略日志中与攻击高度相关的 `OPEN`、`CLONE`、`MMAP`、`MPROTECT`、`UNLINK`、`CHANGE_PRINCIPAL`、`MODIFY_FILE_ATTRIBUTES` 等事件。
- THEIA 使用 `os.listdir()` 的原始顺序；TRACE 使用 `sorted(os.listdir(...))`。在 THEIA 的单遍别名与序列构造中，这会使结果依赖目录枚举顺序，难以复现。

### 4. THEIA 的安全统计特征被错误标记为可用

模块 1 对两套数据都保存 `stat_feature_source=parser_full_action_counts_security_semantic`。TRACE 的 15 个统计维度有 143,937 个非零值；THEIA 的 15 个维度在全部 173,988 个进程上均为零。

原因是 THEIA `filters()` 不生成 `canonical_event_action_counts`，而 `_build_tc3_bundle()` 仍把空字典作为完整统计传入特征提取函数。结果不是报错，而是为每个进程生成全零统计并写入“完整安全统计”标签。这是需要修复的特征有效性与摘要真实性问题。

### 5. normal-only 的“时间切分”当前没有实际时间依据

`_normal_only_temporal_split()` 会按 `first_timestamp_sec` 等字段排序。两套已运行 bundle 的所有任务都没有这些字段，实际退化为按 `task_id` 排序。该问题同时存在于 TRACE 和 THEIA，因此不能解释二者差异，但会削弱 normal-only 结果的时间泛化解释。

### 6. 直接修复过的运行阻断问题

THEIA `filters()` 不返回 `event_count`，但 `_build_tc3_bundle()` 在统计特征开启时仍引用该局部变量，首次 G0 运行因此报 `UnboundLocalError`。已初始化为 `None`，使 THEIA 可以走通模块 1；这只是避免崩溃，不会补出缺失统计。

## 当前结论

这次 THEIA 的低指标确实反映了实现不适配，而不是单纯“换一个 GNN 就能解决”。无向和方向感知 G1 均没有增加正类命中，符合输入特征和身份规范化存在系统性缺失的判断。

在修复前，不应继续把 TRACE 的 `0.9271` 与 THEIA 的 `0.4853` 当作可直接比较的模型结论：TRACE 只有 4 个正图，THEIA 有 459 个正图，且二者的 GT 身份口径不同。

## 原始日志核验

### THEIA

对 25 个 JSON 日志的只读扫描得到：

- 共 `106,044,692` 条 Event、`279,391` 条 Subject；所有 Subject 的类型均为 `SUBJECT_PROCESS`，但 `1,298` 个 Subject 满足“父 Subject 已知且父子 `tgid` 相同”的论文线程合并条件。
- GT 文件包含 `2,041` 个 UUID，全部精确命中 Subject，且每一个都有原始事件。因此“THEIA 正图很多”不是 FileObject/NetFlowObject 被误当进程造成的。
- 当前旧序列白名单仅保留 `33,068,985 / 106,044,692 = 31.18%` 的 Event。
- GT Subject 的原始事件中，`EVENT_MPROTECT=26,173,583`、`EVENT_RECVFROM=3,996,536`、`EVENT_MMAP=545,547`、`EVENT_OPEN=342,401`；旧输入只保留其中的网络、读写和执行项，完全丢弃最主要的 `MPROTECT`，也丢弃 `MMAP/OPEN/UNLINK/CLONE` 等攻击相关行为。
- 旧 `(parent,tgid,path)` 规则产生 `4,672` 个碰撞组，预计合并 `109,889` 个 Subject，最大单组为 `4,049` 个 Subject。这与应按论文规则合并的 `1,298` 个数量相差两个数量级，属于明确的过度合并，而不是轻微实现差异。

对应源码位置：

- [darpa.py](D:\daima\APT-Fusionstep2b1\vendor\tapas\darpa.py:994) 的 `filters()` 是 THEIA 的旧单遍入口。
- [darpa.py](D:\daima\APT-Fusionstep2b1\vendor\tapas\darpa.py:1001) 使用未排序的 `os.listdir()`。
- [darpa.py](D:\daima\APT-Fusionstep2b1\vendor\tapas\darpa.py:1004) 固定旧 10 类事件白名单。
- [darpa.py](D:\daima\APT-Fusionstep2b1\vendor\tapas\darpa.py:1038) 只对读到别名之后的事件做替换。
- [darpa.py](D:\daima\APT-Fusionstep2b1\vendor\tapas\darpa.py:1065) 使用 `(parent,tgid,path)` 作为身份合并键。
- 对照地，[darpa.py](D:\daima\APT-Fusionstep2b1\vendor\tapas\darpa.py:561) 的 `parser_trace()` 从排序输入开始，并在完整 Subject 集合建好后再统一规范化事件。

### TRACE

对 7 个 JSON 日志的同口径只读扫描得到：

- 共 `21,914,150` 条 Event、`2,427,839` 条 Subject。其中 `SUBJECT_PROCESS=32,434`，`SUBJECT_UNIT=2,395,405`。TRACE 不是通过 `tgid` 表达线程关系，不能把 THEIA 的同 `tgid` 合并规则直接套用到它。
- 旧序列白名单保留 `12,147,001 / 21,914,150 = 55.43%` 的 Event，高于 THEIA 的 31.18%，但依然遗漏 `MPROTECT=5,066,584`、`MMAP=482,843`、`CLOSE=1,049,390`、`CLONE/FORK` 等类型。
- TRACE GT 的 `68,183` 条记录绝大部分不是进程 UUID：仅 `11` 条命中 Subject、`14` 条命中 FileObject、`68,061` 条命中 NetFlowObject、`49` 条只命中 PredicateObject。现有 TRACE 路径通过 CID/事件关系间接标注任务图；不能把“GT 文本中只有 11 个 Subject UUID”误读为只有 11 个恶意进程。
- 使用 `(parent,tgid,path)` 的旧式三元组在 TRACE 会产生 `4,291` 个碰撞组、理论上合并 `2,423,161` 个 Subject；CID 作为原始 Subject 身份也会理论合并 `2,406,696` 个 Subject。这些数值主要来自大量 `SUBJECT_UNIT`，说明 TRACE 必须保留当前的 owner/CID 两阶段规范化，而不是复用 THEIA 的旧三元组合并。

因此，TRACE 的 `0.9271` 宏 F1 既受“仅 4 张 GT-positive 图”影响，也受其 GT 以网络流/对象为主、标注口径与 THEIA 不同影响。它能证明 TRACE 路径在该小评估集上可用，但不能证明同一分类器已经适配 THEIA。

## 建议修复顺序

1. 为 TC3 THEIA 改用与 `filters_theia_e5()` 同样的两阶段解析框架：先收集 Subject、对象和事件，再按父子同 `tgid` 规范化并一次性重映射事件。
2. 在同一解析阶段保存 `raw_subject_to_canonical_node`、时间范围、全事件动作统计和解析计数；空统计必须标记为不可用，而非伪装为安全统计。
3. 保留“旧 10 类事件”与“扩展事件集”双线，重新训练或至少单独评估序列编码器，不能把扩展类别直接喂给只见过旧类别分布的 checkpoint。
4. 将组件首时间戳写进每个 task metadata，令 normal-only 的训练/验证/评估真正按时间划分。
5. 修复后先用固定 G0 做模块 1/2 对照；只有表征与 GT 覆盖恢复后，再判断 G1 是否值得保留。

## 审计结论与优先级

THEIA 的低指标首先是预处理和特征供给失配，而不是 G0/G1 图分类器的主要问题。最直接的证据是：所有 2,041 个 THEIA GT UUID 都是有事件的 Subject，但旧路径只保留 31.18% 的事件、错误地按三元组压缩约 109,889 个 Subject，并且输出 46,132 个零序列向量和全部为零的安全统计特征。相比之下，TRACE 的两阶段解析保留更多事件并生成可用统计特征，但其只有 4 张正图，不能用其 F1 作为 THEIA 的同口径目标。

修复优先级如下：

1. 最高优先级：为 TC3 THEIA 实现独立的两阶段解析和规范化，严格使用“父 Subject 已知且父子 `tgid` 相同”进行线程合并，并对全部历史 Event 一次性重映射。
2. 高优先级：为 THEIA 返回真实的解析元数据与事件统计；没有统计时明确关闭该分支，不再写入全零但标称可用的统计向量。
3. 高优先级：固定排序并以双线实验重新评估旧事件集和扩展事件集。扩展事件集必须配合重新训练或单独验证序列表征模型，不能直接复用只见过旧事件分布的 checkpoint。
4. 中优先级：在任务元数据中保存真实时间戳，修复 normal-only 的时间切分；目前 THEIA 和 TRACE 都退化为按任务 ID 切分。
5. 后续：待前四项完成后，才以相同切图、GT 覆盖和特征条件对比 G0、G1 与其它 GNN；现阶段继续换 GNN 缺少有效输入基础。
