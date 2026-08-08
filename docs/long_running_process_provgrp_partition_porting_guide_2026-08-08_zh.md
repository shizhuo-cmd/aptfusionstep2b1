# 将长运行进程行为切分模块移植到 APT-Fusionstep2b1 的施工说明

## 1. 本次目标、范围与边界

本施工单的目标是：把 `APT-Fusionstep2b3` 中已经实现的、参考 ProvGRP 论文的“长运行进程行为切分”模块移植到 `APT-Fusionstep2b1`，用于在基础任务图切分后，继续拆分 CADETS 中由长期运行根进程产生的大型分支图。

本次只移植任务图构造/切分部分，不改 GraphSAGE、XGBoost、融合、恶意任务图分类、链条生成或大模型部分。

本次要同时带回两套代码，但只有第一套允许被接入和试验：

|代码|用途|本次状态|
|---|---|---|
|`provgrp_paper_partition.py`|论文结构化实现：读取原始 CDM18 日志，只看进程、文件、网络流三类对象；分开聚类根进程的入边和出边，再按因果时间关系组织 fork/clone 子分支|**接入，但默认关闭；首次只对 CADETS 开启**|
|`provgrp_behavior_partition.py`|旧版探索实现：为每个 fork/clone 找其前 30 秒内最近的一条根进程非 fork/clone 事件，再据此聚类|**只复制存档，暂不导入、暂不调用、暂不放进 YAML 开关**|

不要把两个实现串联运行，也不要把旧版的 30 秒锚点逻辑混入论文式实现。两者回答的是不同问题，混用后无法解释实验结果。

## 2. 先理解 step2b1 现有代码，避免覆盖原有能力

`step2b1` 的 CADETS 任务图主链在：

`src/apt_fusion/task_detection/tapas_native_backend.py` 中的 `_build_tc3_bundle()`。

其当前顺序是：

1. `vendor/tapas/darpa.py::parser_cadets()` 读取 CADETS 原始日志、归并 Subject、构造进程父子关系和解析元数据。
2. `vendor/tapas/darpa.py::encode_cadets()` 生成进程事件序列表示。
3. `vendor/tapas/darpa.py::cut_task(..., return_task_components=True)` 按 `child_threshold`、`split_mode` 进行基础任务图切分。
4. `tapas_native_backend.py` 可选继续运行根节点时间切分、时间 episode 切分、合成根节点隔离、分支对象重叠切分。
5. `_decompose_tc3_metadata()` 将任务组件交给 TAPAS 的 `decompose()`，形成图学习需要的图元数据。
6. `_save_module1_exports()` 导出 `task_subgraphs.json`、`task_component_diagnostics.json`、`process_segmentation_edges.csv` 等 Module 1 产物。

因此，不能把 `step2b3` 的整个 `tapas_native_backend.py` 覆盖到 `step2b1`：`step2b1` 已有自己的二次切分、诊断字段和后续功能。只应手工移植下文列出的 import、配置、调用点和诊断字段。

`step2b1` 当前没有 `tools/` 目录；需要新建该目录来放独立结构实验脚本。独立脚本只重切已生成的 Module 1 任务图，不应触发 Module 0，也不应重新训练模型。

## 3. 需要查看和复制的 step2b3 文件

### 3.1 必须完整复制的实现文件

1. 复制：
   - 源：`D:/daima/APT-Fusionstep2b3/src/apt_fusion/task_detection/provgrp_paper_partition.py`
   - 目标：`D:/daima/APT-Fusionstep2b1/src/apt_fusion/task_detection/provgrp_paper_partition.py`
   - 要求：完整复制，不要删改函数逻辑后再称为同一次实验。先保证两边文件哈希或 diff 一致，再做 `step2b1` 后端接入。

2. 复制旧实现存档：
   - 源：`D:/daima/APT-Fusionstep2b3/src/apt_fusion/task_detection/provgrp_behavior_partition.py`
   - 目标：`D:/daima/APT-Fusionstep2b1/src/apt_fusion/task_detection/provgrp_behavior_partition_legacy.py`
   - 要求：完整复制，仅改文件名以明确它是历史实现。**本次不能在任何生产代码中 import 它；不能调用它；不能新增启用它的 YAML 参数。**

旧文件中“30 秒最近事件”的含义是：对根进程发出的每个 `EVENT_FORK`/`EVENT_CLONE`，只在该 fork/clone 之前 30 秒内找时间上最近的一条、同样由根进程发出的非 fork/clone 事件，把那条事件当作该子分支的上下文锚点。它是早期启发式，并非 ProvGRP 论文规定的方法；本次保留代码只是为了以后做可重复对比，绝不能作为默认实现。

### 3.2 必须阅读、按需复制的工具文件

1. `D:/daima/APT-Fusionstep2b3/tools/run_cadets_provgrp_paper_partition.py`
   - 复制到：`D:/daima/APT-Fusionstep2b1/tools/run_cadets_provgrp_paper_partition.py`。
   - 作用：读取已有的基线 Module 1 目录中的 `task_subgraphs.json`、`task_component_diagnostics.json`、`process_segmentation_edges.csv`，重建任务组件，运行论文式切分并单独导出结果。
   - 这是第一次结构实验必须使用的入口。不要先把新模块塞进完整 Module 1/Module 2 流水线，否则无法判断差异来自切分还是来自重新解析/训练。

2. `D:/daima/APT-Fusionstep2b3/tools/analyze_cadets_provgrp_entity_scope.py`
   - 建议复制到 `step2b1/tools/`。
   - 作用：统计满足根进程门槛的候选根，在原始日志中涉及的对象类型和事件类型。它用于确认“只关注进程、文件、网络流”的过滤实际有命中，防止规则写了但日志字段不匹配。

3. `D:/daima/APT-Fusionstep2b3/tools/analyze_cadets_event_object_types.py`
   - 建议复制到 `step2b1/tools/`。
   - 作用：从原始 CDM18 日志统计“真实对象类别 x 原始事件名”。用于后续把 `EVENT_*` 映射到论文的抽象 operation 时做依据。

### 3.3 只参考、不要整文件复制的文件

1. `D:/daima/APT-Fusionstep2b3/src/apt_fusion/task_detection/tapas_native_backend.py`
   - 参考其 `provgrp_paper_partition` 的 import、配置调用、诊断字段透传方式。
   - 不要整文件复制到 `step2b1`。

2. `D:/daima/APT-Fusionstep2b3/src/apt_fusion/config.py`
   - 参考 ProvGRP 的配置字段、YAML 解析和数值校验。
   - 仅把论文式实现所需字段移植到 `step2b1`，不移植旧版 30 秒实现的开关。

3. `D:/daima/APT-Fusionstep2b3/pyproject.toml`
   - 参考 `hdbscan==0.8.40` 依赖项。

## 4. 论文式模块在做什么，移植后应保持的规则

模块对应 ProvGRP 论文第 4.2 节的核心结构：将某个长运行根进程的系统事件抽象为 `<主体进程, 操作, 客体, 时间>`，分别对该根进程的入边、出边进行事件聚类。

当前实现的关键函数均在 `provgrp_paper_partition.py`：

|函数|作用|移植要求|
|---|---|---|
|`_read_cdm18_metadata()`|扫描原始 CDM18 JSON，收集 Subject 归属、FileObject 和 NetFlowObject 描述|原样复制；它是补足任务图边中缺失事件语义的来源|
|`_collect_root_dependencies()`|收集候选根进程的入/出依赖事件，只保留客体为进程、文件、网络流的记录|原样复制；这是当前实验的对象范围|
|`_cluster_events()`|按事件时间、对象实体、操作组成预计算距离矩阵，用 HDBSCAN 做密度聚类|保持 `metric="precomputed"`、`cluster_selection_method="eom"`|
|`_execution_groups()`|将输出事件簇中的 fork/clone 对应到子进程，并为其匹配时间上更早的输入事件簇|保留未匹配的 fork/clone 子进程，不能因无输入簇而丢失分支|
|`apply_provgrp_paper_partition()`|对每个符合门槛的根进程拆分任务组件，根节点复制到每个新组件|输出必须维持 `task_components`、`edge_list`、`task_component_diagnostics` 的既有结构|
|`apply_provgrp_paper_partition_to_edge_list()`|TAPAS 后端和独立脚本的适配入口|后端只调用该函数，不要在后端重复实现切图|

距离项保持为论文结构的三部分：时间相似度权重 `0.5`、实体相似度权重 `0.4`、操作相似度权重 `0.1`。HDBSCAN 参数的默认建议为：

```yaml
task_component_provgrp_min_direct_children: 10
task_component_provgrp_min_cluster_size: 5
task_component_provgrp_min_samples: 2
task_component_provgrp_max_events_per_matrix: 512
```

`512` 是预计算距离矩阵的事件上限，不是 HDBSCAN 的簇大小上限：当候选事件多于 512 时，当前实现按时间硬分块以限制内存。它会保留所有事件，但不同块的事件不参与彼此距离比较。因此它是工程性近似，不能写成论文原始参数。

## 5. 对“严格复现”的准确表述

本次移植的是“ProvGRP 的图构造/入出边分开聚类框架”，不是已经完成了操作层面的逐项严格复现。

论文的抽象操作表包括：

|对象类别|论文列出的操作|
|---|---|
|进程|execute、fork、clone、close|
|文件|read、write、delete|
|网络流|connect、connected session、sock send|

CADETS 原始日志用的是 `EVENT_EXECUTE`、`EVENT_FORK`、`EVENT_READ`、`EVENT_SENDTO` 等 CDM18 事件名，两者并不一一同名。当前 `step2b3` 实现已限制对象范围为“进程、文件、网络流”，但尚未完成“原始事件名 + 实际对象类型 -> 上表抽象 operation”的严格映射。因此：

1. 本次先原样移植，保证与 `step2b3` 当前结构实验可比。
2. 不要在移植过程中擅自扩大或缩小事件集。
3. 后续若做严格 operation 实验，应单独新建配置/实现并先用 `analyze_cadets_event_object_types.py` 验证映射。可作为候选但必须验证的映射包括：`EVENT_EXECUTE -> execute`、`EVENT_FORK -> fork`、`EVENT_CLONE -> clone`、文件 `EVENT_READ -> read`、文件 `EVENT_WRITE -> write`、文件 `EVENT_UNLINK -> delete`、网络 `EVENT_CONNECT -> connect`、网络 `EVENT_ACCEPT -> connected session`、网络 `EVENT_SENDTO/EVENT_SENDMSG -> sock send`。`EVENT_RECVFROM`、`EVENT_OPEN`、`EVENT_MMAP` 等不应未经论证直接塞进论文操作表。

## 6. step2b1 的具体代码改动

### 6.1 增加依赖

在 `D:/daima/APT-Fusionstep2b1/pyproject.toml` 的 `dependencies` 中添加：

```toml
"hdbscan==0.8.40",
```

在云服务器必须使用 `fusion` 环境验证：

```bash
PYTHONPATH=src /root/miniconda3/envs/fusion/bin/python -c "import hdbscan; print(hdbscan.__version__)"
```

若未安装，只在 `fusion` 中安装，不要切换到系统 Python：

```bash
/root/miniconda3/envs/fusion/bin/pip install hdbscan==0.8.40
```

### 6.2 增加配置字段

修改 `D:/daima/APT-Fusionstep2b1/src/apt_fusion/config.py`，在现有 `task_component_*` 配置字段附近增加以下五项，默认均保证功能关闭：

```python
task_component_provgrp_behavior_partition_enabled: bool = False
task_component_provgrp_min_direct_children: int = 10
task_component_provgrp_min_cluster_size: int = 5
task_component_provgrp_min_samples: int = 2
task_component_provgrp_max_events_per_matrix: int = 512
```

必须同步做三件事：

1. 在 `FusionConfig` dataclass 加字段。
2. 在 `load_config()` 的 `FusionConfig(...)` 构造器中用 `_get(...)` 解析 YAML。
3. 在配置校验函数中增加：

```python
if cfg.task_component_provgrp_min_direct_children < 1:
    raise ValueError("task_component_provgrp_min_direct_children must be >= 1")
if cfg.task_component_provgrp_min_cluster_size < 2:
    raise ValueError("task_component_provgrp_min_cluster_size must be >= 2")
if cfg.task_component_provgrp_min_samples < 1:
    raise ValueError("task_component_provgrp_min_samples must be >= 1")
if cfg.task_component_provgrp_max_events_per_matrix < 2:
    raise ValueError("task_component_provgrp_max_events_per_matrix must be >= 2")
```

不要添加旧版 30 秒模块的 `context_window_seconds`、`max_cluster_children`、`balance` 等配置。旧版还未启用，暴露开关只会让后续实验难以追踪。

### 6.3 后端 import 与准确接入位置

在 `D:/daima/APT-Fusionstep2b1/src/apt_fusion/task_detection/tapas_native_backend.py` 的同级相对 import 区添加：

```python
from .provgrp_paper_partition import apply_provgrp_paper_partition_to_edge_list
```

**不要** import `provgrp_behavior_partition_legacy.py`。

在 `_build_tc3_bundle()` 中，基础 `vendor.cut_task(..., return_task_components=True, ...)` 完成后插入论文式切分调用。第一次实验要插在当前根节点时间切分之前，即在以下代码之后、`subject_time_ranges = ...` 之前：

```python
# cadets 分支中：
edge_list = vendor.cut_task(subject_list, return_task_components=True, **task_component_kwargs)
```

插入逻辑应为：

```python
if bool(cfg.task_component_provgrp_behavior_partition_enabled):
    if cfg.host != "cadets":
        raise ValueError(
            "task_component_provgrp_behavior_partition_enabled currently supports cadets only"
        )
    if not isinstance(edge_list, dict) or "task_components" not in edge_list:
        raise ValueError(
            "ProvGRP partition requires cut_task(return_task_components=True); "
            "disable task_tapas_release_legacy_cut_logic"
        )
    edge_list = apply_provgrp_paper_partition_to_edge_list(
        edge_list,
        source_logs=source_logs,
        min_direct_children=int(cfg.task_component_provgrp_min_direct_children),
        min_cluster_size=int(cfg.task_component_provgrp_min_cluster_size),
        min_samples=int(cfg.task_component_provgrp_min_samples),
        max_events_per_matrix=int(cfg.task_component_provgrp_max_events_per_matrix),
    )
```

注意事项：

1. `task_tapas_release_legacy_cut_logic` 必须为 `false`。它会让 CADETS `cut_task()` 走旧返回结构，论文式模块需要字典中的 `task_components`。
2. 第一轮 ProvGRP 实验中，下列 `step2b1` 现有功能全部设为 `false`：
   - `task_component_root_temporal_split_enabled`
   - `task_component_temporal_episode_split_enabled`
   - `task_component_synthetic_root_isolation_enabled`
   - `task_component_synthetic_root_selective_isolation_enabled`
   - `task_component_branch_object_overlap_split_enabled`
3. 原因是这些都属于二次切分。若同时启用，无法判断 GT 图变小或变碎究竟来自 ProvGRP 还是旧规则。
4. 只处理 `cadets`。不要让 TRACE、THEIA、FiveDirections 因为缺少 CDM18 字段或语义映射而悄悄走半成品逻辑。

### 6.4 保留诊断元数据，避免切分结果不可解释

`provgrp_paper_partition.py` 会给新组件写入以下字段。`step2b1` 目前的三个字段白名单都要追加这些键，且仅复制存在的键：

```python
[
    "provgrp_paper_partition_applied",
    "provgrp_paper_parent_task_root",
    "provgrp_paper_partition_index",
    "provgrp_paper_partition_count",
    "provgrp_paper_incoming_cluster_id",
    "provgrp_paper_outgoing_cluster_id",
    "provgrp_paper_incoming_event_count",
    "provgrp_paper_outgoing_event_count",
    "provgrp_paper_member_child_roots",
    "provgrp_paper_member_child_count",
    "provgrp_paper_original_root_child_count",
]
```

需要改的三处都是 `D:/daima/APT-Fusionstep2b1/src/apt_fusion/task_detection/tapas_native_backend.py`：

1. `_decompose_tc3_metadata()`，约第 668 行开始的元数据键白名单。
2. `_build_task_component_diagnostics_from_components()`，约第 1002 行开始的诊断键白名单。
3. `_save_module1_exports()`，约第 3072 行开始的导出键白名单。

三处都漏不得：只改第一处会导致模型内存中的元数据有值但 JSON 没有；只改导出处又会因为前面丢失字段而导出空值。

在 Module 1 summary 中也额外记录：

```python
"task_component_provgrp_behavior_partition_enabled": bool(
    cfg.task_component_provgrp_behavior_partition_enabled
),
"provgrp_paper_partition_summary": copy.deepcopy(
    bundle.get("selected_edge_list", {}).get("provgrp_paper_partition_summary", {})
),
```

前提是 `selected_edge_list` 仍是字典；若不是字典，导出空字典。不能因为写 summary 破坏旧的 list 兼容路径。

### 6.5 边方向与组件结构的强制检查

ProvGRP 模块假定组件边的语义是“父进程 -> 子进程”。这是因为它需要从根节点的输出事件中找 fork/clone 所产生的直接子进程。

移植前必须用一个 CADETS 基线 Module 1 产物检查：

1. `process_segmentation_edges.csv` 中必须有 `parent_process_id`、`child_process_id`、`relation_type`、`use_for_segmentation`。
2. `task_components` 中每个组件至少有 `task_root`、`nodes`、`edges`、`boundary_nodes`。
3. 对抽样根节点，`task_root -> child` 的边数必须与诊断中的 `task_root_total_children` 的定义一致。若发现边反向，必须先修适配层，不能继续跑 HDBSCAN。
4. 每次拆分后，原根节点必须出现在每个派生组件；每个原直接子分支必须恰好属于一个派生组件，不能丢失、不能重复。

## 7. 独立结构实验的执行顺序

### 7.1 先做静态与导入检查

在 `step2b1` 根目录执行：

```bash
PYTHONPATH=src /root/miniconda3/envs/fusion/bin/python -m py_compile \
  src/apt_fusion/config.py \
  src/apt_fusion/task_detection/tapas_native_backend.py \
  src/apt_fusion/task_detection/provgrp_paper_partition.py \
  src/apt_fusion/task_detection/provgrp_behavior_partition_legacy.py \
  tools/run_cadets_provgrp_paper_partition.py
```

随后运行：

```bash
PYTHONPATH=src /root/miniconda3/envs/fusion/bin/python -c \
  "from apt_fusion.task_detection.provgrp_paper_partition import apply_provgrp_paper_partition_to_edge_list; print('ok')"
```

旧版模块可以通过 `py_compile`，但本检查不能因 import 它而改变“暂不启用”的约束。

### 7.2 保真空跑

先用一个不可能触发的阈值运行独立脚本，例如：

```bash
PYTHONPATH=src /root/miniconda3/envs/fusion/bin/python \
  tools/run_cadets_provgrp_paper_partition.py \
  --baseline-module1 <CADETS_基础_module1目录> \
  --source-logs <CADETS_原始日志目录> \
  --output-dir <输出目录>/provgrp_smoke_noop \
  --min-direct-children 100000 \
  --min-cluster-size 5 \
  --min-samples 2 \
  --max-events-per-matrix 512
```

预期：任务数、每个任务的节点集合、GT 命中总节点数与基线一致；summary 显示没有 eligible/refined root。若不一致，说明重建组件或导出逻辑有 bug，不能进入真实 HDBSCAN 实验。

### 7.3 第一轮真实实验

固定使用：`min_direct_children=10`、`min_cluster_size=5`、`min_samples=2`、`max_events_per_matrix=512`。

```bash
PYTHONPATH=src /root/miniconda3/envs/fusion/bin/python \
  tools/run_cadets_provgrp_paper_partition.py \
  --baseline-module1 <CADETS_基础_module1目录> \
  --source-logs <CADETS_原始日志目录> \
  --output-dir <输出目录>/provgrp_paper_m5s2_e512 \
  --min-direct-children 10 \
  --min-cluster-size 5 \
  --min-samples 2 \
  --max-events-per-matrix 512
```

只比较结构指标，不跑 Module 0、Module 2、数据增强或模型训练。必须输出并检查：任务总数、GT 命中任务数、GT 命中任务平均/中位/最大节点数、`>500` 和 `>1000` 大图数、每个切分根的子分支数分布、GT 节点覆盖数、重复/遗漏分支数。

首次不要运行 `max_events_per_matrix=1024`。历史结果显示它在 CADETS 上明显变差，应在 512 稳定且确认过滤语义后才作为消融对比。

### 7.4 再接入完整 Module 1

只有独立脚本满足以下条件，才在 `tapas_native_backend.py` 打开配置做端到端 Module 1：

1. 空跑完全保真。
2. 派生组件没有丢失或重复子分支。
3. GT 过程节点覆盖没有下降。
4. GT 命中任务规模没有大量坍缩到 1--2 个进程节点。
5. `task_component_diagnostics.json` 可以看到完整 ProvGRP 字段。

端到端配置必须新建独立 YAML，不要修改基线 YAML。其关键值为：

```yaml
host: cadets
task_tapas_release_legacy_cut_logic: false
task_component_child_threshold: 2
task_component_provgrp_behavior_partition_enabled: true
task_component_provgrp_min_direct_children: 10
task_component_provgrp_min_cluster_size: 5
task_component_provgrp_min_samples: 2
task_component_provgrp_max_events_per_matrix: 512

# 第一轮隔离实验：所有现有二次切分关闭。
task_component_root_temporal_split_enabled: false
task_component_temporal_episode_split_enabled: false
task_component_synthetic_root_isolation_enabled: false
task_component_synthetic_root_selective_isolation_enabled: false
task_component_branch_object_overlap_split_enabled: false
```

## 8. 前几次 CADETS 结构实验结果

以下均为 `APT-Fusionstep2b3` 上的 CADETS Module 1/独立结构实验，评价的是任务图规模与 GT 覆盖，不是恶意检测准确率。GT 统计口径为“含 GT 进程节点的任务图”；所有记录均覆盖 CADETS 的 16 个 GT 进程节点。

|方案|任务图总数|GT 命中任务图数|GT 命中任务图平均节点数|中位数|最大值|说明|
|---|---:|---:|---:|---:|---:|---|
|基础 fanout，`child_threshold=2`|5,247|5|973.00|1,166|1,922|未做 ProvGRP；5 张 GT 图大小为 150、1,166、1,922、1,535、92|
|旧版 30 秒启发式，`m5/s2`，输出上限 64|8,897|9|39.33|未单列|109|旧版且含非论文的均衡/上限处理；结构较紧，但不能作为论文式主线|
|旧版 30 秒启发式，`m5/s2`，输出上限 16|17,545|10|15.10|未单列|29|图更小，但高收益主要来自硬上限，不应误解为 HDBSCAN 自然结果|
|旧版 30 秒启发式，关闭均衡拆分|7,916|9|17.78|未单列|29|仍有 52 个子分区超过 500 个孩子、4 个超过 1,000，说明原始大簇仍存在|
|论文式入/出边 HDBSCAN，`m5/s2/e512`|7,161|9|89.00|46|363|1,987 个派生分区；无超过 1,000 的 GT 大图，但有大量单例/双例分区|
|论文式入/出边 HDBSCAN，`m5/s2/e1024`|6,409|7|179.14|76|777|跨更大时间块后簇变粗，仍出现 3 个超过 1,000 的大图，效果弱于 e512|

补充：`e512` 的派生子分支数统计为最小 1、四分位数 1、中位数 2、上四分位数 33.5、最大 486；单例 973 个，`<=2` 的分区 998 个。这说明当前论文式实现虽然能削弱超大图，但过度碎片化问题仍未解决。

重要实验边界：上表中论文式 `e512/e1024` 实验发生在“只看进程、文件、网络流”对象范围过滤加入代码之前。因此它们不能证明对象范围过滤已经带来收益，只能作为移植后回归对照。当前 `step2b3` 代码已加入对象范围过滤，但尚未在这个最终版本上重跑完整结构统计。

## 9. 旧版 30 秒实现为什么只存档、不启用

旧版实现在历史实验中把一个 fork/clone 对应的行为上下文压缩为“前 30 秒、时间最近的一条非 fork/clone 事件”。这会带来三个风险：

1. 长运行服务的高频背景事件很容易成为最近事件，未必代表真正触发该子进程的因果行为。
2. 30 秒是工程启发式，不来自 ProvGRP 论文，也没有在 CADETS、TRACE、THEIA 上分别验证。
3. 历史上好的大小控制很大程度来自“最小组并入最近时间组”和“按 16/64 个孩子强制均衡拆分”，这些是额外规则，不是 HDBSCAN 的自然聚类结果。

因此，本次只保留 `provgrp_behavior_partition_legacy.py`，并在文件头加一条简短注释：

```python
# Historical 30-second heuristic kept for ablation only. Do not import or enable in production.
```

该注释不改变算法，也能防止后续窗口误把它当作当前主线。

## 10. 验收清单

在交付前逐项确认：

- [ ] `provgrp_paper_partition.py` 已完整复制到 `step2b1`。
- [ ] 旧文件已复制为 `provgrp_behavior_partition_legacy.py`，没有任何 import、调用或 YAML 开关。
- [ ] `hdbscan==0.8.40` 已写入 `pyproject.toml`，并在云端 `fusion` 环境可导入。
- [ ] `config.py` 的 dataclass、YAML 解析、校验均有五个论文式配置字段。
- [ ] 后端调用位置在基础 `cut_task(... return_task_components=True)` 后，且第一轮在其他二次切分前执行。
- [ ] 开启 ProvGRP 时强制 `host == cadets`、强制 `edge_list` 为含 `task_components` 的字典、拒绝 legacy cut 返回结构。
- [ ] 三处诊断白名单均写入 11 个 `provgrp_paper_*` 字段。
- [ ] 新建 `tools/` 并能独立完成空跑、真实 e512 结构实验。
- [ ] 空跑与基线的任务节点集合、GT 覆盖完全一致。
- [ ] 真实运行后没有分支丢失、重复，也没有未说明的 1--2 节点大量坍缩。
- [ ] 结果目录、YAML、命令行和 git commit 中明确标注 `provgrp_paper_m5s2_e512`，不覆盖基线产物。

完成以上验收后再决定是否进入两条后续路线之一：一是改进操作映射以更严格对齐 ProvGRP；二是在保持对象范围和因果完整性的前提下解决单例/双例过多问题。不要先把旧 30 秒启发式重新打开。
