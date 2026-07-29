# 基于 DepComm 社区划分思想改进当前任务图分割的实施方案

本文档以 `D:\daima\APT-Fusionstep2b1` 当前代码为基线，目标是在不直接照搬 DepComm 全部后处理流程的前提下，重点借鉴它的“进程中心社区划分”思想，改进我们当前的任务图分割策略。

这份方案不是泛泛而谈，而是基于以下两部分代码对照后写出的可施工方案：

- 当前项目的任务图分割代码：
  - `D:\daima\APT-Fusionstep2b1\vendor\tapas\darpa.py`
  - `D:\daima\APT-Fusionstep2b1\src\apt_fusion\task_detection\tapas_native_backend.py`
- DepComm 开源实现的已反编译核心模块：
  - `D:\daima\Start_extracted\out00-PYZ.pyz_extracted\communities\Specific2.pyc`
  - `D:\daima\Start_extracted\out00-PYZ.pyz_extracted\Community.pyc`
  - `D:\daima\Start_extracted\out00-PYZ.pyz_extracted\utils\Cmeans.pyc`
  - `D:\daima\Start_extracted\out00-PYZ.pyz_extracted\utils\ExportResult.pyc`
  - `D:\daima\Start_extracted\out00-PYZ.pyz_extracted\Rwgraph.pyc`
  - `D:\daima\Start_extracted\out00-PYZ.pyz_extracted\Noleafgraph.pyc`
  - `D:\daima\Start_extracted\out00-PYZ.pyz_extracted\FileNodeSplit.pyc`

## 1. 先说结论

当前项目的任务图分割，本质上还是“进程树切分”：

- 只看父进程到子进程的关系。
- 只看一个进程有多少个子进程。
- 不看兄弟进程之间是否通过文件、网络、执行对象发生协作。
- 不看资源节点是否把本来应该属于同一攻击动作的多个分支重新连在一起。

而 DepComm 的核心不是“按子进程数切”，而是：

- 先承认社区的主体是进程。
- 但是否属于同一个社区，不能只看父子关系，还要看兄弟进程是否通过资源节点存在数据依赖。
- 社区的典型形态是：
  - 一个主控进程。
  - 一组协同的子进程或后代进程。
  - 这些进程共同访问的一批文件、网络资源。

所以，对我们最值得借鉴的，不是 DepComm 后面的压缩和 InfoPath 总结，而是前面的三件事：

1. 用资源依赖修正单纯的父子树切分。
2. 在高扇出根节点处，把“有协作关系的兄弟分支”重新聚成社区。
3. 过滤掉会制造假连接的普通系统资源、只读资源和高频公共资源。

## 2. 当前代码到底是怎么切任务图的

### 2.1 当前主入口

任务图切分的主入口在：

- `D:\daima\APT-Fusionstep2b1\src\apt_fusion\task_detection\tapas_native_backend.py`

其中：

- `parser_cadets(...)` / `parser_trace(...)` 负责解析日志。
- `vendor.cut_task(subject_list, return_task_components=True, ...)` 负责按进程树构造 `task_components`。
- `vendor.decompose(...)` 再把每个 `task_component` 变成 GNN 看到的一个任务图。

### 2.2 当前切分的核心函数

在 `D:\daima\APT-Fusionstep2b1\vendor\tapas\darpa.py` 中：

- `_resolve_segmented_nodes(...)`
- `_build_task_components(...)`
- `_cut_task(...)`

当前逻辑是：

1. 先根据 `subject_list` 构出进程父子表：
   - `padict`: 父进程 -> 子进程列表
   - `chdict`: 子进程 -> 父进程
2. 如果某个进程的有效子进程数大于阈值 `child_threshold`，就把它标成 `segmented`。
3. 再从根进程和这些 `segmented` 进程出发做 DFS，生成组件。
4. DFS 碰到新的 `segmented` 子节点时停止向下深入，把这个子节点记成边界节点。

### 2.3 当前切法的几个关键问题

#### 问题 1：它本质上只使用了“进程树”

当前切分阶段根本没有使用：

- 文件对象
- 网络对象
- 进程与对象之间的读写执行关系
- 兄弟分支之间通过资源产生的协作关系

这些信息现在只用于节点向量或后续推理，没有真正进入“分割决策”。

#### 问题 2：高扇出根节点并没有被真正按社区拆开

这一点很关键。

当前 `_build_task_components(...)` 的逻辑不是“一个高扇出节点拆成多个孩子簇”，而是：

- 把高扇出节点自己也当作一个 `task_root`
- 然后从它继续向下走
- 只有遇到它下面再次被标成 `segmented` 的节点时才停止

这意味着：

- 如果最上层根进程本身子进程很多，但这些子进程自己没有再次超阈值，
- 那么这个根组件仍然可能把大量本不该放在一起的兄弟分支全部装进一个大图里。

也就是说，当前“fanout 分割”对顶层大根节点的效果其实很弱。

#### 问题 3：兄弟进程之间的协作关系完全丢了

例如：

- 父进程 `P0` 派生 `P1`、`P2`、`P3`
- `P1` 下载或写入一个文件 `F`
- `P2` 再去执行 `F`
- `P3` 再把结果发到外网

这种场景里：

- 进程树上 `P1/P2/P3` 只是兄弟
- 但攻击语义上它们明显属于同一动作链

当前切分看不到这层关系。

#### 问题 4：公共系统资源会误导“是否相关”

如果后面直接粗暴地引入“共享对象就算相关”，又会遇到另一类问题：

- 多个正常服务进程都读相同的系统库
- 多个进程都访问相同配置文件
- 高频公共日志文件把大量无关分支连在一起

DepComm 之所以有效，不是因为它简单地用“共享对象”聚类，而是它先做了资源预处理。

## 3. DepComm 真正做了什么

这里不只看论文，也看了代码实现。

## 3.1 DepComm 的社区定义

根据论文和 `groundtruth/README.md`，DepComm 的社区真值定义可以概括成一句话：

同一个父进程创建的一组兄弟进程，如果它们之间通过资源节点存在数据依赖，那么这些相关兄弟进程应该属于同一个社区；这个父进程就是该社区的主控进程。

这是它最值得借鉴的地方，因为这正好击中我们当前分割的薄弱点。

### 3.2 DepComm 的输入图不是纯进程树，而是依赖图

从反编译后的 `ImportGraph.py`、`Parser.py` 可以看出，DepComm 建的是多类型依赖图：

- 进程节点
- 文件节点
- 网络节点
- 进程到进程边
- 进程到文件边
- 文件到进程边
- 进程到网络边
- 网络到进程边

也就是说，社区划分一开始就不是只看进程父子边。

### 3.3 DepComm 在划分前做了三类预处理

#### 预处理 A：去掉只读文件

`Rwgraph.py` 的逻辑是：

- 如果一个文件节点入度为 0，就删掉。

在它的边定义里，这通常对应“文件只被读，没有被写入或生成”。

这些对象大多是：

- 系统库
- 配置文件
- 普通输入文件

它们对识别“哪些进程在协同完成一个任务”帮助不大，反而容易造成噪声。

#### 预处理 B：迭代去掉叶子资源节点

`Noleafgraph.py` 的逻辑是：

- 反复删除只有 1 个邻居的非进程节点。

意思是：

- 只和一个进程相连的资源节点，对“把多个进程聚成社区”没有帮助。
- 它更像这个进程自己的局部细节，不应该主导社区划分。

#### 预处理 C：对热点文件做时间相关拆分

`FileNodeSplit.py` 的逻辑是：

- 如果一个文件节点连接了太多进出边，
- 就根据输入输出事件的时间关系，把这个文件拆成多个伪文件副本，
- 让不同时间段、不同子任务对应的访问不再全都挤在同一个文件节点上。

这是为了解决：

- 一个高频公共文件把很多本来无关的分支错误黏在一起。

### 3.4 DepComm 的“亲密进程”识别规则

`Specific2.py` 是最核心的社区检测逻辑。

它先给每个进程构造两类上下文：

- `parent / parents / processlink`
  - 表示该进程在进程谱系树里的位置。
  - 特别关注“最近的分叉祖先”，也就是最近的高扇出祖先。
- `R(process)`
  - 表示该进程访问过的非进程资源集合。

然后它做层次化随机游走，重点偏向以下几类转移：

1. 在同一个父系分支内部行走。
2. 在共享资源的兄弟进程之间行走。
3. 从资源节点回到进程节点时，优先回到与前一个进程拥有共同分叉祖先的进程。

从代码看，几个特别关键的权重思想是：

- `getweight1(...)`：
  - 当当前进程是一个高扇出父节点时，
  - 如果某个兄弟进程和前一个进程共享资源，就给它高权重。
- `getweight10(...)`：
  - 当游走经过资源节点时，
  - 如果两个进程的最近分叉祖先相同，就倾向认为它们可能属于同一社区。

所以，DepComm 不是“看到共享文件就聚”，而是：

- 共享资源
- 同一父系或同一分叉祖先
- 过程上的层次化上下文

三者一起决定社区。

### 3.5 DepComm 先聚进程，再把资源挂回社区

`Community.py` + `utils/Cmeans.py` + `utils/ExportResult.py` 表明：

1. 先对进程做随机游走和向量化。
2. 用模糊 C 均值聚类得到进程到社区的归属度。
3. 再把资源节点根据相邻进程的社区归属挂回去。
4. 如果某个资源和多个社区都相连，就复制资源副本，分别放进多个社区。

这里对我们最有用的启发是：

- 社区主体是进程。
- 资源是决定进程是否协作的证据。
- 资源不一定要直接成为 module1 的训练节点，但它必须参与“如何切分”。

## 4. 我们应该借什么，不应该借什么

### 4.1 这次应该借的

这次最值得借的是：

1. 基于资源依赖修正父子树切分。
2. 在高扇出父节点处识别“协作的兄弟分支”。
3. 引入资源预处理，避免公共资源制造假社区。
4. 对超大组件再做局部社区细化，而不是全局硬切。

### 4.2 这次不建议直接照搬的

暂时不建议直接照搬：

1. DepComm 的社区压缩。
2. DepComm 的 InfoPath 总结。
3. 把 module1 任务图直接改成进程+文件+网络的异构图去训练。
4. 一上来就在全量数据上做完整随机游走聚类。

原因很简单：

- 我们当前 module1 的训练输入是“仅进程节点”的任务图。
- 如果一步把结构换太大，很难判断收益来自哪一层。
- 这次最优先要解决的是“切得不对”，不是“摘要展示得不够漂亮”。

## 5. 建议的整体改造思路

建议采用“先小改可验证，再逐步替换核心切分逻辑”的路线。

分成四步：

1. 先补分割 sidecar 和诊断，不改最终切分结果。
2. 再在当前 `fanout` 结果后面，加一个 DepComm 风格的“兄弟分支社区细化”后处理。
3. 如果有效，再把这个社区细化前移，替换当前 `_build_task_components(...)` 的核心逻辑。
4. 最后只对仍然过大的组件，引入 DepComm 风格的局部随机游走聚类。

这样做的优点是：

- 每一步都能单独跑实验。
- 每一步都知道收益来自哪里。
- 一旦某一步负提升，可以精确回退，不会把整条流水线一起打乱。

## 6. Step 0：先补分割 sidecar 和诊断，不改变切分结果

这一步的目标是：

- 给后续社区细化准备足够的过程数据。
- 但这一步本身不改变 `task_components`。

### 6.1 要改哪些文件

- `D:\daima\APT-Fusionstep2b1\vendor\tapas\darpa.py`
- `D:\daima\APT-Fusionstep2b1\src\apt_fusion\task_detection\tapas_native_backend.py`
- `D:\daima\APT-Fusionstep2b1\src\apt_fusion\config.py`

### 6.2 要新增什么 sidecar

建议统一叫：

- `graph_partition_sidecar`

建议包含以下字段：

```python
{
    "process_to_object_events": {
        process_id: {
            object_id: [event_type_id, ...]
        }
    },
    "object_to_processes": {
        object_id: [process_id, ...]
    },
    "object_meta": {
        object_id: {
            "object_type": "file" | "net",
            "path": "...",              # 文件对象时尽量保留
            "local_ip": "...",          # 网络对象时可选
            "remote_ip": "...",         # 网络对象时可选
            "local_port": "...",
            "remote_port": "..."
        }
    },
    "process_parent": {
        child_process_id: parent_process_id
    },
    "parent_children": {
        parent_process_id: [child_process_id, ...]
    }
}
```

### 6.3 CADets / TRACE 怎么拿 sidecar

这一步尽量不额外回查原始日志，直接利用已经解析出的信息：

- `parser_cadets(...)`
- `parser_trace(...)`

当前它们已经有：

- `subject_list`
- `object_list`
- `event_count`

所以这一步只需要把聚合事件重新整理成 sidecar 即可。

关键点：

- `event_count` 目前是 `(event_type_id, subject_id, object_id) -> count`
- 虽然没有单条事件时间，但已经足够支持第一阶段的“共享对象协作”分析

### 6.4 Theia 怎么拿 sidecar

Theia 的 `filters(...)` 现在内部已经有：

- `events_seen`
- 对象类型
- 主体映射

所以也要在 `filters(...)` 里构造同样的 sidecar，并放进返回字典里。

### 6.5 这一步要额外导出哪些诊断

建议在 module1 产物目录下新增：

- `partition_sidecar_summary.json`
- `partition_overlap_diagnostics.json`

其中 `partition_overlap_diagnostics.json` 至少记录：

- 每个任务组件根节点的直接孩子数
- 每个孩子分支访问了多少对象
- 孩子分支之间共享对象数
- 共享对象里有多少是系统路径对象
- 如果按“共享对象连通分量”切，会得到几个孩子簇

这一步不改变 `task_components`，只是把“是否值得做社区细化”先量化出来。

## 7. Step 1：在现有 fanout 结果之后，加一层“兄弟分支社区细化”

这是第一步真正改变行为的地方。

注意，这一步不要直接重写 `vendor/tapas/darpa.py` 的主切分逻辑，而是在现有 `task_components` 产出后做后处理。这样改动更小，也更容易做对比实验。

### 7.1 设计目标

目标不是“更激进地切碎”，而是：

- 在一个高扇出根节点下面，
- 把本来应该属于同一攻击动作的兄弟分支重新聚成一个社区，
- 把互不相关的兄弟分支拆开，
- 从而替代当前“整个根组件太大、但又没有按协作关系拆开”的问题。

### 7.2 要改哪些文件

- `D:\daima\APT-Fusionstep2b1\src\apt_fusion\task_detection\tapas_native_backend.py`
- 新增一个独立帮助文件，建议：
  - `D:\daima\APT-Fusionstep2b1\src\apt_fusion\task_detection\depcomm_partition_refine.py`
- `D:\daima\APT-Fusionstep2b1\src\apt_fusion\config.py`

### 7.3 这一步的输入

输入就是当前已有的：

- `edge_list["task_components"]`
- `edge_list["task_component_diagnostics"]`
- `graph_partition_sidecar`

### 7.4 先定义几个中文概念

#### 主控进程

就是一个候选任务组件的 `task_root`。

在 DepComm 语境里，它相当于一个社区的 master process。

#### 孩子分支

指主控进程的每一个直接子进程及其在当前组件里的后代集合。

记作：

- `branch(child_i)`

#### 协作证据

指两个孩子分支不是“只是同父”，而是还存在资源依赖关系。

第一阶段只看以下几种简单而稳定的证据：

1. 两个分支共享同一个非公共文件对象。
2. 一个分支写入或创建某对象，另一个分支执行或读取同对象。
3. 两个分支共享同一个非公共网络对象。
4. 两个分支共享的对象数量达到阈值。

### 7.5 这一步的具体算法

对每个候选组件执行：

1. 找到 `task_root` 的直接孩子。
2. 为每个孩子构造一个分支节点。
3. 统计每个分支访问过的对象集合，以及对象上的事件类型集合。
4. 在这些孩子分支之间建立“分支协作图”。
5. 对这个分支协作图取连通分量。
6. 每个连通分量生成一个新的细化组件。

### 7.6 分支协作图怎么建

两个孩子分支 `A` 和 `B` 之间连边，当且仅当满足以下任一条件：

#### 规则 1：共享强对象

如果它们共享至少一个对象，且这个对象满足以下任一条件：

- 在任一分支上出现 `EXECUTE`
- 在任一分支上出现 `WRITE`
- 在任一分支上出现 `CREATE_OBJECT`
- 在任一分支上出现 `SENDTO` / `SENDMSG` / `CONNECT`

则 `A-B` 连边。

动机：

- 这类对象更像“落地文件、执行载体、外发通道”，比普通读库文件更能代表协作。

#### 规则 2：写后读 / 写后执行

如果：

- 分支 `A` 在对象 `O` 上有 `WRITE` 或 `CREATE_OBJECT`
- 分支 `B` 在同对象 `O` 上有 `READ` 或 `EXECUTE`

或者反过来，

则 `A-B` 连边。

动机：

- 这是最接近攻击阶段里“一个分支准备载荷，另一个分支消费载荷”的模式。

#### 规则 3：共享普通对象达到阈值

如果两个分支共享的过滤后对象数 `>= 2`，则 `A-B` 连边。

动机：

- 单个普通对象不够可靠，但多个普通对象一起共享，通常说明这两个分支确实有协作。

#### 规则 4：共享网络端点且存在主动通信事件

如果两个分支共享同一个网络对象，且至少一侧存在：

- `CONNECT`
- `SENDTO`
- `SENDMSG`
- `RECVFROM`
- `RECVMSG`

则 `A-B` 连边。

### 7.7 哪些对象一开始就不能参与连边

第一版就必须过滤掉这些对象，不然误连会很多：

1. 进程度数太高的公共对象
   - 例如被超过 `K` 个进程访问
2. 系统路径对象
   - 路径前缀命中 `/lib/`、`/usr/lib/`、`/usr/share/`、`/etc/`
3. 仅有普通读取、没有写入/执行/网络语义的对象
4. 仅被一个分支访问的对象

这里的 `K` 建议第一版先设成 8 或 10，做成配置项。

### 7.8 细化组件如何生成

设主控进程为 `R`，孩子分支社区为 `C1, C2, ..., Cn`。

则每个新组件的节点集为：

- `R`
- `Ci` 内所有孩子分支包含的进程节点

边集只保留这些节点之间原有的父子边。

输出组件时建议新增字段：

```python
{
    "community_refine_applied": True,
    "community_refine_root": R,
    "community_cluster_index": i,
    "community_cluster_count": n,
    "community_member_child_roots": [...],
    "community_shared_object_ids": [...],
    "community_shared_object_count": m
}
```

### 7.9 这一步的关键决策

#### 决策 A：要不要保留原始大组件

建议：

- 默认不保留被成功细化的大组件。
- 只保留细化后的多个社区组件。

原因：

- 如果原始大组件继续保留，它往往会重新成为“大而杂”的高分误报候选。
- 我们这一步的目的就是替换它，而不是在它旁边再附加几个小图。

#### 决策 B：主控进程是否允许复制

建议允许。

也就是：

- 同一个 `task_root` 可以出现在多个细化组件里。

原因：

- 这和 DepComm 对重叠节点、尤其是社区边界节点的处理思想一致。
- 主控进程本身就是多个兄弟分支的公共祖先，不复制它反而会丢掉父系语义。

#### 决策 C：普通后代进程是否允许跨组件复制

第一版不允许。

也就是：

- 只有 `task_root` 允许跨多个细化组件重复出现。
- 其他普通进程尽量只属于一个细化组件。

这样更稳，也更符合当前 module1 的训练输入习惯。

### 7.10 这一步为什么有效

它直接借了 DepComm 最关键的那条社区真值定义：

- 同父兄弟如果通过资源存在依赖，就应该被放到一起。

但它又没有一上来就把整个 module1 改成异构图聚类，所以风险可控。

## 8. Step 2：把社区细化前移，替换当前 `_build_task_components(...)` 的核心逻辑

如果 Step 1 有明显收益，下一步就不应该再满足于“后处理修补”，而应把社区细化前移到真正的组件构造阶段。

### 8.1 这一步要解决 Step 1 的什么不足

Step 1 的不足是：

- 它是在现有组件生成后再细化。
- 如果原始组件在前一层 DFS 时已经因为边界节点而截断，
- 那么它看到的只是“局部分支”，不是完整子树。

因此 Step 2 要做的是：

- 不再先生成粗糙 `task_components` 再修。
- 而是在构造组件时，直接按“孩子分支社区”生成。

### 8.2 要改哪些文件

- `D:\daima\APT-Fusionstep2b1\vendor\tapas\darpa.py`
- `D:\daima\APT-Fusionstep2b1\src\apt_fusion\task_detection\tapas_native_backend.py`
- `D:\daima\APT-Fusionstep2b1\src\apt_fusion\config.py`

### 8.3 具体做法

保留 `_resolve_segmented_nodes(...)` 作为“候选高扇出根节点发现器”，但重写组件生成逻辑：

- 新增 `_build_task_components_depcomm_hybrid(...)`

建议逻辑：

1. 先找到根进程和高扇出候选进程。
2. 对每个候选根 `R`：
   - 枚举其直接孩子 `c1...ck`
   - 每个孩子对应完整的后代子树
   - 基于 sidecar 构建孩子分支协作图
   - 对孩子分支求连通分量
   - 每个连通分量输出一个组件
3. 如果某个候选根没有形成有效社区结构，再回退到旧规则。

### 8.4 Step 2 的核心变化

旧逻辑：

- “遇到高扇出节点就当一个边界，再做 DFS”

新逻辑：

- “遇到高扇出节点时，先问它的孩子分支之间有没有协作社区，再按社区来出组件”

这才是真正从“扇出切分”走向“进程中心社区切分”。

## 9. Step 3：引入 DepComm 风格的资源预处理

如果 Step 1/Step 2 引入共享对象后误连还比较多，就继续做这一步。

这一阶段借鉴的是：

- `Rwgraph.py`
- `Noleafgraph.py`
- `FileNodeSplit.py`

但我们不需要原样复制图结构，只需要把它们转成“对象是否参与社区连边”的规则。

### 9.1 规则 A：去掉只读普通对象

如果某对象满足：

- 从未出现 `WRITE`
- 从未出现 `CREATE_OBJECT`
- 从未出现 `EXECUTE`
- 从未出现外向通信语义

并且只是普通文件读取，

则默认不参与孩子分支连边。

### 9.2 规则 B：去掉单分支叶子对象

如果某对象在当前候选根下只被一个孩子分支访问，

则不参与“兄弟是否协作”的判定。

### 9.3 规则 C：热点对象黑名单

如果某对象被过多孩子分支共享，优先视为公共资源，默认不参与连边。

建议阈值做成配置项：

- `task_component_common_object_degree_threshold`

### 9.4 规则 D：热点对象时间拆分

这一步只有在前面几步都稳定后再做。

需要补单条事件时间 sidecar，然后对热点文件对象按时间簇拆成多个伪对象。

这一步相当于在我们这里借鉴 `FileNodeSplit.py` 的思想：

- 不让一个高频公共文件把不同时段、不同子任务误粘在一起。

## 10. Step 4：只对仍然超大的组件，加入 DepComm 风格的局部随机游走社区细化

这一步是高级版，不要提前做。

只有在以下情况同时满足时才做：

1. Step 1 和 Step 2 已经把明显的大根节点问题处理掉了。
2. 仍然存在很大的组件，且简单共享对象规则无法分清内部结构。

### 10.1 这一步借鉴什么

主要借 `Specific2.py`：

- 利用父系分叉结构
- 利用共享资源集合 `R(process)`
- 利用层次化随机游走去学习“亲密进程”的表示

### 10.2 但第一版不要完整复刻 DepComm 聚类

因为我们当前 module1 有两个约束：

1. 训练图希望尽量是稳定的、近似不重叠的进程集合。
2. 现在的主任务还是“图分割给 module1 用”，不是“生成完整社区摘要”。

所以建议只在超大组件里做“局部 walk refinement”：

1. 构建局部进程-资源二部图。
2. 只对进程做 walk 序列。
3. 只在这个局部组件内部学习嵌入和聚类。
4. 聚类结果默认硬分配为单社区。
5. 次高归属度仅写入 sidecar，不直接重复普通进程节点。

### 10.3 可以先实现的简化版本

先不做 8 套完整 scheme 的严格复刻，而是先做这几个偏置：

1. 同父或同最近分叉祖先优先。
2. 共享强对象的兄弟分支优先。
3. 从资源回到进程时，优先回到和前一个进程共享最近分叉祖先的进程。

这已经抓住了 DepComm 最关键的结构偏置。

## 11. 建议新增的配置项

在 `D:\daima\APT-Fusionstep2b1\src\apt_fusion\config.py` 中新增：

```python
task_component_depcomm_refine_enabled: bool = False
task_component_depcomm_refine_stage: str = "none"  # none / post / native / walk
task_component_common_object_degree_threshold: int = 8
task_component_shared_object_min_count: int = 2
task_component_depcomm_keep_parent_component: bool = False
task_component_depcomm_allow_root_duplication: bool = True
task_component_depcomm_ignore_system_paths: bool = True
task_component_depcomm_ignore_read_only_objects: bool = True
task_component_depcomm_enable_hot_object_split: bool = False
task_component_depcomm_walk_refine_min_processes: int = 25
```

建议阶段含义如下：

- `none`
  - 不启用
- `post`
  - 启用 Step 1，后处理细化
- `native`
  - 启用 Step 2，原生社区构造
- `walk`
  - 在 `native` 基础上，再启用 Step 4 的局部随机游走细化

## 12. 建议的实验顺序

必须按下面顺序来，不要跳步。

### 实验 1：只做 Step 0

目标：

- 先确认当前大根节点下面到底有多少“共享资源的兄弟分支”。

看这些统计：

- 平均每个高扇出根节点的孩子数
- 孩子分支间共享对象数分布
- 被过滤前后共享对象数变化
- 如果按共享对象连通分量切，会新增多少组件

### 实验 2：启用 Step 1

对比：

- baseline `fanout`
- `fanout + depcomm post refine`

重点看：

- 平均任务图大小
- 超大任务图数量
- 恶意任务图召回
- 误报任务图数量
- 恶意 1-hop 邻域节点是否更集中到同一任务图中

### 实验 3：Step 1 稳定后，再做 Step 2

对比：

- Step 1 后处理版
- Step 2 原生构造版

重点看：

- 顶层大根组件是否真正消失
- 是否减少重复的大杂烩组件
- 是否让恶意任务图规模更接近真实攻击活动范围

### 实验 4：只有前面两步都稳定后，再做 Step 3/Step 4

这一阶段主要看：

- 是否进一步减少由公共对象导致的误连
- 是否帮助拆开仍然偏大的复杂服务组件

## 13. 建议的成功标准

这次改造的成功，不要只看最终分类指标，还要看分割本身是不是更合理。

建议至少同时看这几类指标：

### 13.1 结构指标

- 平均任务图进程节点数
- 任务图大小中位数
- 任务图大小 95 分位数
- 大于 200 / 500 / 1000 节点的任务图数量
- 每个高扇出根节点平均被细化成多少个社区组件

### 13.2 恶意覆盖指标

- 每个恶意任务图 1-hop 恶意节点被同一组件覆盖的比例
- 攻击报告中同一阶段关键进程是否更容易落到同一组件
- 同一组件内部恶意节点密度是否上升

### 13.3 module1 检测指标

- task-level precision / recall / F1
- 误报任务图平均大小
- 漏报恶意组件的典型结构

## 14. 施工时一定要避免的几个坑

### 坑 1：不要把“共享任意对象”直接等价成“属于同一社区”

这会被系统库、配置文件、公共日志文件污染得很厉害。

### 坑 2：不要一上来就在全量图上做完整随机游走聚类

先把确定有效的规则层引入，再考虑 walk。

### 坑 3：不要在第一步就让普通进程节点大规模重复出现在多个组件里

第一步只允许根节点复制，其他节点尽量单归属。

### 坑 4：不要保留“原始大组件 + 细化后小组件”并存

如果都保留，原始大组件很容易继续成为高分误报来源。

## 15. 推荐的实际落地顺序

如果让我安排另一个窗口施工，我会要求严格按下面顺序做：

1. 先做 Step 0，只生成 sidecar 和诊断，不改变结果。
2. 看诊断，确认高扇出根节点下确实存在共享资源的兄弟分支。
3. 做 Step 1，只做后处理社区细化，不动 `vendor/tapas/darpa.py` 主体逻辑。
4. 跑实验。
5. 如果 Step 1 有正收益，再做 Step 2，把细化前移到组件构造期。
6. 跑实验。
7. 如果误连仍明显，再做 Step 3 的对象过滤增强。
8. 最后才考虑 Step 4 的局部随机游走细化。

## 16. 一句话总结

我们当前的任务图分割最大的问题，不是“阈值调得不够好”，而是“切分依据太单一，只看进程树，不看兄弟分支之间通过资源形成的协作关系”。

DepComm 最值得借鉴的，也正是这一点：

- 社区的主体是进程，
- 社区的边界由父系结构和资源依赖共同决定，
- 高扇出父节点下面真正该聚在一起的是“协作的兄弟分支”，不是“整棵子树”。

所以这次改造的主线应该是：

- 先把资源依赖真正接进任务图分割，
- 再把高扇出根节点从“按树硬切”升级成“按协作社区细化”，
- 最后再视情况补 DepComm 风格的预处理和局部随机游走。

## 17. 推荐的函数拆分与调用顺序

这一节专门写给施工窗口，避免“知道要改什么，但不知道塞到哪里”。

### 17.1 Step 0 建议新增的函数

#### 在 `vendor/tapas/darpa.py` 中新增

```python
def _build_graph_partition_sidecar(subject_list, object_list, event_count):
    ...
```

职责：

- 从已有的 `subject_list / object_list / event_count` 构造 `graph_partition_sidecar`
- 不改变当前任务图切分结果

#### 在 `filters(...)` 内部补 sidecar 构造

Theia 不走 `parser_trace/parser_cadets` 这条路径，所以要在 `filters(...)` 返回字典里补：

```python
result["graph_partition_sidecar"] = sidecar
```

#### 在 `parser_cadets(...)` / `parser_trace(...)` 的返回 metadata 中补

```python
metadata["graph_partition_sidecar"] = sidecar
```

### 17.2 Step 1 建议新增的函数

#### 新文件

- `D:\daima\APT-Fusionstep2b1\src\apt_fusion\task_detection\depcomm_partition_refine.py`

#### 建议函数

```python
def apply_depcomm_post_refine(
    edge_list,
    *,
    sidecar,
    child_threshold,
    common_object_degree_threshold,
    shared_object_min_count,
    keep_parent_component,
    allow_root_duplication,
    ignore_system_paths,
    ignore_read_only_objects,
):
    ...
```

内部再拆成几个小函数：

```python
def _component_children(component): ...
def _component_branch_nodes(component, root, child): ...
def _collect_branch_object_profile(branch_nodes, sidecar): ...
def _filter_linkable_objects(object_ids, sidecar, ...): ...
def _build_branch_collaboration_graph(branch_profiles, ...): ...
def _connected_branch_clusters(branch_graph): ...
def _build_refined_components(component, clusters, ...): ...
```

### 17.3 Step 1 在主流程里的调用位置

在 `src/apt_fusion/task_detection/tapas_native_backend.py` 里，建议放在：

- `edge_list` 已经生成之后
- `vendor.decompose(...)` 之前

也就是这几个分支里：

- `cadets`
- `trace`
- `theia`

都在拿到 `edge_list` 之后，统一插入一段：

```python
if cfg.task_component_depcomm_refine_stage == "post":
    edge_list = apply_depcomm_post_refine(
        edge_list,
        sidecar=...,
        ...
    )
```

### 17.4 Theia 的顺序建议

如果：

- `cfg.host == "theia"`
- 并且 `task_component_theia_temporal_split_enabled == True`

建议顺序为：

1. 先跑当前已有的 temporal split
2. 再跑 `apply_depcomm_post_refine(...)`

原因：

- 先做时间切分，可以减少一个超长时间窗大组件内部的噪声共享对象。

### 17.5 Step 1 的启用条件

只对满足以下条件的组件尝试细化：

1. `task_root` 存在
2. `task_root` 的直接孩子数 `> child_threshold`
3. 组件节点数 `>= 4`
4. 构出的孩子分支数 `>= 2`

只在以下条件满足时真正替换原组件：

1. 社区细化后得到的簇数 `>= 2`
2. 每个新组件都至少有 2 个进程节点
3. 每个新组件都至少保留 1 条父子边

否则直接回退原组件。

### 17.6 Step 2 建议新增的函数

当 Step 1 证明有效后，再在 `vendor/tapas/darpa.py` 里加：

```python
def _build_task_components_depcomm_hybrid(
    padict,
    chdict,
    segmented,
    *,
    sidecar,
    child_threshold,
    common_object_degree_threshold,
    shared_object_min_count,
    ...
):
    ...
```

然后在 `_cut_task(...)` 里按配置选择：

```python
if split_mode == "depcomm_hybrid":
    components = _build_task_components_depcomm_hybrid(...)
else:
    components = _build_task_components(...)
```

### 17.7 Step 2 的一个关键要求

`depcomm_hybrid` 模式下，一旦某个根节点已经成功生成多个社区组件：

- 默认不要再额外保留那个未细化的原始大组件

否则很容易回到“一个大杂烩组件继续干扰排序和训练”的老问题。

### 17.8 建议的阶段化实验开关

建议用下面这组配置来做实验，而不是边改边删代码：

```yaml
task_component_depcomm_refine_enabled: true
task_component_depcomm_refine_stage: "post"   # none / post / native / walk
task_component_common_object_degree_threshold: 8
task_component_shared_object_min_count: 2
task_component_depcomm_keep_parent_component: false
task_component_depcomm_allow_root_duplication: true
task_component_depcomm_ignore_system_paths: true
task_component_depcomm_ignore_read_only_objects: true
task_component_depcomm_enable_hot_object_split: false
```

对应实验阶段：

- `none`
  - 纯基线
- `post`
  - 只启用 Step 1
- `native`
  - 启用 Step 2
- `walk`
  - `native` 基础上再启用 Step 4
