# CADETS/TRACE：节点预算、回并与重复叶压缩实验

## 目的

上一轮 P90 直接子进程启动时间切分将 CADETS 最大任务图从 71,975 降至
8,998 节点，但仍存在不适合图模型训练的长尾大图。本轮在同一份
`quantile90 + balanced_child_count` 时间切分 Module 1 输入上测试：

1. 硬节点预算：`512`、`1024`、`2048`；
2. `1024` 预算后的最小 16 节点预算分区回并；
3. 在第 2 项基础上，同父、同非空事件计数签名、至少 4 个成员的保守重复叶压缩。

所有路由均显式关闭 `task_component_branch_object_overlap_split_enabled`，不使用先前暂停的资源二次切分，也不调用 Module 0。预算、回并和压缩规则不读取攻击标签；GT 仅用于最终评价。重复叶压缩保留 `original_nodes`，因此压缩后的标签仍按原始 UUID 集合计算。

## 实现

- [预算/回并/压缩后端](D:/daima/APT-Fusionstep2b1/src/apt_fusion/task_detection/tapas_native_backend.py)
- [配置项](D:/daima/APT-Fusionstep2b1/src/apt_fusion/config.py)
- [云端复用 Module 1 的矩阵脚本](D:/daima/APT-Fusionstep2b1/debug/remote_ops/cadets_trace_budget_compression_reuse_module1_20260805_runner.py)
- [汇总结果](D:/daima/APT-Fusionstep2b1/debug/remote_ops/out/cadets_trace_budget_compression_reuse_module1_20260805/matrix_summary.json)

为避免每条路由重新解析 CADETS/TRACE 原始日志，矩阵从上一轮已经完成的
`quantile90 + balanced_child_count` Module 1 bundle 重建任务组件，应用新规则后重新生成图并运行 Module 2。这保证所有路由的时间切分输入一致。

## CADETS 结果

时间切分输入基线：5,390 张图、最大 8,998 节点、F1 `0.6665`。

| Route | 图数 | 最大节点数 | P95 / P99 | `>500` / `>1000` | GT 正图最小/最大 | GT `<=3` / `<=5` | F1 | PR-AUC |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Budget 512 | 5,694 | 512 | 512 / 512 | 304 / 0 | 92 / 241 | 0 / 0 | 0.6668 | 0.5260 |
| Budget 1024 | 5,526 | 1,024 | 61 / 1,024 | 168 / 136 | 92 / 241 | 0 / 0 | **0.6731** | **0.5593** |
| Budget 2048 | 5,446 | 2,048 | 20 / 2,048 | 104 / 80 | 92 / 241 | 0 / 0 | 0.6665 | 0.5593 |
| Budget 1024 + merge16 | 5,526 | 1,024 | 61 / 1,024 | 168 / 136 | 92 / 241 | 0 / 0 | 0.6731 | 0.5593 |
| Budget 1024 + merge16 + leaf compression | 5,526 | 1,024 | 61 / 1,024 | 168 / 136 | 92 / 241 | 0 / 0 | 0.6731 | 0.5593 |

解释：

- 三档预算都严格控制了最大图规模；不存在无法继续拆分的超过预算任务。
- `1024` 是最好的折中：最大图比时间切分输入进一步减少 `88.6%`，并在本次固定 normal-only 流程中获得最高 F1。
- `512` 过于激进，P95 也达到 512，说明大量图紧贴预算上限；`2048` 留下较多大图。
- 回并数量为 0。预算切分没有产生小于 16 节点、且存在可在预算内合并的同源分区。
- 严格叶压缩删除节点数为 0；当前 CADETS 时间切分后的任务图中没有满足“同父、同精确事件计数签名、至少四个叶节点”的组。这是保守签名设计的负结果，不表示重复行为不存在。

## TRACE 结果

时间切分输入的最大图只有 140 节点，因此所有预算均未触发。

| Route | 图数 | 最大节点数 | GT 正图最小/最大 | GT `<=3` / `<=5` | F1 | PR-AUC |
|---|---:|---:|---:|---:|---:|---:|
| Budget 512/1024/2048 | 1,112 | 140 | 4 / 31 | 0 / 1 | 0.4941 | 0.6603 |
| Budget 1024 + merge16 | 1,112 | 140 | 4 / 31 | 0 / 1 | 0.4941 | 0.6603 |
| Budget 1024 + merge16 + leaf compression | 1,112 | 140 | 4 / 31 | 0 / 1 | 0.4941 | 0.6603 |

因此，当前的预算后回并只约束新产生的预算分区，不能也不应随意合并 TRACE 原有的 4 节点 GT 任务。原始小任务是否应合并需要额外的因果证据，不能仅因为节点数小而处理。

## 结论

建议将下列配置作为 CADETS 的可选资源控制视图：

```text
temporal episode: P90 + balanced_child_count
hard node budget: 1024
small-task merge: disabled
repeated-leaf compression: disabled
```

原因是 `1024` 同时消除了超大单图、未制造 2/3 节点 GT 图，并取得本轮最好的 F1。回并和严格重复叶压缩暂不作为默认规则：前者没有实际触发，后者过于保守而没有压缩收益。

若后续继续研究压缩，应优先扩展为“相同父进程 + 相近事件类型集合 + 时间相近”的近似重复叶签名，并单独报告压缩率、GT UUID 覆盖和攻击链可恢复性；不要仅放宽事件签名而不做这些安全检查。
