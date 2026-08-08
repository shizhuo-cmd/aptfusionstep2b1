# CADETS/TRACE 直接子进程时间 Episode 切图实验（2026-08-05）

## 目标

本轮不启用共享对象二次切分 `task_component_branch_object_overlap_split_enabled`。目标是从时间角度改进当前 TAPAS `child_count > 2` 的父子任务切分，重点检查：

- 是否降低节点数异常大的任务图；
- 是否不新增节点数为 2 或 3 的 GT 阳性任务图；
- 是否保持 GT 节点覆盖；
- 是否不以明显的 normal-only 检测退化换取图压缩。

本轮所有完整实验只运行 Module 1 和 Module 2，未调用 Module 0。

## 设计依据

长期运行进程会把多个独立行为错误地粘连为同一溯源主体。BEEP 将长期进程划分为处理独立请求的执行单元；LogKernel 使用依赖在生命周期中的时间密度划分行为实例；ProvGRP 也将时间间隔作为区分长期进程高层行为的特征。

- [BEEP: High Accuracy Attack Provenance via Binary-based Execution Partition](https://www.cs.purdue.edu/homes/dxu/pubs/NDSS13.pdf)
- [LogKernel](https://arxiv.org/abs/2208.08820)
- [ProvGRP](https://www.mdpi.com/2079-9292/13/1/100)
- [TAPAS](https://www.usenix.org/system/files/usenixsecurity25-zhang-bo-tapas.pdf)

旧的根节点时间实验只处理 `parent_missing` 根，且以整条子树的首末时间聚类。它在 CADETS 中产生碎片、在 TRACE 中不命中有效组件。新方案改为：

1. 对每张 TAPAS 任务图的根，取直接子进程的**自身首次可观测 Event 时间**，不使用后代节点时间；
2. 仅在任务图不少于 200 节点、直接子进程不少于 16 个、直接子进程时间跨度不少于 60 分钟时尝试切分；
3. 将相邻启动间隔高于阈值的子进程划入新的时间 episode；
4. 使用相邻启动间隔的 P90 作为每个父进程自适应阈值；
5. 小于 8 个直接子进程的相邻 episode 会回并，避免生成 2/3 节点任务；
6. 每个父进程最多保留 8 个 episode，并保留原根作为所有 episode 的边界节点；
7. 未带时间的分支不伪造时间，保留为一组并参与后续回并。

这仍是纯时间方案：未引入文件、网络或共享对象关系。

## 对照路线

| 路线 | 时间阈值 | 父节点范围 | episode 预算合并 |
|---|---|---|---|
| Baseline | 无 | 原始 TAPAS | 无 |
| parent-missing fixed 30m | 固定 30 分钟 | 仅缺失父根 | 相邻贪心 |
| all fixed 30m | 固定 30 分钟 | 所有合格根 | 相邻贪心 |
| all quantile P90 | 相邻间隔 P90 | 所有合格根 | 相邻贪心 |
| all median + 3 MAD | 中位数 + 3 MAD | 所有合格根 | 相邻贪心 |
| all quantile P90 balanced | 相邻间隔 P90 | 所有合格根 | 时间顺序、按直接子进程数量均衡到 8 组 |

结构审计对所有路线复用同一次解析的 TAPAS 组件，因此不受模型随机性影响。最终 Module 1/2 只运行 P90 的两种预算合并版本。

## 结构审计结果

### CADETS

| 路线 | 任务图 | 阳性图 | 最大节点数 | P99 | GT 节点覆盖 | 阳性 `<=3` | 阳性 `<=5` |
|---|---:|---:|---:|---:|---:|---:|---:|
| Baseline | 5,247 | 5 | 71,975 | 38 | 16 | 0 | 0 |
| parent-missing fixed 30m | 5,276 | 5 | 71,975 | 76 | 16 | 0 | 0 |
| all fixed 30m | 5,286 | 5 | 71,975 | 83 | 16 | 0 | 0 |
| all quantile P90 | 5,390 | 5 | 12,563 | 432 | 16 | 0 | 0 |
| all median + 3 MAD | 5,330 | 5 | 71,902 | 183 | 16 | 0 | 0 |

固定 30 分钟对最大 CADETS 图无效；MAD 对高密度 burst 给出过小阈值，预算回并后仍留下接近原始规模的图。P90 方案首次切分了 71,975 节点组件，但也把尾部规模从少数超大图转移为更多中大型 episode。

### TRACE

| 路线 | 任务图 | 阳性图 | 最大节点数 | P99 | GT 节点覆盖 | 阳性 `<=3` | 阳性 `<=5` |
|---|---:|---:|---:|---:|---:|---:|---:|
| Baseline | 1,108 | 4 | 252 | 80 | 11 | 0 | 1 |
| parent-missing fixed 30m | 1,108 | 4 | 252 | 80 | 11 | 0 | 1 |
| all fixed 30m | 1,108 | 4 | 252 | 80 | 11 | 0 | 1 |
| all quantile P90 | 1,112 | 4 | 140 | 79 | 11 | 0 | 1 |
| all median + 3 MAD | 1,112 | 4 | 140 | 79 | 11 | 0 | 1 |

TRACE 只有一个 252 节点的合格根被切为 5 个 episode。现有唯一极小 GT 图为 4 节点，时间切分既没有合并它，也没有把它切得更小。

## 完整 Module 1/2 验证

### CADETS

| 路线 | 任务图 | 最大节点数 | P95 / P99 | 阳性最小 / 中位 / 最大 | 阳性 `<=3` / `<=5` | Precision | Recall | F1 | PR-AUC |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Baseline | 5,247 | 71,975 | 11 / 38 | 92 / 1,166 / 1,922 | 0 / 0 | 0.6351 | 0.7949 | 0.6843 | 0.4698 |
| P90 + 相邻贪心 | 5,390 | 12,563 | 15 / 432 | 92 / 213 / 311 | 0 / 0 | 0.5962 | 0.9870 | 0.6547 | 0.5593 |
| P90 + 均衡合并 | 5,390 | **8,998** | 15 / 445 | 92 / 150 / 241 | 0 / 0 | 0.6042 | 0.9883 | **0.6665** | 0.5593 |

均衡合并将最大任务图从 71,975 降至 8,998，减少 87.5%。相对于相邻贪心，它进一步缩小最大图并提高 F1 约 0.0118；但仍低于基线 0.0178。P95/P99 和 `>500` 图数量上升，说明该方案是把极端超大图转化为多个中大型图，而不是整体缩小所有图。

### TRACE

| 路线 | 任务图 | 最大节点数 | P95 / P99 | 阳性最小 / 中位 / 最大 | 阳性 `<=3` / `<=5` | Precision | Recall | F1 | PR-AUC |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Baseline | 1,108 | 252 | 77 / 80 | 4 / 28 / 31 | 0 / 1 | 0.4883 | 0.5000 | 0.4941 | 1.0000 |
| P90 + 相邻贪心 | 1,112 | 140 | 77 / 79 | 4 / 28 / 31 | 0 / 1 | 0.4883 | 0.5000 | 0.4941 | 0.6603 |
| P90 + 均衡合并 | 1,112 | 140 | 77 / 79 | 4 / 28 / 31 | 0 / 1 | 0.4883 | 0.5000 | 0.4941 | 0.6603 |

TRACE 中两种预算策略等价，因为只有一个根被分成 5 个 episode，未超过 8 组预算。分类阈值下的 Precision、Recall 和 F1 保持不变；排序指标变化表明图表示有变化，不能只用 F1 宣称无影响。

## 结论

1. 不应将本时间切分设为 TAPAS 的默认规则。CADETS 的最大图显著缩小，但 F1 由 0.6843 降为 0.6665，且 P99 和中大型图数量上升。
2. `P90 + balanced_child_count` 是本轮最稳的时间候选。它不降低 GT 节点覆盖，不增加 2/3 节点 GT 图，并给出最小的 CADETS 最大图。
3. TRACE 只有规模收益，没有 GT 小图修复收益。当前 4 节点 GT 图来自原始 TAPAS 结构，单纯切分不能把它合理合并；后续若要处理该问题，需要单独研究同一边界父节点下的时间邻近小任务合并，而不能在本轮无证据地加入。
4. 后续建议将此开关用于内存受限的攻击路径重建或大图审计，而非默认 normal-only 检测训练。若继续优化，应在 P90 episode 内再引入会话或资源因果关系，而不是继续调低时间间隔。

## 实现与产物

- [配置定义](../src/apt_fusion/config.py)
- [时间 episode 切分实现](../src/apt_fusion/task_detection/tapas_native_backend.py)
- [结构审计运行脚本](../debug/remote_ops/cadets_trace_temporal_episode_audit_20260805_runner.py)
- [Module 1/2 运行脚本](../debug/remote_ops/cadets_trace_temporal_episode_module12_20260805_runner.py)
- 云端结构审计：`/root/autodl-tmp/APT-Fusionstep2b1/debug/remote_ops/out/cadets_trace_temporal_episode_audit_20260805/audit_summary.json`
- 云端完整矩阵：`/root/autodl-tmp/APT-Fusionstep2b1/debug/remote_ops/out/cadets_trace_temporal_episode_module12_20260805/matrix_summary.json`

