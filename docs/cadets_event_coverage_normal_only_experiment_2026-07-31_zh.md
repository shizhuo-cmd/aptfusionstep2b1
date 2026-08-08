# CADETS 事件覆盖统计旁路实验记录

日期：2026-07-31  
范围：仅模块 1 和模块 2；未运行模块 0、模块 3 或后续攻击战术分析。

## 实验目的

确认当前进程序列表示只记录有限事件类别时，给任务图节点增加流式动作统计是否能改善正常任务原型检测；同时区分“只统计现有核心事件”和“统计更宽事件集合”的效果。

## 固定条件

- 数据集：CADETS 原始日志。
- 任务切分：父子分支切分，子进程数大于 2 时切分，分割点不计入上游有效子节点数。
- 不做数据增强。
- 每条路线都重新运行模块 1 和模块 2；不复用模块 1 产物。
- 正常任务按时间切分：3,669 张训练、786 张验证、787 张测试；5 张 GT 阳性任务图只进入测试。
- 阈值由良性验证集的 99% 分位数确定，目标良性验证告警率为 1%。

GT 阳性任务图固定为：`task_0005`、`task_0006`、`task_0012`、`task_0013`、`task_1021`。三条路线均形成 5,247 张任务图，并包含上述全部 5 张 GT 阳性图。

## 路线

| 路线 | 节点输入 | 事件覆盖 | 维度 |
|---|---|---|---:|
| `legacy_sequence_only` | 既有 LSTM-GRU 序列向量 | 既有 10 类事件 | 42 |
| `core_event_statistics` | 序列向量加统计旁路 | 既有核心事件类别的完整规范进程计数 | 103 |
| `extended_event_statistics` | 序列向量加统计旁路 | 额外加入删除、提权、属性修改、打开、映射、创建及其他动作 | 103 |

统计旁路在同一遍日志解析中累计，线程先归并到所属进程后再统计；不需要额外扫描原始日志。核心线和扩展线使用相同的 61 维统计特征模式，仅事件覆盖范围不同。

## 结果

| 路线 | 检出 GT | 漏报 GT | 误报良性图 | 宏 Precision | 宏 Recall | 宏 F1 | ROC-AUC | PR-AUC | 阈值 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `legacy_sequence_only` | 3 / 5 | 2 | 8 | 0.6351 | 0.7949 | 0.6843 | 0.9926 | 0.5271 | 16.5813 |
| `core_event_statistics` | 5 / 5 | 0 | 7 | 0.7083 | 0.9956 | 0.7919 | 0.9982 | 0.7783 | 7.8984 |
| `extended_event_statistics` | 5 / 5 | 0 | 7 | 0.7083 | 0.9956 | 0.7919 | 0.9959 | 0.5766 | 9.6646 |

基线漏掉 `task_0005` 和 `task_1021`。核心和扩展统计都补回两张任务图，并把误报从 8 张降至 7 张。扩展统计没有进一步改善固定阈值下的召回或误报数，且 PR-AUC 从核心线的 0.7783 降为 0.5766。

## 结论

核心事件统计旁路应保留为下一步的 CADETS 正常任务检测基线。扩展事件集合不应在当前统计模型中默认启用；后续应把它用于统一语义事件编码或下一事件预测误差，而不是无差别扩大统计集合。

基线到核心线的提升是联合收益：旧序列向量覆盖 209,323 个进程，统计旁路覆盖任务图中的 224,503 个规范进程。因此它同时体现了核心统计信息和原本零历史进程获得表示的效果。核心与扩展两条路线进程覆盖和特征维度相同，二者的比较更适合衡量扩大事件覆盖本身的影响。

## 产物

- `/root/autodl-tmp/APT-Fusionstep2b1/artifacts_cadets_normal_only_eventstats_legacy_20260731`
- `/root/autodl-tmp/APT-Fusionstep2b1/artifacts_cadets_normal_only_eventstats_core_20260731`
- `/root/autodl-tmp/APT-Fusionstep2b1/artifacts_cadets_normal_only_eventstats_extended_20260731`
- `/root/autodl-tmp/APT-Fusionstep2b1/debug/remote_ops/out/cadets_event_coverage_normal_only_matrix_20260731/matrix_summary.json`

## 第二轮：安全语义统计与正常样本模型对照（2026-07-31）

这一轮仍然只运行模块 1 和模块 2，没有运行模块 0。四条路线都使用同一份 CADETS 原始日志、同一套 5 张 GT 阳性任务图和相同的正常样本时间切分：3,669 张训练正常图、786 张验证正常图、787 张测试正常图；5 张已知攻击图始终只进入最终测试。阈值继续只由正常验证集的 99% 分位数确定。

本轮不再把所有扩展动作逐项送进统计分支，而是按安全含义归并为执行、进程生命周期、提权、文件读写/修改、网络连接/收发、内存控制和进程信号等组；总事件量和安全事件占比单独保留，未映射的 `OTHER` 不作为攻击特征。这样既保留高价值行为，也避免把大量通用系统调用当成独立信号。随后比较固定 Top-3 与随图规模变化的 `ceil(sqrt(node_count))` 局部聚合，并以 KNN 替换 KMeans 全局正常模型。

| 路线 | 节点特征 | 局部聚合 | 全局正常模型 | 检出 GT | 漏报 | 误报正常图 | Macro Precision | Macro Recall | Macro F1 | ROC-AUC | PR-AUC |
|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `core_raw_fixed` | 42 维序列表征 + 61 维核心原始动作统计 | 固定 Top-3 | KMeans | 5 / 5 | 0 | 7 | 0.7083 | 0.9956 | 0.7919 | 0.9982 | 0.7783 |
| `security_semantic_fixed` | 42 维序列表征 + 15 维安全语义统计 | 固定 Top-3 | KMeans | 5 / 5 | 0 | 6 | 0.7273 | 0.9962 | 0.8106 | 0.9980 | 0.6962 |
| `security_semantic_adaptive` | 同上 | 自适应 Top-K，最大 16 | KMeans | 5 / 5 | 0 | 5 | 0.7500 | 0.9968 | 0.8317 | 0.9980 | 0.6962 |
| `security_semantic_adaptive_knn` | 同上 | 自适应 Top-K，最大 16 | 5 邻居 KNN | 5 / 5 | 0 | 6 | 0.7273 | 0.9962 | 0.8106 | 0.9992 | 0.9250 |

四条路线均覆盖全部 GT 任务图：`task_0005`、`task_0006`、`task_0012`、`task_0013`、`task_1021`。KNN 路线复用 `security_semantic_adaptive` 已重新生成的模块 1 结果，只重跑模块 2；因此它和自适应 KMeans 路线的任务图、GT 覆盖及特征完全一致。

### 本轮结论

安全语义统计比 61 维原始动作统计更紧凑（57 维总输入而非 103 维），在固定 Top-3 下将误报从 7 张降到 6 张，并把 Macro F1 从 0.7919 提升到 0.8106。进一步改用自适应局部 Top-K 后，全部 5 张攻击图仍被检出，误报进一步降到 5 张，Macro F1 达到本轮最高的 0.8317。因此后续 CADETS normal-only 主线应优先采用“安全语义统计 + 自适应局部 Top-K + KMeans”。

KNN 的 PR-AUC 虽然最高，但其验证分数尺度极不稳定（阈值约 1.18e7，而中位数约 0.70），固定的 1% 正常验证告警率下仍产生 6 张误报，并没有超过自适应 KMeans 的最终告警效果。它可作为排序/集成候选，但暂不替换默认全局模型。

## 第二轮产物

- `/root/autodl-tmp/APT-Fusionstep2b1/artifacts_cadets_normal_only_semantic_model_core_raw_fixed_20260731`
- `/root/autodl-tmp/APT-Fusionstep2b1/artifacts_cadets_normal_only_semantic_model_security_semantic_fixed_20260731`
- `/root/autodl-tmp/APT-Fusionstep2b1/artifacts_cadets_normal_only_semantic_model_security_semantic_adaptive_20260731`
- `/root/autodl-tmp/APT-Fusionstep2b1/artifacts_cadets_normal_only_semantic_model_security_semantic_adaptive_knn_20260731`
- `/root/autodl-tmp/APT-Fusionstep2b1/debug/remote_ops/out/cadets_normal_only_semantic_model_matrix_20260731/matrix_summary.json`
