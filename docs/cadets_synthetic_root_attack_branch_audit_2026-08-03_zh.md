# CADETS 大收集根攻击分支审计与选择性拆分实验

日期：2026-08-03  
范围：CADETS 模块 1 与模块 2；未运行模块 0。

## 问题

CADETS 的少数 GT 正类任务图很大，但它们的根并不是实际执行的父进程，而是 `parent=null` 且 `startTimestampNanos=0` 的收集根。这样的根把相互无关的服务分支粘在一起，导致攻击子树和大量正常服务行为混在同一任务图中。

本次目标不是按 GT 或报告文件名硬编码，而是确认能否从原始日志中找出一个可泛化的拆分条件，尽量将和攻击无关的分支留在原图之外。

## 日志与报告核验

审计脚本：`debug/remote_ops/audit_cadets_gt_root_branches_20260803.py`。完整结果保存在云端：

`/root/autodl-tmp/APT-Fusionstep2b1/debug/remote_ops/out/cadets_gt_root_branch_audit_20260803/cadets_gt_root_branch_audit.json`

| GT 任务图 | 节点数 | 日志中攻击相关分支 | 同根下明确无关的典型分支 |
| --- | ---: | --- | --- |
| `task_0005` | 150 | `/tmp/tmux-1002`、`/tmp/minions`、`/tmp/font`、`/tmp/XIM`、`/tmp/test`，以及 `netlog/sendmail/main/test` 的写入或删除 | 少量正常分支 |
| `task_0006` | 1,166 | 两个单节点分支分别执行 `/tmp/tmux-1002`、`/tmp/minions` | 1,000 多个 Postfix `local`、`smtpd`、`cleanup` 等服务分支 |
| `task_0012` | 1,922 | 执行 `/tmp/tmux-1002` 与 `/var/log/netlog` 的分支 | 大量无关服务分支 |
| `task_0013` | 1,535 | 执行 `/tmp/XIM` 的分支 | 大量 `/usr/local/libexec/imapd` 与 `mlock` 分支 |
| `task_1021` | 92 | `/tmp/pEja72mA`、`/tmp/memhelp.so`、`eraseme`、`done.so`、`injectLog.txt` 相关分支 | 少量非攻击分支 |

这些观察与 TC3 报告中 CADETS 的临时载荷、`netlog`、清理和注入描述一致。也同时说明“访问 `/tmp`”“有网络行为”或“执行任意程序”都太宽：例如 `task_0013` 的正常 IMAP 服务也会频繁接触临时对象。

## 规则设计

新增的选择性规则只在同时满足下列条件时工作：

1. 任务根没有父进程，且启动时间为 `0`。
2. 任务图至少有 500 个节点、根下至少有 64 个直接子分支。
3. 直接子树内存在 `EVENT_EXECUTE` 的目标，该目标不位于常见系统二进制目录（`/bin`、`/sbin`、`/usr/bin`、`/usr/sbin`、`/usr/lib`、`/usr/local/libexec`、`/lib`、`/lib64`）。
4. 该执行目标在同一个收集根中最多出现 3 次。

命中的分支会单独形成候选任务图；未命中的分支仍保留在原收集根的剩余任务图中。规则只使用日志事件、路径和局部出现频次，**不**使用 GT UUID、攻击报告名称或固定恶意文件名。

为支持该规则，CADETS 解析阶段新增了“规范化进程 -> 实际执行目标路径及次数”的轻量元数据。线程归并完成后才进行统计，避免线程 UUID 把同一进程的执行记录拆散。

## 对照实验

固定设置：正常样本训练、无数据增强、相同模块 2 配置。指标为模块 2 验证/评估输出的宏平均结果。

| 方案 | 任务图数 | GT 正类图数 | 最大图节点数 | 宏精确率 | 宏召回率 | 宏 F1 | TP / FN | 结论 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| 固定基线 | 5,247 | 5 | 71,975 | 0.632 | 0.991 | 0.704 | 5 / 0 | 对照 |
| 所有根下分支均拆出 | 133,593 | 7 | 44,711 | 0.501 | 0.684 | 0.487 | 3 / 4 | 失败 |
| 选择性罕见执行分支拆分 | 5,251 | 6 | 71,975 | 0.650 | 0.991 | 0.726 | 6 / 0 | 保留 |

全量拆分实验把真实的收集根下所有服务子树都变成独立样本，造成任务数暴涨并显著降低 F1；该产物已改名为：

`/root/autodl-tmp/APT-Fusionstep2b1/artifacts_cadets_synthetic_root_isolation_start0_20260803_failed_metric_regression`

选择性规则只在 3 个收集根上生效，共抽出 4 条分支：

- 一个根：`/tmp/vUgefal`
- 一个根：`/tmp/minions`、`/tmp/tmux-1002`
- 一个根：`/tmp/XIM`

成功产物：

`/root/autodl-tmp/APT-Fusionstep2b1/artifacts_cadets_selective_synthetic_root_isolation_20260803`

实验摘要：

`/root/autodl-tmp/APT-Fusionstep2b1/debug/remote_ops/out/cadets_selective_synthetic_root_isolation_20260803/matrix_summary.json`

## 结论和限制

这条规则证明，大收集根不应被统一按子分支完全拆碎；但是依据实际 `EXECUTE` 目标做局部、低频、非系统二进制分支隔离，可以缩小攻击语义与大量邮件或服务行为的混合，并在当前 CADETS 正常样本检测实验中提高宏 F1。

规则尚未覆盖只通过写入、加载或删除体现而没有明确 `EVENT_EXECUTE` 路径的攻击分支，例如部分 `netlog` 与注入后续行为。下一步如需继续扩展，应先以同样严格的方式加入“写入后执行/加载”对象谱系，而不能把任何临时文件或外连直接视作攻击。
