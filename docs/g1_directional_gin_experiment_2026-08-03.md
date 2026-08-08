# G1 Directional GIN Experiment (2026-08-03)

## Purpose

G1 tests whether parent-to-child process direction improves normal-only task
graph anomaly detection.  It is a controlled model experiment: parsing,
sequence features, security statistics, task splitting, task labels, benign
time split, threshold calibration, and module1 bundles remain fixed.

Relevant references and implementation sources:

- Dir-GNN wrapper: https://pytorch-geometric.readthedocs.io/en/2.6.1/generated/torch_geometric.nn.conv.DirGNNConv.html
- GraphMAE paper: https://arxiv.org/abs/2205.10803
- GraphMAE reference code: https://github.com/THUDM/GraphMAE

## Implementation

The detector is a benign-only feature reconstruction autoencoder.  A two-layer
GIN encoder feeds an MLP decoder.  The reconstruction loss is first averaged
inside each task graph and then across graphs in the batch; this prevents a
large CADETS service tree from dominating training because of node count.

The final score is the fixed combination already used by the normal-only line:

```
0.6 * mean(top-k node reconstruction errors)
+ 0.4 * distance(pooled graph embedding, benign graph prototypes)
```

The threshold is the 98th percentile of held-out benign validation scores.
Known attack graphs are excluded from fitting and threshold selection.

| Route | Only changed variable |
| --- | --- |
| G1 undirected | `GINConv(to_undirected(parent_to_child_edges))` |
| G1 directed | `DirGNNConv(GINConv(...))` on the original parent-to-child edges |

Both routes use hidden size 64, two layers, dropout 0.10, AdamW learning rate
0.001, weight decay 0.0001, 20 epochs, batch size 4, KMeans graph prototypes,
and adaptive `min(ceil(sqrt(node_count)), 16)` local aggregation.  The runs use
PyG 2.6.1 and an NVIDIA RTX 4080 SUPER.  Module0 was not run.  Module1 was
reused from the fixed G0 paper-aligned sequence bundle, because G1 changes only
the module2 graph detector.

## Results

All metrics are macro metrics on the held-out evaluation partition.

| Dataset | Route | Accuracy | Precision | Recall | F1 | ROC-AUC | PR-AUC | TP / FP / FN |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| CADETS | G0 fixed baseline | 0.9848 | 0.6471 | 0.9924 | 0.7234 | 0.9980 | 0.6962 | 5 / 12 / 0 |
| CADETS | G1 undirected GIN | 0.9747 | 0.6000 | 0.9873 | 0.6602 | 0.9964 | 0.6176 | 5 / 20 / 0 |
| CADETS | G1 directed GIN | 0.9773 | 0.6087 | 0.9886 | 0.6728 | 0.9964 | 0.6089 | 5 / 18 / 0 |
| TRACE | G0 fixed baseline | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 4 / 0 / 0 |
| TRACE | G1 undirected GIN | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 4 / 0 / 0 |
| TRACE | G1 directed GIN | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 4 / 0 / 0 |

## Audit and decision

Direction is useful inside the G1 pair on CADETS: it retains all five positive
tasks and reduces false positives from 20 to 18.  However, both G1 routes are
below the fixed G0 baseline, which has only 12 false positives.  The extra G1
false alarms are mainly short benign tasks (4 to 19 nodes) plus several 55 to
80 node service tasks.  Their standardized reconstruction scores are highly
dispersed after benign-only calibration, indicating that full feature
reconstruction is too sensitive to rare-but-benign process behavior.

Decision: retain the G1 implementation and successful artifacts as an
ablation/control, but do not promote it to the default detector and do not
advance automatically to G2.  The next masked-GraphMAE step should only be run
if it is redesigned to address this calibration instability, for example by
masked-node scoring with repeated masks and a separately audited local score.
