from __future__ import annotations
import copy, json, shutil, sys, traceback
from pathlib import Path
import torch

REPO=Path('/root/autodl-tmp/APT-Fusionstep2b1')
OUT=REPO/'debug/remote_ops/out/provgrp_tc3_g0_g1_20260808'
sys.path.insert(0,str(REPO/'src'))
from apt_fusion.config import load_config
from apt_fusion.task_detection.module1_online_graph import run_module1
from apt_fusion.task_detection.module2_online_detection import run_module2

SPECS={
 'cadets': (REPO/'configs/fusion_cloud_cadets_normal_only_eventstats_core_20260731.yaml', Path('/root/autodl-tmp/data/cadets/logs'), Path('/root/autodl-tmp/data/cadets/cadets.txt')),
 'trace': (REPO/'configs/fusion_cloud_trace_normal_only_multimodal_20260730.yaml', Path('/root/autodl-tmp/data/trace/logs'), Path('/root/autodl-tmp/data/trace/trace.txt')),
 'theia': (REPO/'configs/fusion_cloud_theia_train_stats_latefusion_llama31_taskcomponents.yaml', Path('/root/autodl-tmp/data/theia/logs'), Path('/root/autodl-tmp/data/theia/theia_ground_truth.txt')),
}
def q(v):
 v=sorted(v)
 if not v:return {'count':0}
 return {'count':len(v),'min':v[0],'median':v[len(v)//2],'p90':v[min(len(v)-1,round((len(v)-1)*.9))],'max':v[-1], 'le2':sum(x<=2 for x in v), 'gt1000':sum(x>1000 for x in v)}
def cfg_for(name, route):
 base, logs, gt=SPECS[name]; c=copy.copy(load_config(base)); c.host=name;c.source_logs=logs;c.task_ground_truth_path=gt
 c.artifacts_dir=REPO/f'artifacts_{name}_provgrp_{route}_20260808';c.ocr_runtime_root=REPO/'runtime'/'darpa_tc3'/f'{name}_provgrp_{route}_20260808'/'experiments';c.ocr_model_name=f'{name}_provgrp_{route}_20260808.pkl';c.task_detector_model_output=c.artifacts_dir/'module2'/'normal_only_model.pkl'
 c.task_detector_mode='normal_only';c.task_tapas_augmentation_enabled=False;c.path_reason_enabled=False
 c.task_component_provgrp_behavior_partition_enabled=True;c.task_component_provgrp_min_direct_children=10;c.task_component_provgrp_min_cluster_size=5;c.task_component_provgrp_min_samples=2;c.task_component_provgrp_max_events_per_matrix=512
 c.task_component_root_temporal_split_enabled=False;c.task_component_temporal_episode_split_enabled=False;c.task_component_synthetic_root_isolation_enabled=False;c.task_component_synthetic_root_selective_isolation_enabled=False;c.task_component_branch_object_overlap_split_enabled=False
 c.task_normal_only_train_fraction=.70;c.task_normal_only_validation_fraction=.15;c.task_normal_only_validation_fpr=.02;c.task_normal_only_global_model='kmeans';c.task_normal_only_local_top_k_mode='sqrt';c.task_normal_only_local_top_k_max=16;c.task_normal_only_global_weight=.40
 if route=='g0': c.task_normal_only_detector='prototype'
 else:
  c.task_normal_only_detector='gin_autoencoder';c.task_normal_only_gnn_direction_mode=route;c.task_normal_only_gnn_hidden_dim=64;c.task_normal_only_gnn_num_layers=2;c.task_normal_only_gnn_dropout=.1;c.task_normal_only_gnn_epochs=20;c.task_normal_only_gnn_batch_size=4;c.task_normal_only_gnn_learning_rate=.001;c.task_normal_only_gnn_weight_decay=.0001
 return c
def details(c, outs, reused):
 b=torch.load(c.module1_dir/'tapas_native_graphs.pt',map_location='cpu',weights_only=False); th=json.loads(Path(outs['task_thresholds']).read_text()); back=th.get('backend_summary',{}); metas=b['selected_graph_metas'];pos=[m for m in metas if int(m.get('label',0))]
 return {'module1_reused':reused,'task_count':len(metas),'gt_task_count':len(pos),'all_size':q([len(x.get('node_ids',[])) for x in metas]),'gt_size':q([len(x.get('node_ids',[])) for x in pos]),'module2_metrics':back.get('evaluation_metrics',{}),'provgrp':b.get('provgrp_paper_partition_summary',{})}
def save(rows): OUT.mkdir(parents=True,exist_ok=True);(OUT/'matrix_summary.json').write_text(json.dumps({'routes':rows},ensure_ascii=False,indent=2))
rows=[]
for name in SPECS:
 try:
  c=cfg_for(name,'g0');print('[START]',name,'G0',flush=True);m=run_module1(c);o=run_module2(c,m['process_embeddings'],m['task_subgraphs'],m['process_segmentation_edges']);rows.append({'dataset':name,'route':'g0_prototype','status':'completed','details':details(c,o,False)});save(rows);print('[DONE]',name,'G0',flush=True)
 except Exception as e:
  traceback.print_exc();rows.append({'dataset':name,'route':'g0_prototype','status':'failed','error':repr(e)});save(rows);continue
 for route in ('undirected','directed'):
  try:
   c=cfg_for(name,route);c.artifacts_dir.mkdir(parents=True,exist_ok=True);target=c.artifacts_dir/'module1';source=REPO/f'artifacts_{name}_provgrp_g0_20260808'/'module1';target.symlink_to(source,target_is_directory=True);print('[START]',name,'G1',route,flush=True);o=run_module2(c,target/'process_embeddings.csv',target/'task_subgraphs.json',target/'process_segmentation_edges.csv');rows.append({'dataset':name,'route':'g1_'+route,'status':'completed','details':details(c,o,True)});save(rows);print('[DONE]',name,'G1',route,flush=True)
  except Exception as e: traceback.print_exc();rows.append({'dataset':name,'route':'g1_'+route,'status':'failed','error':repr(e)});save(rows)
print(json.dumps({'routes':rows},ensure_ascii=False,indent=2))
