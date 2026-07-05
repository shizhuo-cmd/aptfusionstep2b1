import copy
import os, json, traceback, sys, re, gc
sys.dont_write_bytecode = True
import collections
import random
from datetime import datetime, timezone
from sklearn.metrics import accuracy_score, precision_recall_fscore_support
import torch
import torch.nn as nn
import numpy as np
import torch.nn.functional as F
from torch_geometric.data import Data, InMemoryDataset
from torch_geometric.nn import SAGEConv, global_mean_pool, Linear, global_add_pool, global_max_pool
from torch_geometric.loader import DataLoader
from torch.optim import Adam
from tqdm import tqdm

device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')


def _subject_properties_map(subject_data):
    properties = subject_data.get("properties")
    if not isinstance(properties, dict):
        return {}
    mapping = properties.get("map")
    if not isinstance(mapping, dict):
        return {}
    return mapping


def _subject_parent_uuid(subject_data):
    parent_ref = subject_data.get("parentSubject")
    if isinstance(parent_ref, dict):
        value = parent_ref.get("com.bbn.tc.schema.avro.cdm18.UUID")
        if value:
            return str(value)
    return "Unknow"


def _subject_tgid(subject_data):
    props = _subject_properties_map(subject_data)
    value = props.get("tgid")
    if value is None:
        return ""
    return str(value).strip()


def _resolve_thread_subject_owners(subject_rows):
    subject_info = {
        str(row["uuid"]): dict(row)
        for row in subject_rows
        if isinstance(row, dict) and str(row.get("uuid", "")).strip()
    }
    owner_cache = {}

    def resolve_owner(subject_uuid, trail=None):
        subject_uuid = str(subject_uuid)
        if subject_uuid in owner_cache:
            return owner_cache[subject_uuid]
        if subject_uuid not in subject_info:
            owner_cache[subject_uuid] = subject_uuid
            return subject_uuid
        if trail is None:
            trail = set()
        if subject_uuid in trail:
            owner_cache[subject_uuid] = subject_uuid
            return subject_uuid
        trail.add(subject_uuid)
        row = subject_info[subject_uuid]
        owner = subject_uuid
        parent_uuid = str(row.get("parentuuid", "Unknow"))
        subject_tgid = str(row.get("tgid", "")).strip()
        if parent_uuid in subject_info:
            parent_tgid = str(subject_info[parent_uuid].get("tgid", "")).strip()
            if subject_tgid and parent_tgid and subject_tgid == parent_tgid:
                owner = resolve_owner(parent_uuid, trail)
        trail.remove(subject_uuid)
        owner_cache[subject_uuid] = owner
        return owner

    owner_by_uuid = {
        subject_uuid: resolve_owner(subject_uuid)
        for subject_uuid in subject_info
    }
    process_parent_by_owner = {}
    for subject_uuid, row in subject_info.items():
        owner_uuid = owner_by_uuid[subject_uuid]
        if owner_uuid != subject_uuid:
            continue
        current_tgid = str(row.get("tgid", "")).strip()
        parent_uuid = str(row.get("parentuuid", "Unknow"))
        visited = {subject_uuid}
        resolved_parent = "Unknow"
        while parent_uuid in subject_info and parent_uuid not in visited:
            visited.add(parent_uuid)
            parent_row = subject_info[parent_uuid]
            parent_tgid = str(parent_row.get("tgid", "")).strip()
            if current_tgid and parent_tgid and current_tgid == parent_tgid:
                parent_uuid = str(parent_row.get("parentuuid", "Unknow"))
                continue
            resolved_parent = owner_by_uuid.get(parent_uuid, parent_uuid)
            break
        process_parent_by_owner[owner_uuid] = resolved_parent
    return owner_by_uuid, process_parent_by_owner


def _remap_event_subjects(event_count, raw_to_canonical):
    remapped = {}
    for key, count in event_count.items():
        if not isinstance(key, tuple) or len(key) != 3:
            continue
        event_type, subject_id, object_id = key
        canonical_subject = raw_to_canonical.get(str(subject_id), str(subject_id))
        remapped_key = (event_type, canonical_subject, object_id)
        if remapped_key in remapped:
            remapped[remapped_key] += count
        else:
            remapped[remapped_key] = count
    return remapped

def parser_cadets(data_path):
    data_list = os.listdir(data_path)
    event_map = {'EVENT_ACCEPT': 1, 'EVENT_CONNECT': 2, 'EVENT_EXECUTE': 3, 'EVENT_EXIT': 4, 'EVENT_READ': 5,
                 'EVENT_RECVFROM': 6, 'EVENT_RECVMSG': 7, 'EVENT_SENDTO': 8, 'EVENT_SENDMSG': 9, 'EVENT_WRITE': 10}
    subject_list = []
    object_list = []
    event_count = {}
    file_path = {}
    subject_rows = []

    for file in tqdm(data_list, desc=f"Parsing", unit="file"):
        f = open(data_path + file, 'r')
        for line in f:
            try:
                event = json.loads(line)
                if "com.bbn.tc.schema.avro.cdm18.Event" in event["datum"]:
                    data = event["datum"]["com.bbn.tc.schema.avro.cdm18.Event"]
                    type = data["type"]
                    if type not in event_map:
                        continue
                    subId = data["subject"]["com.bbn.tc.schema.avro.cdm18.UUID"]
                    if data["predicateObject"] is None:
                        continue
                    objId = data["predicateObject"]["com.bbn.tc.schema.avro.cdm18.UUID"]
                    typeId = event_map[type]
                    key = (typeId, subId, objId)
                    if key in event_count:
                        event_count[key] += 1
                    else:
                        event_count[key] = 1

                    if data['predicateObjectPath'] is not None:
                        var = data['predicateObjectPath']['string']
                        var = 'Unknow' if 'unknow' in var else var
                        file_path[objId] = var

                elif "com.bbn.tc.schema.avro.cdm18.NetFlowObject" in event["datum"]:
                    data = event["datum"]["com.bbn.tc.schema.avro.cdm18.NetFlowObject"]
                    uuid = data["uuid"]
                    localIP = data["localAddress"]
                    localPort = str(data["localPort"])
                    remoteIP = data["remoteAddress"]
                    remotePort = str(data["remotePort"])
                    object_list.append(['3', uuid, localIP, remoteIP, localPort, remotePort])
                elif "com.bbn.tc.schema.avro.cdm18.Subject" in event["datum"]:
                    data = event["datum"]["com.bbn.tc.schema.avro.cdm18.Subject"]
                    uuid = data["uuid"]
                    parentuuid = _subject_parent_uuid(data)
                    pid = str(data["cid"])
                    subject_rows.append(
                        {
                            "uuid": str(uuid),
                            "parentuuid": str(parentuuid),
                            "process_id": pid,
                            "tgid": _subject_tgid(data),
                        }
                    )
                elif "com.bbn.tc.schema.avro.cdm18.FileObject" in event["datum"]:
                    data = event["datum"]["com.bbn.tc.schema.avro.cdm18.FileObject"]
                    uuid = data["uuid"]
                    object_list.append(['2', uuid])
                else:
                    continue
            except Exception as e:
                traceback.print_exc()
                print(line)
        f.close()

    for i in range(len(object_list)):
        if object_list[i][0] == '2':
            object_list[i].append(file_path[object_list[i][1]] if object_list[i][1] in file_path else 'Unknow')
    owner_by_uuid, process_parent_by_owner = _resolve_thread_subject_owners(subject_rows)
    canonical_subject_list = []
    seen_subjects = set()
    for row in subject_rows:
        owner_uuid = owner_by_uuid.get(row["uuid"], row["uuid"])
        if owner_uuid != row["uuid"] or owner_uuid in seen_subjects:
            continue
        parent_uuid = process_parent_by_owner.get(owner_uuid, "Unknow")
        if parent_uuid == owner_uuid:
            parent_uuid = "Unknow"
        canonical_subject_list.append(['1', owner_uuid, parent_uuid, row["process_id"]])
        seen_subjects.add(owner_uuid)
    event_count = _remap_event_subjects(
        event_count,
        {raw_uuid: owner_by_uuid.get(raw_uuid, raw_uuid) for raw_uuid in owner_by_uuid},
    )
    metadata = {
        "raw_subject_to_canonical_node": {
            raw_uuid: owner_by_uuid.get(raw_uuid, raw_uuid)
            for raw_uuid in owner_by_uuid
        },
        "thread_subject_count": int(sum(1 for raw_uuid, owner_uuid in owner_by_uuid.items() if raw_uuid != owner_uuid)),
        "process_subject_count": int(len(canonical_subject_list)),
    }
    return canonical_subject_list, object_list, event_count, metadata


def parser_fivedirections(data_path):
    data_list = os.listdir(data_path)
    event_map = {'EVENT_ACCEPT': 1, 'EVENT_CONNECT': 2, 'EVENT_EXECUTE': 3, 'EVENT_EXIT': 4, 'EVENT_READ': 5,
                 'EVENT_RECVFROM': 6, 'EVENT_RECVMSG': 7, 'EVENT_SENDTO': 8, 'EVENT_SENDMSG': 9, 'EVENT_WRITE': 10}
    subject_list = []
    object_list = []
    event_count = {}

    file_path = {}
    subject_rows = []

    for file in tqdm(data_list, desc=f"Parsing", unit="file"):
        f = open(data_path + file, 'r', encoding='utf-8')
        for line in f:
            line = re.search(r'\{.*\}', line).group(0)
            try:
                event = json.loads(line)
                if "com.bbn.tc.schema.avro.cdm18.Event" in event["datum"]:
                    data = event["datum"]["com.bbn.tc.schema.avro.cdm18.Event"]
                    type = data["type"]
                    if type not in event_map:
                        continue
                    subId = data["subject"]["com.bbn.tc.schema.avro.cdm18.UUID"]
                    if data["predicateObject"] is None:
                        continue
                    objId = data["predicateObject"]["com.bbn.tc.schema.avro.cdm18.UUID"]
                    typeId = event_map[type]
                    key = (typeId, subId, objId)
                    if key in event_count:
                        event_count[key] += 1
                    else:
                        event_count[key] = 1

                    if data['predicateObjectPath'] is not None:
                        file_path[objId] = data['predicateObjectPath']['string']

                elif "com.bbn.tc.schema.avro.cdm18.NetFlowObject" in event["datum"]:
                    data = event["datum"]["com.bbn.tc.schema.avro.cdm18.NetFlowObject"]
                    uuid = data["uuid"]
                    localIP = data["localAddress"]
                    localPort = str(data["localPort"])
                    remoteIP = data["remoteAddress"]
                    remotePort = str(data["remotePort"])
                    object_list.append(['3', uuid, localIP, remoteIP, localPort, remotePort])
                elif "com.bbn.tc.schema.avro.cdm18.Subject" in event["datum"]:
                    data = event["datum"]["com.bbn.tc.schema.avro.cdm18.Subject"]
                    uuid = data["uuid"]
                    parentuuid = _subject_parent_uuid(data)
                    pid = str(data["cid"])
                    subject_rows.append(
                        {
                            "uuid": str(uuid),
                            "parentuuid": str(parentuuid),
                            "process_id": pid,
                            "tgid": _subject_tgid(data),
                        }
                    )
                elif "com.bbn.tc.schema.avro.cdm18.FileObject" in event["datum"]:
                    data = event["datum"]["com.bbn.tc.schema.avro.cdm18.FileObject"]
                    uuid = data["uuid"]
                    object_list.append(['2', uuid])
                else:
                    continue
            except Exception as e:
                traceback.print_exc()
                print(line)
        f.close()
    for i in range(len(object_list)):
        if object_list[i][0] == '2':
            object_list[i].append(file_path[object_list[i][1]] if object_list[i][1] in file_path else 'Unknow')
    owner_by_uuid, process_parent_by_owner = _resolve_thread_subject_owners(subject_rows)
    canonical_subject_list = []
    seen_subjects = set()
    for row in subject_rows:
        owner_uuid = owner_by_uuid.get(row["uuid"], row["uuid"])
        if owner_uuid != row["uuid"] or owner_uuid in seen_subjects:
            continue
        parent_uuid = process_parent_by_owner.get(owner_uuid, "Unknow")
        if parent_uuid == owner_uuid:
            parent_uuid = "Unknow"
        canonical_subject_list.append(['1', owner_uuid, parent_uuid, row["process_id"]])
        seen_subjects.add(owner_uuid)
    event_count = _remap_event_subjects(
        event_count,
        {raw_uuid: owner_by_uuid.get(raw_uuid, raw_uuid) for raw_uuid in owner_by_uuid},
    )
    metadata = {
        "raw_subject_to_canonical_node": {
            raw_uuid: owner_by_uuid.get(raw_uuid, raw_uuid)
            for raw_uuid in owner_by_uuid
        },
        "thread_subject_count": int(sum(1 for raw_uuid, owner_uuid in owner_by_uuid.items() if raw_uuid != owner_uuid)),
        "process_subject_count": int(len(canonical_subject_list)),
    }
    return canonical_subject_list, object_list, event_count, metadata

def parser_trace(data_path):
    data_list=sorted(os.listdir(data_path))
    event_map={'EVENT_RENAME': 1, 'EVENT_CONNECT': 2, 'EVENT_EXECUTE': 3, 'EVENT_EXIT': 4, 'EVENT_READ': 5,
                'EVENT_RECVFROM': 6, 'EVENT_RECVMSG': 7, 'EVENT_SENDTO': 8, 'EVENT_SENDMSG': 9, 'EVENT_WRITE': 10, 'EVENT_CREATE_OBJECT':11}
    subject_list=[]
    object_list=[]
    event_count={}
    subject_rows=[]
    for file in tqdm(data_list, desc=f"Parsing", unit="file"):
        f=open(data_path+file,'r')
        for line in f:
            try:
                event=json.loads(line)
                if "com.bbn.tc.schema.avro.cdm18.Event" in event["datum"]:
                    data=event["datum"]["com.bbn.tc.schema.avro.cdm18.Event"]
                    subject_ref = data.get("subject", {})
                    if not isinstance(subject_ref, dict):
                        continue
                    subId = str(subject_ref.get("com.bbn.tc.schema.avro.cdm18.UUID", "")).strip()
                    if not subId:
                        continue
                    objId=data["predicateObject"]["com.bbn.tc.schema.avro.cdm18.UUID"]
                    type=data["type"]
                    if type not in event_map:
                        continue
                    typeId=event_map[type]
                    key=(typeId,subId,objId)
                    if key in event_count:
                        event_count[key]+=1
                    else:
                        event_count[key]=1
                elif "com.bbn.tc.schema.avro.cdm18.NetFlowObject" in event["datum"]:
                    data=event["datum"]["com.bbn.tc.schema.avro.cdm18.NetFlowObject"]
                    uuid=data["uuid"]
                    localIP=data["localAddress"]
                    localPort=str(data["localPort"])
                    remoteIP=data["remoteAddress"]
                    remotePort=str(data["remotePort"])
                    object_list.append(['3',uuid,localIP,remoteIP,localPort,remotePort])
                elif "com.bbn.tc.schema.avro.cdm18.Subject" in event["datum"]:
                    data=event["datum"]["com.bbn.tc.schema.avro.cdm18.Subject"]
                    uuid=data["uuid"]
                    parentuuid = _subject_parent_uuid(data)
                    cid=str(data["cid"])
                    props = _subject_properties_map(data)
                    path=props["cwd"] if "cwd" in props else ''
                    name=props.get("name", "")
                    subject_rows.append(
                        {
                            "uuid": str(uuid),
                            "parentuuid": str(parentuuid),
                            "process_id": cid,
                            "tgid": _subject_tgid(data),
                            "name": path + '/' + name,
                        }
                    )
                elif "com.bbn.tc.schema.avro.cdm18.FileObject" in event["datum"]:
                    data=event["datum"]["com.bbn.tc.schema.avro.cdm18.FileObject"]
                    uuid=data["uuid"]
                    name=data["baseObject"]["properties"]["map"]["path"]
                    object_list.append(['2',uuid,name])
                else:
                    continue
            except Exception as e:
                traceback.print_exc()
                print(line)
        f.close()
    owner_by_uuid, process_parent_by_owner = _resolve_thread_subject_owners(subject_rows)
    owner_process_id = {}
    owner_name = {}
    for row in subject_rows:
        owner_uuid = owner_by_uuid.get(row["uuid"], row["uuid"])
        if owner_uuid != row["uuid"]:
            continue
        owner_process_id[owner_uuid] = str(row["process_id"])
        owner_name[owner_uuid] = str(row.get("name", ""))

    raw_to_canonical = {
        raw_uuid: owner_process_id.get(owner_by_uuid.get(raw_uuid, raw_uuid), str(raw_uuid))
        for raw_uuid in owner_by_uuid
    }
    event_count = _remap_event_subjects(event_count, raw_to_canonical)

    seen_subjects = set()
    for row in subject_rows:
        owner_uuid = owner_by_uuid.get(row["uuid"], row["uuid"])
        if owner_uuid != row["uuid"] or owner_uuid in seen_subjects:
            continue
        node_id = owner_process_id.get(owner_uuid, str(row["process_id"]))
        parent_owner_uuid = process_parent_by_owner.get(owner_uuid, "Unknow")
        parent_node_id = owner_process_id.get(parent_owner_uuid, "Unknow") if parent_owner_uuid != "Unknow" else "Unknow"
        if parent_node_id == node_id:
            parent_node_id = "Unknow"
        subject_list.append(['1',node_id,parent_node_id,node_id,owner_name.get(owner_uuid, str(row.get("name", "")))])
        seen_subjects.add(owner_uuid)
    metadata = {
        "raw_subject_to_canonical_node": raw_to_canonical,
        "thread_subject_count": int(sum(1 for raw_uuid, owner_uuid in owner_by_uuid.items() if raw_uuid != owner_uuid)),
        "process_subject_count": int(len(subject_list)),
    }
    return subject_list,object_list,event_count,metadata

def compare_address(add1, add2):
    a = 0
    if add1 == add2:
        a = 4
    else:
        if add1 == 'NA' or add2 == 'NA':
            a = 5
        elif add1 == 'NETLINK' or add2 == 'NETLINK':
            a = 6
        elif "." not in add1 or "." not in add2:
            a = 7
        else:
            address1_parts = add1.split('.')
            address2_parts = add2.split('.')
            for i in range(len(address1_parts)):
                if address1_parts[i] != address2_parts[i]:
                    a = i + 1
    return a


def getportcode(port):
    if int(port) < 1024:
        dstpVec = 0
    elif int(port) < 49152:
        dstpVec = 1
    else:
        dstpVec = 2
    return dstpVec


def load_fix(path):
    newdict = {}
    with open(path, 'r') as file:
        for line in file:
            if line:
                line = line.strip().split("#")
                newdict.update({line[0]: line[1]})
    return newdict


def _to_seconds_like(value):
    if value is None:
        return None
    if isinstance(value, (int, float)):
        raw = float(value)
    else:
        text = str(value).strip()
        if text == "":
            return None
        if re.fullmatch(r"[-+]?\d+(\.\d+)?", text):
            raw = float(text)
        else:
            normalized = text.replace("Z", "+00:00")
            try:
                dt = datetime.fromisoformat(normalized)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.timestamp()
            except ValueError:
                return None
    digits = len(str(int(abs(raw)))) if raw != 0 else 1
    if digits >= 18:
        return raw / 1e9
    if digits >= 15:
        return raw / 1e6
    if digits >= 12:
        return raw / 1e3
    return raw


def _event_timestamp_seconds(event_data):
    if not isinstance(event_data, dict):
        return None
    return _to_seconds_like(
        event_data.get('timestampNanos')
        or event_data.get('timestampMicros')
        or event_data.get('timestampMillis')
        or event_data.get('timestamp')
    )


def _update_subject_time_range(subject_time_ranges, subject_uuid, timestamp_sec):
    if subject_uuid in (None, "") or timestamp_sec is None:
        return
    key = str(subject_uuid)
    current = subject_time_ranges.get(key)
    if current is None:
        subject_time_ranges[key] = [float(timestamp_sec), float(timestamp_sec), 1]
        return
    if timestamp_sec < current[0]:
        current[0] = float(timestamp_sec)
    if timestamp_sec > current[1]:
        current[1] = float(timestamp_sec)
    current[2] = int(current[2]) + 1


def encode_cadets(sub_list, obj_list, event_list):
    sys_path_dict = load_fix('./data/linux_system_path.txt')
    file_type_dict = load_fix('./data/linux_file_type.txt')

    sub_list_hat = {}
    obj_list_hat = {}

    for sub in sub_list:
        if sub[3] == "Unknown":
            sub[3] = '0'
    for obj in obj_list:
        if obj[0] == '2':
            index = 90
            max_length = 0
            for match in sys_path_dict.keys():
                if obj[2].startswith(match) and len(match) > max_length:
                    max_length = len(match)
                    index = int(sys_path_dict[match]) + 10
            else:
                last_part = obj[2].rsplit('/', 1)[-1]
                filetypeVec = 0
                if 'python' not in last_part and '.' in last_part:
                    output = last_part.split('.', 1)[-1]
                    if 'so' in output:
                        output = 'so'
                    if '.' in output:
                        output = last_part.rsplit('.', 1)[-1]
                    if output in file_type_dict.keys():
                        filetypeVec = int(file_type_dict[output]) + 1
                    else:
                        filetypeVec = 0
            obj_list_hat[obj[1]] = ['2', str(index), str(filetypeVec), '0']
        elif obj[0] == '3':
            location = compare_address(obj[2], obj[3])
            srcp = getportcode(obj[4])
            dstp = getportcode(obj[5])
            obj_list_hat[obj[1]] = ['3', str(location), str(srcp), str(dstp)]
        else:
            continue

    for eve in event_list:
        if eve[2] in obj_list_hat:
            # print(eve)
            if eve[1] not in sub_list_hat:
                sub_list_hat[eve[1]] = []
            sub_list_hat[eve[1]].append([eve[0], event_list[eve]] + obj_list_hat[eve[2]])

    return sub_list_hat


def encode_fivedirections(sub_list, obj_list, event_list):
    sys_path_dict = load_fix('./data/windows_system_path.txt')
    file_type_dict = load_fix('./data/windows_file_type.txt')

    sub_list_hat = {}
    obj_list_hat = {}

    for sub in sub_list:
        if sub[3] == "Unknown":
            sub[3] = '0'

    for obj in obj_list:
        if obj[0] == '2':
            index = 90
            max_length = 0
            for match in sys_path_dict.keys():
                if obj[2].startswith(match) and len(match) > max_length:
                    max_length = len(match)
                    index = int(sys_path_dict[match]) + 1
            else:
                last_part = obj[2].rsplit('\\', 1)[-1]
                filetypeVec = 0
                if 'python' not in last_part and '.' in last_part:
                    output = last_part.split('.', 1)[-1]
                    if 'so' in output:
                        output = 'so'
                    if '.' in output:
                        output = last_part.rsplit('.', 1)[-1]
                    if output in file_type_dict.keys():
                        filetypeVec = int(file_type_dict[output]) + 1
                    else:
                        filetypeVec = 0
            obj_list_hat[obj[1]] = ['2', str(index), str(filetypeVec), '0']
        elif obj[0] == '3':
            location = compare_address(obj[2], obj[3])
            srcp = getportcode(obj[4])
            dstp = getportcode(obj[5])
            obj_list_hat[obj[1]] = ['3', str(location), str(srcp), str(dstp)]
        else:
            continue

    for eve in event_list:
        if eve[2] in obj_list_hat:
            # print(eve)
            if eve[1] not in sub_list_hat:
                sub_list_hat[eve[1]] = []
            sub_list_hat[eve[1]].append([eve[0], event_list[eve]] + obj_list_hat[eve[2]])

    return sub_list_hat


def encode_trace(sub_list, obj_list, event_list):
    sys_path_dict = load_fix('./data/linux_system_path.txt')
    file_type_dict = load_fix('./data/linux_file_type.txt')

    sub_list_hat = {}
    obj_list_hat = {}

    for sub in sub_list:
        index = 90
        max_length = 0
        for match in sys_path_dict.keys():
            if sub[4].startswith(match) and len(match) > max_length:
                max_length = len(match)
                index = int(sys_path_dict[match]) + 1
            if sub[3] == "Unknown":
                sub[3] = '0'

    for obj in obj_list:
        if obj[0] == '2':
            index = 90
            max_length = 0
            for match in sys_path_dict.keys():
                if obj[2].startswith(match) and len(match) > max_length:
                    max_length = len(match)
                    index = int(sys_path_dict[match]) + 1
            else:
                last_part = obj[2].rsplit('/', 1)[-1]
                filetypeVec = 0
                if 'python' not in last_part and '.' in last_part:
                    output = last_part.split('.', 1)[-1]
                    if 'so' in output:
                        output = 'so'
                    if '.' in output:
                        output = last_part.rsplit('.', 1)[-1]
                    if output in file_type_dict.keys():
                        filetypeVec = int(file_type_dict[output]) + 1
                    else:
                        filetypeVec = 0
            obj_list_hat[obj[1]] = ['2', str(index), str(filetypeVec), '0']
        elif obj[0] == '3':
            location = compare_address(obj[2], obj[3])
            srcp = getportcode(obj[4])
            dstp = getportcode(obj[5])
            obj_list_hat[obj[1]] = ['3', str(location), str(srcp), str(dstp)]
        else:
            continue

    for eve in event_list:
        if eve[2] in obj_list_hat:
            # print(eve)
            if eve[1] not in sub_list_hat:
                sub_list_hat[eve[1]] = []
            sub_list_hat[eve[1]].append([eve[0], event_list[eve]] + obj_list_hat[eve[2]])

    return sub_list_hat

def filters(
        data_path,
        return_task_components=False,
        child_threshold=2,
        split_mode="fanout",
        count_segmented_children_upstream=False,
):
    data_list=os.listdir(data_path)
    syspath = './data/linux_system_path.txt'
    filetypepath = './data/linux_file_type.txt'
    aimevetype = {'EVENT_ACCEPT': 1, 'EVENT_CONNECT': 2, 'EVENT_EXECUTE': 3, 'EVENT_EXIT': 4, 'EVENT_READ': 5,
                  'EVENT_RECVFROM': 6, 'EVENT_RECVMSG': 7, 'EVENT_SENDTO': 8, 'EVENT_SENDMSG': 9, 'EVENT_WRITE': 10}

    syspathdict = load_fix(syspath)
    filetypedict = load_fix(filetypepath)
    events_seen = {}
    objvec = {}
    subjhistory = {}
    raw_subject_time_ranges = {}
    tgiddict = {}
    subjswap = {}
    subject_seen = set()
    subjhisvec = {}
    padict = {}
    chdict = {}
    for file in tqdm(data_list, desc=f"Parsing", unit="file"):
        with open(data_path + file, 'r', encoding='utf-8') as f:
            for line in f:
                js = json.loads(line)
                if 'com.bbn.tc.schema.avro.cdm18.Event' in js['datum']:
                    event_data = js['datum']['com.bbn.tc.schema.avro.cdm18.Event']
                    subject_ref = event_data.get('subject', {})
                    if isinstance(subject_ref, dict):
                        _update_subject_time_range(
                            raw_subject_time_ranges,
                            subject_ref.get('com.bbn.tc.schema.avro.cdm18.UUID'),
                            _event_timestamp_seconds(event_data),
                        )
                    event_type = event_data['type']
                    if event_type in aimevetype:
                        eveid = aimevetype[event_type]
                        subject_uuid = event_data['subject']['com.bbn.tc.schema.avro.cdm18.UUID']
                        object_uuid = event_data['predicateObject'][
                            'com.bbn.tc.schema.avro.cdm18.UUID']
                        if subject_uuid in subjswap.keys():
                            subject_uuid = subjswap[subject_uuid]
                        key = tuple([eveid, subject_uuid, object_uuid])
                        ''''''
                        if key not in events_seen:
                            events_seen[key] = 1
                        else:
                            events_seen[key] = events_seen[key] + 1

                    else:
                        continue

                else:
                    output = ""
                    if 'com.bbn.tc.schema.avro.cdm18.Subject' in js['datum']:
                        subject_data = js['datum']['com.bbn.tc.schema.avro.cdm18.Subject']
                        subjectuuid = subject_data['uuid']
                        parentuuid = subject_data['parentSubject']['com.bbn.tc.schema.avro.cdm18.UUID']
                        subject_seen.add(subjectuuid)
                        subtgid = "Unknown"
                        if "tgid" in subject_data['properties']['map']:
                            subtgid = subject_data['properties']['map']['tgid']

                        subpath = "Unknown"
                        if "path" in subject_data['properties']['map']:
                            subpath = subject_data['properties']['map']['path']

                        tup = (parentuuid, subtgid, subpath)
                        if str(tup) in tgiddict.keys():
                            subjswap[subjectuuid] = tgiddict[str(tup)]
                            subjectuuid = tgiddict[str(tup)]
                        else:
                            tgiddict[str(tup)] = subjectuuid
                        if parentuuid == 'Unknow':
                            continue
                        if subjectuuid in chdict:
                            if chdict[subjectuuid] == parentuuid:
                                continue
                            else:
                                nearpare = chdict[subjectuuid]
                                if nearpare in padict:
                                    if len(padict[nearpare]) == 1:
                                        if padict[nearpare][0] == subjectuuid:
                                            padict.pop(nearpare)
                                        else:
                                            continue
                                    else:
                                        padict[nearpare].remove(subjectuuid)

                                    if parentuuid in padict:
                                        padict[parentuuid].append(subjectuuid)
                                    else:
                                        padict[parentuuid] = [subjectuuid]
                                    chdict[subjectuuid] = parentuuid
                        else:
                            chdict[subjectuuid] = parentuuid
                            if parentuuid in padict:
                                padict[parentuuid].append(subjectuuid)
                            else:
                                padict[parentuuid] = [subjectuuid]



                    elif 'com.bbn.tc.schema.avro.cdm18.FileObject' in js['datum']:
                        subject_data = js['datum']['com.bbn.tc.schema.avro.cdm18.FileObject']
                        if 'baseObject' in subject_data and 'properties' in subject_data['baseObject'] and 'map' in \
                                subject_data['baseObject']['properties']:
                            map_data = subject_data['baseObject']['properties']['map']
                            if 'filename' in map_data:
                                filename = map_data['filename']
                            else:
                                filename = "Unknown"
                            if 'dev' in map_data:
                                dev = map_data['dev']
                                if len(dev) > 5 or not dev.isdigit():
                                    dev = "Unknown"
                            else:
                                dev = "Unknown"

                            max_length = 0
                            subpathVec = 90
                            for match in syspathdict.keys():
                                if filename.startswith(match) and len(match) > max_length:
                                    max_length = len(match)
                                    subpathVec = int(syspathdict[match]) + 1

                            if filename == "Unknown":
                                filetypeVec = 0
                            else:
                                last_part = filename.rsplit('/', 1)[-1]
                                filetypeVec = 0
                                if 'python' not in last_part and '.' in last_part:
                                    output = last_part.split('.', 1)[-1]
                                    if 'so' in output:
                                        output = 'so'
                                    if '.' in output:
                                        output = last_part.rsplit('.', 1)[-1]
                                    if output in filetypedict.keys():
                                        filetypeVec = int(filetypedict[output]) + 1
                                    else:
                                        filetypeVec = 0

                            if len(dev) > 5 or "Unknown" in dev or "/" in dev or "con" in dev or "Empty" in dev or "Labs" in dev or "with" in dev:
                                devvec = "0"
                            else:
                                devvec = dev

                            objvec[subject_data['uuid']] = ["2", str(subpathVec), str(filetypeVec), str(devvec)]
                        else:
                            continue

                    elif 'com.bbn.tc.schema.avro.cdm18.NetFlowObject' in js['datum']:
                        subject_data = js['datum']['com.bbn.tc.schema.avro.cdm18.NetFlowObject']
                        localAddress = subject_data['localAddress']
                        localPort = subject_data['localPort']
                        remoteAddress = subject_data['remoteAddress']
                        remotePort = subject_data['remotePort']
                        if localPort is None:
                            localPort = "1024"
                        if remotePort is None:
                            remotePort = "1024"
                        if localAddress == "":
                            localAddress = "unknown"
                        if remoteAddress == "":
                            remoteAddress = "unknown"

                        location = compare_address(localAddress, remoteAddress)
                        srcp = getportcode(localPort)
                        dstp = getportcode(remotePort)
                        objvec[subject_data['uuid']] = ["3", str(location), str(srcp), str(dstp)]
                    else:
                        continue
    task_components = None
    segmented = set()
    if return_task_components:
        segmented = _resolve_segmented_nodes(
            padict,
            chdict,
            child_threshold=child_threshold,
            split_mode=split_mode,
            count_segmented_children_upstream=count_segmented_children_upstream,
        )
        task_components = _build_task_components(padict, chdict, segmented, split_mode=split_mode)
        task_component_diagnostics = _build_task_component_diagnostics(
            padict,
            chdict,
            task_components,
            segmented,
            child_threshold=child_threshold,
            split_mode=split_mode,
            count_segmented_children_upstream=count_segmented_children_upstream,
        )
    else:
        task_component_diagnostics = []

    canonical_subject_time_ranges = None
    if return_task_components:
        canonical_subject_time_ranges = {}
        for raw_uuid, value in raw_subject_time_ranges.items():
            canonical_uuid = subjswap.get(raw_uuid, raw_uuid)
            current = canonical_subject_time_ranges.get(canonical_uuid)
            if current is None:
                canonical_subject_time_ranges[canonical_uuid] = [
                    float(value[0]),
                    float(value[1]),
                    int(value[2]),
                ]
            else:
                if value[0] < current[0]:
                    current[0] = float(value[0])
                if value[1] > current[1]:
                    current[1] = float(value[1])
                current[2] = int(current[2]) + int(value[2])

    del tgiddict
    del subjswap
    del chdict
    gc.collect()

    for event, num in events_seen.items():
        if event[2] not in objvec:
            continue
        evevec = [str(event[0]), str(num)] + objvec[event[2]]
        if event[1] in subjhistory:
            subjhistory[event[1]].append(evevec)
        else:
            subjhistory[event[1]] = [evevec]

    del events_seen
    del objvec
    gc.collect()

    for key in list(padict.keys()):
        filtered_children = []
        for xvalue in padict[key]:
            if xvalue in padict:
                continue
            filtered_children.append(xvalue)
        padict[key] = filtered_children
    chi_pa = []
    for key, value in padict.items():
        for var in value:
            if var != 'Unknow':
                chi_pa.append([str(key), str(var)])

    LSTMmodel = LSTM(6, 256, 6)
    LSTMmodel.load_state_dict(torch.load('./model/stackedlstm_tc.pt'))
    LSTMmodel.to(device)
    LSTMmodel.eval()
    for subj in tqdm(subjhistory, desc=f"Getting node vector:", unit="node"):
        history = subjhistory[subj]
        data = []
        for eve in history:
            eve = [float(x) for x in eve]
            data.append(eve)
        if len(data) < 1:
            subjhisvec[subj] = [0.0] * 42
        else:
            train_x_tensor = torch.tensor(np.array([data]), dtype=torch.float32).to(device)
            h_n = LSTMmodel(train_x_tensor)
            # vec = h_n[0]
            vec = torch.Tensor.tolist(h_n)
            subjhisvec[subj] = vec

    del subjhistory
    del subject_seen
    gc.collect()

    if return_task_components:
        return {
            'edge_list': chi_pa,
            'task_components': task_components or [],
            'segmented_nodes': sorted(segmented),
            'child_threshold': int(child_threshold),
            'split_mode': str(split_mode),
            'count_segmented_children_upstream': bool(count_segmented_children_upstream),
            'task_component_diagnostics': task_component_diagnostics,
            'subject_time_ranges': {
                str(subject_uuid): {
                    'first_timestamp_sec': float(value[0]),
                    'last_timestamp_sec': float(value[1]),
                    'event_count': int(value[2]),
                }
                for subject_uuid, value in (canonical_subject_time_ranges or {}).items()
            },
        }, subjhisvec
    return chi_pa, subjhisvec

def cut_task(
        subject_list,
        return_task_components=False,
        child_threshold=2,
        split_mode="fanout",
        count_segmented_children_upstream=False,
):
    return _cut_task(
        subject_list,
        return_task_components=return_task_components,
        child_threshold=child_threshold,
        split_mode=split_mode,
        count_segmented_children_upstream=count_segmented_children_upstream,
    )


def _normalize_task_maps(subject_list):
    padict = {}
    chdict = {}
    for var in subject_list:
        subj = var[1]
        pare = var[2]
        if pare == 'Unknow':
            continue
        if subj in chdict:
            if chdict[subj] == pare:
                continue
            else:
                nearpare = chdict[subj]
                if nearpare not in padict:
                    continue
                if len(padict[nearpare]) == 1:
                    if padict[nearpare][0] == subj:
                        padict.pop(nearpare)
                    else:
                        continue
                else:
                    if subj in padict[nearpare]:
                        padict[nearpare].remove(subj)

                if pare in padict:
                    padict[pare].append(subj)
                else:
                    padict[pare] = [subj]
                chdict[subj] = pare
        else:
            chdict[subj] = pare
            if pare in padict:
                padict[pare].append(subj)
            else:
                padict[pare] = [subj]
    for key in list(padict.keys()):
        filtered = []
        seen = set()
        for child in padict[key]:
            if child == 'Unknow':
                continue
            if child in seen:
                continue
            seen.add(child)
            filtered.append(child)
        if filtered:
            padict[key] = filtered
        else:
            padict.pop(key, None)
    return padict, chdict


def _resolve_segmented_nodes(
        padict,
        chdict,
        child_threshold=2,
        split_mode="fanout",
        count_segmented_children_upstream=False,
):
    if split_mode == "connected":
        return set()
    if split_mode != "fanout":
        raise ValueError(f"Unsupported split_mode: {split_mode}")
    segmented = set()
    candidate_nodes = [
        node
        for node, parent in chdict.items()
        if parent not in (None, 'Unknow')
    ]
    while True:
        next_segmented = set()
        for node in candidate_nodes:
            children = padict.get(node, [])
            if count_segmented_children_upstream:
                effective_children = len(children)
            else:
                effective_children = sum(1 for child in children if child not in segmented)
            if effective_children > child_threshold:
                next_segmented.add(node)
        if next_segmented == segmented:
            return segmented
        segmented = next_segmented


def _build_task_component_diagnostics(
        padict,
        chdict,
        components,
        segmented,
        child_threshold=2,
        split_mode="fanout",
        count_segmented_children_upstream=False,
):
    diagnostics = []
    segmented_nodes = set(segmented)
    for component in components:
        task_root = component.get('task_root')
        children = list(padict.get(task_root, []))
        if count_segmented_children_upstream:
            effective_children = len(children)
        else:
            effective_children = sum(1 for child in children if child not in segmented_nodes)
        diagnostics.append(
            {
                'task_root': task_root,
                'task_size': len(component.get('nodes', [])),
                'internal_edge_count': len(component.get('edges', [])),
                'boundary_node_count': len(component.get('boundary_nodes', [])),
                'task_root_total_children': len(children),
                'task_root_effective_children': int(effective_children),
                'task_root_segmented': bool(task_root in segmented_nodes),
                'task_root_parent_missing': chdict.get(task_root) in (None, 'Unknow'),
                'child_threshold': int(child_threshold),
                'split_mode': str(split_mode),
                'count_segmented_children_upstream': bool(count_segmented_children_upstream),
            }
        )
    return diagnostics


def _build_task_components(padict, chdict, segmented, split_mode="fanout"):
    all_nodes = set(chdict.keys()) | set(padict.keys())
    for children in padict.values():
        all_nodes.update(children)
    if split_mode == "connected":
        adjacency = {}
        for node in all_nodes:
            adjacency.setdefault(node, set())
        for parent, children in padict.items():
            adjacency.setdefault(parent, set())
            for child in children:
                adjacency.setdefault(child, set())
                adjacency[parent].add(child)
                adjacency[child].add(parent)

        components = []
        visited = set()
        for start in sorted(all_nodes):
            if start in visited:
                continue
            stack = [start]
            visited.add(start)
            node_order = []
            node_seen = set()
            edge_order = []
            edge_seen = set()
            while stack:
                node = stack.pop()
                if node not in node_seen:
                    node_seen.add(node)
                    node_order.append(node)
                for neigh in sorted(adjacency.get(node, []), reverse=True):
                    edge_key = tuple(sorted((node, neigh)))
                    if edge_key not in edge_seen:
                        edge_seen.add(edge_key)
                        parent, child = (node, neigh) if chdict.get(neigh) == node else (neigh, node)
                        edge_order.append([parent, child])
                    if neigh in visited:
                        continue
                    visited.add(neigh)
                    stack.append(neigh)
            if len(node_order) < 2 or len(edge_order) == 0:
                continue
            components.append(
                {
                    'task_root': start,
                    'nodes': node_order,
                    'edges': edge_order,
                    'boundary_nodes': [],
                }
            )
        return components
    roots = sorted(
        node
        for node in all_nodes
        if node not in chdict or chdict.get(node) in (None, 'Unknow')
    )
    task_roots = []
    seen_roots = set()
    for node in roots:
        if node in seen_roots:
            continue
        seen_roots.add(node)
        task_roots.append(node)
    for node in sorted(segmented):
        if node not in seen_roots:
            seen_roots.add(node)
            task_roots.append(node)

    components = []

    def walk(root):
        node_order = []
        visited_nodes = set()
        edge_order = []
        edge_seen = set()

        def dfs(node):
            if node not in visited_nodes:
                visited_nodes.add(node)
                node_order.append(node)
            for child in sorted(padict.get(node, [])):
                if child not in visited_nodes:
                    visited_nodes.add(child)
                    node_order.append(child)
                edge = (node, child)
                if edge not in edge_seen:
                    edge_seen.add(edge)
                    edge_order.append([node, child])
                if child in segmented:
                    continue
                dfs(child)

        dfs(root)
        boundary_nodes = sorted(
            node
            for node in node_order
            if node in segmented
        )
        return {
            'task_root': root,
            'nodes': node_order,
            'edges': edge_order,
            'boundary_nodes': boundary_nodes,
        }

    for root in task_roots:
        component = walk(root)
        if len(component['nodes']) < 2 or len(component['edges']) == 0:
            continue
        components.append(component)

    return components


def _cut_task(
        subject_list,
        return_task_components=False,
        child_threshold=2,
        split_mode="fanout",
        count_segmented_children_upstream=False,
):
    padict, chdict = _normalize_task_maps(subject_list)
    segmented = _resolve_segmented_nodes(
        padict,
        chdict,
        child_threshold=child_threshold,
        split_mode=split_mode,
        count_segmented_children_upstream=count_segmented_children_upstream,
    )
    components = _build_task_components(padict, chdict, segmented, split_mode=split_mode)
    task_component_diagnostics = _build_task_component_diagnostics(
        padict,
        chdict,
        components,
        segmented,
        child_threshold=child_threshold,
        split_mode=split_mode,
        count_segmented_children_upstream=count_segmented_children_upstream,
    )

    edge_seen = set()
    chi_pa = []
    for component in components:
        for edge in component['edges']:
            edge_key = (edge[0], edge[1])
            if edge_key in edge_seen:
                continue
            edge_seen.add(edge_key)
            chi_pa.append([edge[0], edge[1]])
    if return_task_components:
        return {
            'edge_list': chi_pa,
            'task_components': components,
            'segmented_nodes': sorted(segmented),
            'child_threshold': int(child_threshold),
            'split_mode': str(split_mode),
            'count_segmented_children_upstream': bool(count_segmented_children_upstream),
            'task_component_diagnostics': task_component_diagnostics,
        }
    return chi_pa


class LSTM(nn.Module):
    def __init__(
            self,
            input_size,
            batch_size,
            output_size
    ):
        super().__init__()
        self.input_size = input_size
        self.output_size = output_size
        self.num_directions = 1
        self.batch_size = batch_size
        self.lstm0 = nn.LSTMCell(input_size, hidden_size=16)
        self.gru = nn.GRUCell(input_size=16, hidden_size=10)
        self.dropout = nn.Dropout(p=0.4)
        self.linear = nn.Linear(10, output_size)

    def forward(self, input_seq):
        batch_size, seq_len = input_seq.shape[0], input_seq.shape[1]
        # batch_size, hidden_size
        c_l0 = torch.zeros(batch_size, 16).to(device)
        h_l0 = torch.zeros(batch_size, 16).to(device)
        h_l1 = torch.zeros(batch_size, 10).to(device)
        output = []
        for t in range(seq_len):
            h_l0, c_l0 = self.lstm0(input_seq[:, t, :], (h_l0, c_l0))
            h_l0, c_l0 = self.dropout(h_l0), self.dropout(c_l0)
            h_l1 = self.gru(h_l0, h_l1)
            h_l1 = self.dropout(h_l1)
            output.append(h_l1)
        output = output[-1]
        pred = self.linear(output[-1])
        result = torch.cat([h_l0[-1], c_l0[-1], h_l1[-1]], dim=0)
        return result


def get_node_vec(subjhistory):
    subjhisvec = []
    LSTMmodel = LSTM(6, 256, 6)
    LSTMmodel.load_state_dict(torch.load('./model/stackedlstm_tc.pt'))
    LSTMmodel.to(device)
    LSTMmodel.eval()
    for subj in tqdm(subjhistory, desc=f"Getting node vector:", unit="node"):
        history = subjhistory[subj]
        data = []
        for eve in history:
            eve = [float(x) for x in eve]
            data.append(eve)
        if len(data) < 1:
            subjhisvec.append([subj] + [0.0] * 42)
        else:
            train_x_tensor = torch.tensor(np.array([data]), dtype=torch.float32).to(device)
            h_n = LSTMmodel(train_x_tensor)
            #vec = h_n[0]
            vec = torch.Tensor.tolist(h_n)
            subjhisvec.append([subj] + vec)
    return subjhisvec


def decompose(edgeList, nodeVec, onedataname, canonical_ground_truth=None):
    if isinstance(edgeList, dict) and 'task_components' in edgeList:
        return _decompose_task_components(edgeList['task_components'], nodeVec, onedataname)
    if isinstance(nodeVec, list):
        nodeVec = {
            str(row[0]): [float(x) for x in row[1:]]
            for row in nodeVec
            if isinstance(row, (list, tuple)) and len(row) >= 43
        }
    nodeList = set()
    for line in edgeList:
        nodeList.add(line[0])
        nodeList.add(line[1])
    father = {}
    for node in nodeList:
        father[node] = node

    def find(x):
        root = x
        while root != father[root]:
            root = father[root]
        while x != root:
            next_node = father[x]
            father[x] = root
            x = next_node
        return root

    def union(x, y):
        father[find(x)] = find(y)

    for edge in edgeList:
        union(edge[0], edge[1])

    node_map = collections.defaultdict(list)
    edge_map = collections.defaultdict(list)
    for node in nodeList:
        root = find(node)
        node_map[root].append(node)
    for edge in edgeList:
        root = find(edge[0])
        edge_map[root].append(edge)

    graphList = []
    for key in node_map:
        if len(edge_map[key]) == 0:
            continue
        graphList.append([node_map[key], edge_map[key]])

    attackNode = set()
    if canonical_ground_truth is None:
        f = open('./groundtruth/{}.txt'.format(onedataname), 'r')
        for line in f:
            attackNode.add(line.strip())
    else:
        attackNode = {str(item).strip() for item in canonical_ground_truth if str(item).strip()}

    data = []
    attack_graph = 0
    for graph in graphList:
        label = 0
        attacknum = 0
        nodenum = 0
        nodeId = {}

        node_list_hat = []
        edge_list_hat = []

        for node in graph[0]:
            if node in attackNode:
                attacknum += 1
                label = 1
            if node not in nodeId:
                nodeId[node] = nodenum
                nodenum += 1
            vec = nodeVec.get(str(node), [0.0] * 42)
            node_list_hat.append(vec)
        for edge in graph[1]:
            if edge[0] in nodeId and edge[1] in nodeId:
                edge_list_hat.append([nodeId[edge[0]], nodeId[edge[1]]])
        attack_graph += label
        if len(node_list_hat) < 2:
            continue
        data.append({
            'nodes': node_list_hat,
            'edges': edge_list_hat,
            'label': label,
            'attacknum': attacknum
        })
    return data


def _decompose_task_components(task_components, nodeVec, onedataname):
    if isinstance(nodeVec, list):
        nodeVec = {
            str(row[0]): [float(x) for x in row[1:]]
            for row in nodeVec
            if isinstance(row, (list, tuple)) and len(row) >= 43
        }
    attackNode = set()
    f = open('./groundtruth/{}.txt'.format(onedataname), 'r')
    for line in f:
        attackNode.add(line.strip())

    data = []
    for component in task_components:
        label = 0
        attacknum = 0
        nodenum = 0
        nodeId = {}
        node_list_hat = []
        edge_list_hat = []

        for node in component.get('nodes', []):
            if node in attackNode:
                attacknum += 1
                label = 1
            if node not in nodeId:
                nodeId[node] = nodenum
                nodenum += 1
            vec = nodeVec.get(str(node), [0.0] * 42)
            node_list_hat.append(vec)
        for edge in component.get('edges', []):
            if edge[0] in nodeId and edge[1] in nodeId:
                edge_list_hat.append([nodeId[edge[0]], nodeId[edge[1]]])
        if len(node_list_hat) < 2 or len(edge_list_hat) == 0:
            continue
        data.append({
            'nodes': node_list_hat,
            'edges': edge_list_hat,
            'label': label,
            'attacknum': attacknum
        })
    return data


class LSTM_GRU_HAT(nn.Module):
    def __init__(
            self,
            input_size,
            batch_size,
            output_size
    ):
        super().__init__()
        self.input_size = input_size
        self.output_size = output_size
        self.num_directions = 1
        self.batch_size = batch_size
        self.lstm0 = nn.LSTMCell(input_size, hidden_size=16)
        self.gru = nn.GRUCell(input_size=16, hidden_size=10)
        self.dropout = nn.Dropout(p=0.4)
        self.linear = nn.Linear(10, output_size)

    def forward(self, input_seq, hidden):
        batch_size, seq_len = input_seq.shape[0], input_seq.shape[1]
        # batch_size, hidden_size
        h_l0 = torch.zeros(batch_size, 16).to(device)
        c_l0 = torch.zeros(batch_size, 16).to(device)
        h_l1 = torch.zeros(batch_size, 10).to(device)
        if hidden != None:
            h_l0 = hidden[:,0:16].to(device)
            c_l0 = hidden[:,16:32].to(device)
            h_l1 = hidden[:,32:].to(device)
        output = []
        # for t in range(seq_len):
        # h_l0, c_l0 = self.lstm0(input_seq[:, t, :], (h_l0, c_l0))
        h_l0, c_l0 = self.lstm0(input_seq, (h_l0, c_l0))
        h_l0, c_l0 = self.dropout(h_l0), self.dropout(c_l0)
        h_l1 = self.gru(h_l0, h_l1)
        h_l1 = self.dropout(h_l1)
        output.append(h_l1)
        pred = self.linear(output[-1])
        result = torch.cat([h_l0[-1], c_l0[-1], h_l1[-1]], dim=0)
        return result


def dataenhance(x, addnum, onedataname):
    LSTMmodel = LSTM_GRU_HAT(6, 256, 6)
    LSTMmodel.load_state_dict(torch.load('./model/stackedlstm_tc.pt'))
    LSTMmodel.to(device)
    LSTMmodel.eval()
    addx = []

    benignTop10actdict = {'cadets':[[5, 1, 2, 12, 0, 0], [10, 1, 2, 5, 0, 0], [5, 1, 2, 55, 10, 0], [5, 1, 2, 19, 0, 0], [5, 1, 2, 6, 8, 0],
               [5, 1, 2, 90, 0, 0], [10, 1, 2, 90, 0, 0], [5, 1, 2, 63, 0, 0], [5, 1, 2, 6, 0, 0], [5, 1, 2, 5, 0, 0]],
               'trace':[[7, 1, 3, 4, 1, 0],[10, 1, 2, 5, 0, 0],[5, 1, 2, 63, 0, 0],[7, 1, 3, 4, 1, 1],[5, 1, 2, 21, 0, 0],
                        [5, 1, 2, 6, 0, 0],[7, 1, 2, 5, 0, 0],[10, 1, 2, 36, 0, 0],[5, 1, 2, 68, 0, 0],[5, 1, 2, 36, 0, 0]],
                'theia':[[5, 1, 2, 6, 0, 0],[6, 1, 3, 4, 2, 0],[6, 1, 3, 4, 1, 0],[5, 1, 2, 21, 0, 3],[7, 1, 3, 5, 0, 0],
                         [9, 1, 3, 5, 0, 0],[6, 1, 3, 5, 1, 0],[5, 1, 2, 36, 0, 0],[10, 1, 2, 36, 0, 0],[6, 1, 3, 5, 0, 0]],
                'fivedirections':[[5, 1, 2, 90, 3, 0],[6, 1, 3, 4, 1, 2],[5, 1, 2, 90, 26, 0],[6, 1, 3, 4, 1, 1],[5, 1, 2, 12, 25, 0],
                                  [8, 1, 3, 4, 2, 1],[6, 1, 3, 4, 2, 1],[5, 1, 2, 90, 0, 0],[10, 1, 2, 90, 14, 0],[10, 1, 2, 90, 0, 0]]}
    actlist = benignTop10actdict[onedataname]

    nodenum = len(x) - 1
    for i in range(addnum):
        randomnode = random.randint(0, nodenum)
        randomact = random.randint(0, len(actlist) - 1)
        data = []
        act = actlist[randomact]
        act = [float(x) for x in act]
        data.append(act)
        train_x_tensor = torch.tensor(np.array([act]), dtype=torch.float32).to(device)
        h1 = torch.tensor(np.array(x[randomnode]).reshape(1, 42), dtype=torch.float32).to(device)
        newnodevec = LSTMmodel(train_x_tensor, h1)

        #vec = newnodevec[0]
        #vec = torch.Tensor.tolist(vec[0])
        vec = torch.Tensor.tolist(newnodevec)
        newx = copy.deepcopy(x)
        newx[randomnode] = vec
        addx.append(newx)
    return addx


def data_deal(data_list, onedataname, divisor=2000, bonus=0):
    data_pro = []
    atttack_num = 0
    count = len(data_list)
    for x in data_list:
        if x['label'] == 1:
            if divisor <= 0:
                needadd = 0
            else:
                needadd = max(0, (count // divisor) + bonus)
            atttack_num += needadd
            data_pro.append(copy.deepcopy(x))
            addx = dataenhance(x['nodes'], needadd, onedataname)
            for a in addx:
                data = copy.deepcopy(x)
                data['nodes'] = a
                data_pro.append(data)
        else:
            data_pro.append(copy.deepcopy(x))
    print(f'Total Task:{len(data_pro)}\t Attack Tasks:{atttack_num}')
    return data_pro


class GraphSAGE(torch.nn.Module):
    def __init__(self, input_dim, hidden_dim, output_dim, dropout_p=0.0):
        super(GraphSAGE, self).__init__()
        self.conv1 = SAGEConv(input_dim, hidden_dim)
        self.conv2 = SAGEConv(hidden_dim, hidden_dim)
        # self.conv3 = SAGEConv(hidden_dim, hidden_dim)
        self.lin = Linear(hidden_dim, output_dim)
        self.dropout_p = float(dropout_p)

    def forward(self, x, edge_index, batch):
        x = self.conv1(x, edge_index)
        x = F.relu(x)
        x = self.conv2(x, edge_index)
        x = F.relu(x)
        embedding = global_max_pool(x, batch)
        if self.dropout_p > 0.0:
            embedding = F.dropout(embedding, p=self.dropout_p, training=self.training)
        logits = self.lin(embedding)
        return embedding, logits


class MyOwnDataset(InMemoryDataset):
    def __init__(self, data):
        super().__init__(root='dataset_temp')

        data_list = []
        attack_num = 0
        graphs = data
        for g in graphs:
            x = []
            edge_index = [[], []]
            for node in g['nodes']:
                x.append(node)
            for edge in g['edges']:
                edge_index[0].append(edge[0])
                edge_index[1].append(edge[1])
            x = torch.tensor(x, dtype=torch.float32)
            
            edge_index = torch.tensor(edge_index, dtype=torch.long)
            y = g['label']
            attack_num += y
            data = Data(x=x, edge_index=edge_index, y=y)
            data_list.append(data)
        self.data, self.slices = self.collate(data_list)

    @property
    def raw_file_names(self):
        return []

    @property
    def processed_file_names(self):
        return []

    def download(self):
        pass

    def process(self):
        pass


def eval(model, data_loder, flag):
    model.eval()
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    model.to(device)
    all_preds = []
    all_labels = []
    all_embeddings = []
    for data in data_loder:
        data.to(device)
        em, out = model(data.x, data.edge_index, data.batch)
        pred = out.argmax(dim=1)
        all_preds.append(pred.cpu())
        all_labels.append(data.y.cpu())
        all_embeddings.append(em)
    all_preds = torch.cat(all_preds)
    all_labels = torch.cat(all_labels)
    all_embeddings = torch.cat(all_embeddings)

    accuracy = accuracy_score(all_labels, all_preds)
    precision, recall, f1, _ = precision_recall_fscore_support(all_labels, all_preds, average='macro', zero_division=0)

    print(f"[{flag}]: Accuracy: {accuracy:.4f}, Precision: {precision:.4f}, Recall: {recall:.4f}, F1 Score: {f1:.4f}")


def train(
    params,
    onedataname,
    *,
    class_weight_w0=1.0,
    class_weight_w1=2.0,
    dropout_p=0.0,
    seed=2025,
    train_eval_split=True,
):
    torch.manual_seed(int(seed))
    np.random.seed(int(seed))
    random.seed(int(seed))
    lr, epoch, batchSize = params
    data = torch.load('./data/{}/data.pt'.format(onedataname))
    dataset = MyOwnDataset(data)
    dataset = dataset.shuffle()
    if train_eval_split:
        index = int(0.8 * len(dataset))
        train_data = dataset[0:index]
        test_data = dataset[index:]
    else:
        train_data = dataset
        test_data = None
    train_loader = DataLoader(train_data, batch_size=batchSize, shuffle=True)
    test_loader = DataLoader(test_data, batch_size=batchSize, shuffle=False) if test_data is not None and len(test_data) > 0 else None
    model = GraphSAGE(
        input_dim=dataset.num_features,
        hidden_dim=64,
        output_dim=dataset.num_classes,
        dropout_p=dropout_p,
    )
    print(model)
    model.to(device)
    optimizer = Adam(model.parameters(), lr=lr, weight_decay=5e-4)
    weight = torch.tensor([float(class_weight_w0), float(class_weight_w1)], dtype=torch.float32).to(device)
    criterion = torch.nn.CrossEntropyLoss(weight=weight)

    for e in range(epoch):
        total_loss = 0.0
        model.train()
        for data in train_loader:
            data = data.to(device)
            optimizer.zero_grad()
            _, out = model(data.x, data.edge_index, data.batch)
            loss = criterion(out, data.y)
            loss.backward()
            optimizer.step()
            total_loss += float(loss.detach().item())
        print(f"\nEpoch {e + 1}/{epoch}, Loss: {total_loss:.4f}")
        eval(model, train_loader, 'Train')
        if test_loader is not None:
            eval(model, test_loader, 'Test ')

    torch.save(model, './model/{}.pkl'.format(onedataname))


def get_eval_result(data_name, all_labels, all_preds):
    accuracy = accuracy_score(all_labels, all_preds)
    precision, recall, f1, _ = precision_recall_fscore_support(all_labels, all_preds, average='macro', zero_division=0)

    print(
        f"[{data_name}]:\n\tAccuracy: {accuracy:.4f}\n\tPrecision: {precision:.4f}\n\tRecall: {recall:.4f}\n\tF1 Score: {f1:.4f}")


def eval_final(data_name, model):
    torch.manual_seed(2025)
    dataset = torch.load('./data/{}/data.pt'.format(data_name, data_name), weights_only=False)
    dataset = MyOwnDataset(dataset)
    dataset = dataset.shuffle()
    index = int(0.8 * len(dataset))
    test_data = dataset[index:]
    test_loader = DataLoader(test_data, shuffle=False)
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

    model = torch.load('./model/{}.pkl'.format(model), weights_only=False, map_location=torch.device('cpu'))
    model.to(device)
    model.eval()
    model.to(device)
    all_preds = []
    all_labels = []
    all_embeddings = []
    for data in test_loader:
        data.to(device)
        em, out = model(data.x, data.edge_index, data.batch)
        pred = out.argmax(dim=1)
        all_preds.append(pred.cpu())
        all_labels.append(data.y.cpu())
        all_embeddings.append(em)
    all_preds = torch.cat(all_preds)
    all_labels = torch.cat(all_labels)
    all_embeddings = torch.cat(all_embeddings)

    get_eval_result(data_name, all_labels, all_preds)

if __name__ == "__main__":
    # dataset = ['trace', 'theia', 'fivedirections', 'cadets']
    dataset = ['cadets']
    for dataname in dataset:
        data_path = './data/{}/logs/'.format(dataname)
        if dataname == 'cadets':
            subject_list, object_list, event_count, _ = parser_cadets(data_path)
            subjectnode = encode_cadets(subject_list, object_list, event_count)
            chi_pa = cut_task(subject_list)
            device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
            subvec = get_node_vec(subjectnode)
        elif dataname == 'fivedirections':
            subject_list, object_list, event_count, _ = parser_fivedirections(data_path)
            subjectnode = encode_fivedirections(subject_list, object_list, event_count)
            chi_pa = cut_task(subject_list)
            device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
            subvec = get_node_vec(subjectnode)
        elif dataname == 'theia':
            chi_pa, subvec = filters(data_path)
        else:
            subject_list, object_list, event_count, _ = parser_trace(data_path)
            subjectnode = encode_trace(subject_list, object_list, event_count)
            chi_pa = cut_task(subject_list)
            device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
            subvec = get_node_vec(subjectnode)
        data = decompose(chi_pa, subvec, dataname)
        random.seed(173)
        data = data_deal(data, dataname)
        torch.save(data, './data/{}/data.pt'.format(dataname))
        device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        params = [0.001, 100, 500]
        #if not os.path.exists('./model/cadets.pkl'):
        train(params, dataname)

        eval_final(dataname, dataname)


