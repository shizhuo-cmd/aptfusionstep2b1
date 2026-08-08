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


_CDM_ZERO_UUID = "00000000-0000-0000-0000-000000000000"


def _unwrap_avro_scalar(value):
    """Return a scalar from JSON emitted for an Avro union value."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if not isinstance(value, dict):
        return value
    for key in ("string", "int", "long", "double", "float", "boolean", "bytes"):
        if key in value:
            return _unwrap_avro_scalar(value[key])
    if len(value) == 1:
        return _unwrap_avro_scalar(next(iter(value.values())))
    return None


def _cdm_uuid(value):
    """Read UUIDs from CDM18/19/20 JSON without hard-coding a namespace."""
    if isinstance(value, str):
        return value
    if not isinstance(value, dict):
        return None
    for key, nested in value.items():
        if key == "UUID" or key.endswith(".UUID"):
            scalar = _unwrap_avro_scalar(nested)
            return str(scalar) if scalar is not None else None
    scalar = _unwrap_avro_scalar(value)
    return str(scalar) if scalar is not None else None


def _cdm_datum_payload(record, record_name):
    """Find a datum by its short CDM record name across schema versions."""
    datum = record.get("datum", {}) if isinstance(record, dict) else {}
    if not isinstance(datum, dict):
        return None
    for key, payload in datum.items():
        if key == record_name or key.endswith("." + record_name):
            return payload if isinstance(payload, dict) else None
    return None


def _is_zero_uuid(value):
    return str(value or "").strip().upper() == _CDM_ZERO_UUID


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
        subject_type = str(row.get("subject_type", "")).strip().upper()
        subject_tgid = str(row.get("tgid", "")).strip()
        if parent_uuid in subject_info:
            parent_tgid = str(subject_info[parent_uuid].get("tgid", "")).strip()
            # TRACE emits many SUBJECT_UNIT records for execution units within
            # an existing process.  They inherit the parent process identity;
            # treating their cid as a standalone process creates spurious nodes.
            if subject_type in {"SUBJECT_THREAD", "SUBJECT_UNIT"}:
                owner = resolve_owner(parent_uuid, trail)
            elif subject_tgid and parent_tgid and subject_tgid == parent_tgid:
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


# Stable, dataset-independent labels for the semantic sequence encoder.  These
# labels are intentionally categorical; they are embedded by the new encoder
# rather than treated as continuous legacy TAPAS event IDs.
_SEMANTIC_EVENT_IDS = {
    "PROCESS_CREATE": 1,
    "EXECUTE": 2,
    "PROCESS_EXIT": 3,
    "FILE_OPEN": 4,
    "FILE_READ": 5,
    "FILE_WRITE": 6,
    "FILE_REMOVE_OR_RENAME": 7,
    "FILE_METADATA": 8,
    "NETWORK_CONNECT_OR_ACCEPT": 9,
    "NETWORK_RECEIVE": 10,
    "NETWORK_SEND": 11,
    "PRIVILEGE_CHANGE": 12,
    "MEMORY_CONTROL": 13,
    "IPC_OR_SIGNAL": 14,
    "OTHER": 15,
}


def _semantic_event_id(event_type):
    value = str(event_type or "").upper()
    if value in {"EVENT_FORK", "EVENT_CLONE", "EVENT_VFORK", "EVENT_CREATE_PROCESS"}:
        return _SEMANTIC_EVENT_IDS["PROCESS_CREATE"]
    if value in {"EVENT_EXECUTE", "EVENT_EXECUTE2"}:
        return _SEMANTIC_EVENT_IDS["EXECUTE"]
    if value in {"EVENT_EXIT", "EVENT_EXIT_GROUP"}:
        return _SEMANTIC_EVENT_IDS["PROCESS_EXIT"]
    if value in {"EVENT_OPEN", "EVENT_OPENAT", "EVENT_CLOSE"}:
        return _SEMANTIC_EVENT_IDS["FILE_OPEN"]
    if value in {"EVENT_READ", "EVENT_READV", "EVENT_PREAD", "EVENT_PREAD64"}:
        return _SEMANTIC_EVENT_IDS["FILE_READ"]
    if value in {"EVENT_WRITE", "EVENT_WRITEV", "EVENT_PWRITE", "EVENT_PWRITE64", "EVENT_CREATE_OBJECT"}:
        return _SEMANTIC_EVENT_IDS["FILE_WRITE"]
    if value in {"EVENT_UNLINK", "EVENT_UNLINKAT", "EVENT_RENAME", "EVENT_RENAMEAT"}:
        return _SEMANTIC_EVENT_IDS["FILE_REMOVE_OR_RENAME"]
    if value in {"EVENT_MODIFY_FILE_ATTRIBUTES", "EVENT_CHMOD", "EVENT_CHOWN", "EVENT_TRUNCATE"}:
        return _SEMANTIC_EVENT_IDS["FILE_METADATA"]
    if value in {"EVENT_CONNECT", "EVENT_ACCEPT"}:
        return _SEMANTIC_EVENT_IDS["NETWORK_CONNECT_OR_ACCEPT"]
    if value in {"EVENT_RECVFROM", "EVENT_RECVMSG", "EVENT_RECEIVE"}:
        return _SEMANTIC_EVENT_IDS["NETWORK_RECEIVE"]
    if value in {"EVENT_SENDTO", "EVENT_SENDMSG", "EVENT_SEND"}:
        return _SEMANTIC_EVENT_IDS["NETWORK_SEND"]
    if value in {"EVENT_CHANGE_PRINCIPAL", "EVENT_SETUID", "EVENT_SETGID"}:
        return _SEMANTIC_EVENT_IDS["PRIVILEGE_CHANGE"]
    if value in {"EVENT_MMAP", "EVENT_MPROTECT", "EVENT_MUNMAP"}:
        return _SEMANTIC_EVENT_IDS["MEMORY_CONTROL"]
    if value in {"EVENT_SIGNAL", "EVENT_KILL", "EVENT_SHM", "EVENT_CORRELATION"}:
        return _SEMANTIC_EVENT_IDS["IPC_OR_SIGNAL"]
    return _SEMANTIC_EVENT_IDS["OTHER"]


def _remap_semantic_event_histories(raw_event_counts, raw_to_canonical):
    """Merge compact per-subject semantic histories after thread normalization."""
    remapped = {}
    for key, count in raw_event_counts.items():
        if not isinstance(key, tuple) or len(key) != 2:
            continue
        semantic_id, raw_subject = key
        canonical_subject = str(raw_to_canonical.get(str(raw_subject), raw_subject))
        remapped_key = (int(semantic_id), canonical_subject)
        remapped[remapped_key] = remapped.get(remapped_key, 0) + int(count)
    histories = collections.defaultdict(list)
    for (semantic_id, subject_id), count in remapped.items():
        histories[str(subject_id)].append([int(semantic_id), int(count)])
    return {str(subject_id): history for subject_id, history in histories.items()}

def _cross_subject_object_ids(raw_subject_object_ids, canonical_subject_by_raw, known_object_ids):
    """Keep only objects that can connect two different canonical processes.

    A singleton object can never join two root-child branches, so retaining it
    for the post-segmentation overlap pass only increases memory and scan time.
    """
    first_owner = {}
    shared_object_ids = set()
    for raw_subject_id, object_ids in raw_subject_object_ids.items():
        canonical_subject_id = canonical_subject_by_raw.get(str(raw_subject_id), str(raw_subject_id))
        for object_uuid in object_ids:
            object_uuid = str(object_uuid)
            if object_uuid not in known_object_ids:
                continue
            previous_owner = first_owner.get(object_uuid)
            if previous_owner is None:
                first_owner[object_uuid] = canonical_subject_id
            elif previous_owner != canonical_subject_id:
                shared_object_ids.add(object_uuid)

    if not shared_object_ids:
        return {}
    canonical_subject_object_ids = collections.defaultdict(set)
    for raw_subject_id, object_ids in raw_subject_object_ids.items():
        canonical_subject_id = canonical_subject_by_raw.get(str(raw_subject_id), str(raw_subject_id))
        retained = shared_object_ids.intersection(str(object_uuid) for object_uuid in object_ids)
        if retained:
            canonical_subject_object_ids[canonical_subject_id].update(retained)
    return {
        str(subject_id): sorted(object_ids)
        for subject_id, object_ids in canonical_subject_object_ids.items()
        if object_ids
    }


def parser_cadets(data_path, collect_subject_object_ids=False):
    data_list = os.listdir(data_path)
    event_map = {'EVENT_ACCEPT': 1, 'EVENT_CONNECT': 2, 'EVENT_EXECUTE': 3, 'EVENT_EXIT': 4, 'EVENT_READ': 5,
                 'EVENT_RECVFROM': 6, 'EVENT_RECVMSG': 7, 'EVENT_SENDTO': 8, 'EVENT_SENDMSG': 9, 'EVENT_WRITE': 10}
    subject_list = []
    object_list = []
    event_count = {}
    # Keep a compact per-subject action tally for optional full-event statistics.
    # Unlike event_count, this includes events outside the legacy TAPAS whitelist.
    raw_event_action_counts = collections.defaultdict(collections.Counter)
    raw_event_type_counts = collections.Counter()
    raw_semantic_event_counts = {}
    raw_subject_time_ranges = {}
    raw_execute_object_counts = collections.defaultdict(collections.Counter)
    raw_subject_object_ids = collections.defaultdict(set) if collect_subject_object_ids else None
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
                    raw_event_type_counts[str(type)] += 1
                    subject_ref = data.get("subject")
                    if isinstance(subject_ref, dict):
                        raw_subject_id = subject_ref.get("com.bbn.tc.schema.avro.cdm18.UUID")
                        if raw_subject_id:
                            raw_event_action_counts[str(raw_subject_id)][str(type)] += 1
                            semantic_key = (_semantic_event_id(type), str(raw_subject_id))
                            raw_semantic_event_counts[semantic_key] = raw_semantic_event_counts.get(semantic_key, 0) + 1
                            _update_subject_time_range(
                                raw_subject_time_ranges,
                                raw_subject_id,
                                _event_timestamp_seconds(data),
                            )
                            if str(type) == 'EVENT_EXECUTE':
                                predicate_object = data.get('predicateObject')
                                if isinstance(predicate_object, dict):
                                    object_uuid = predicate_object.get('com.bbn.tc.schema.avro.cdm18.UUID')
                                    if object_uuid:
                                        raw_execute_object_counts[str(raw_subject_id)][str(object_uuid)] += 1
                            if raw_subject_object_ids is not None:
                                for object_field in ('predicateObject', 'predicateObject2'):
                                    object_ref = data.get(object_field)
                                    if isinstance(object_ref, dict):
                                        object_uuid = object_ref.get('com.bbn.tc.schema.avro.cdm18.UUID')
                                        if object_uuid:
                                            raw_subject_object_ids[str(raw_subject_id)].add(str(object_uuid))
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
                            "subject_type": str(data.get("type", "")),
                            "start_timestamp_nanos": int(data.get("startTimestampNanos", 0) or 0),
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
    canonical_event_action_counts = collections.defaultdict(collections.Counter)
    for raw_subject_id, action_counts in raw_event_action_counts.items():
        canonical_subject_id = owner_by_uuid.get(str(raw_subject_id), str(raw_subject_id))
        for action, count in action_counts.items():
            canonical_event_action_counts[canonical_subject_id][str(action)] += int(count)
    canonical_subject_time_ranges = _canonicalize_subject_time_ranges(
        raw_subject_time_ranges,
        {raw_uuid: owner_by_uuid.get(raw_uuid, raw_uuid) for raw_uuid in owner_by_uuid},
    )
    canonical_subject_start_timestamps: dict[str, int] = {}
    for row in subject_rows:
        raw_subject_id = str(row["uuid"])
        canonical_subject_id = owner_by_uuid.get(raw_subject_id, raw_subject_id)
        start_timestamp = int(row.get("start_timestamp_nanos", 0) or 0)
        previous = canonical_subject_start_timestamps.get(canonical_subject_id)
        if previous is None or (start_timestamp > 0 and (previous == 0 or start_timestamp < previous)):
            canonical_subject_start_timestamps[canonical_subject_id] = start_timestamp
    canonical_semantic_event_histories = _remap_semantic_event_histories(
        raw_semantic_event_counts,
        {raw_uuid: owner_by_uuid.get(raw_uuid, raw_uuid) for raw_uuid in owner_by_uuid},
    )
    canonical_execute_targets = collections.defaultdict(collections.Counter)
    for raw_subject_id, object_counts in raw_execute_object_counts.items():
        canonical_subject_id = owner_by_uuid.get(str(raw_subject_id), str(raw_subject_id))
        for object_uuid, count in object_counts.items():
            target_path = str(file_path.get(str(object_uuid), '')).strip()
            if target_path and target_path != 'Unknow':
                canonical_execute_targets[canonical_subject_id][target_path] += int(count)
    known_object_ids = {str(row[1]) for row in object_list if len(row) >= 2}
    canonical_subject_object_ids = (
        _cross_subject_object_ids(
            raw_subject_object_ids,
            {raw_uuid: owner_by_uuid.get(raw_uuid, raw_uuid) for raw_uuid in owner_by_uuid},
            known_object_ids,
        )
        if raw_subject_object_ids is not None
        else {}
    )
    metadata = {
        "raw_subject_to_canonical_node": {
            raw_uuid: owner_by_uuid.get(raw_uuid, raw_uuid)
            for raw_uuid in owner_by_uuid
        },
        "thread_subject_count": int(sum(1 for raw_uuid, owner_uuid in owner_by_uuid.items() if raw_uuid != owner_uuid)),
        "process_subject_count": int(len(canonical_subject_list)),
        "canonical_event_action_counts": {
            str(subject_id): {str(action): int(count) for action, count in action_counts.items()}
            for subject_id, action_counts in canonical_event_action_counts.items()
        },
        "raw_event_type_counts": {str(action): int(count) for action, count in raw_event_type_counts.items()},
        "semantic_event_vocabulary": {name: int(value) for name, value in _SEMANTIC_EVENT_IDS.items()},
        "canonical_semantic_event_histories": canonical_semantic_event_histories,
        "canonical_subject_time_ranges": canonical_subject_time_ranges,
        "canonical_subject_start_timestamps": canonical_subject_start_timestamps,
        "canonical_execute_targets": {
            str(subject_id): {str(path): int(count) for path, count in targets.items()}
            for subject_id, targets in canonical_execute_targets.items()
        },
        "canonical_subject_object_ids": canonical_subject_object_ids,
    }
    metadata["graph_identity_mode"] = "uuid"
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
                            "subject_type": str(data.get("type", "")),
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

def parser_trace(data_path, collect_subject_object_ids=False):
    data_list=sorted(os.listdir(data_path))
    event_map={'EVENT_RENAME': 1, 'EVENT_CONNECT': 2, 'EVENT_EXECUTE': 3, 'EVENT_EXIT': 4, 'EVENT_READ': 5,
                'EVENT_RECVFROM': 6, 'EVENT_RECVMSG': 7, 'EVENT_SENDTO': 8, 'EVENT_SENDMSG': 9, 'EVENT_WRITE': 10, 'EVENT_CREATE_OBJECT':11}
    subject_list=[]
    object_list=[]
    event_count={}
    subject_rows=[]
    raw_subject_time_ranges = {}
    raw_semantic_event_counts = {}
    raw_event_type_counts = collections.Counter()
    raw_event_action_counts = collections.defaultdict(collections.Counter)
    raw_subject_object_ids = collections.defaultdict(set) if collect_subject_object_ids else None
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
                    type=data.get("type", "")
                    raw_event_type_counts[str(type)] += 1
                    raw_event_action_counts[subId][str(type)] += 1
                    semantic_key = (_semantic_event_id(type), subId)
                    raw_semantic_event_counts[semantic_key] = raw_semantic_event_counts.get(semantic_key, 0) + 1
                    _update_subject_time_range(
                        raw_subject_time_ranges,
                        subId,
                        _event_timestamp_seconds(data),
                    )
                    if raw_subject_object_ids is not None:
                        for object_field in ('predicateObject', 'predicateObject2'):
                            object_ref = data.get(object_field)
                            if isinstance(object_ref, dict):
                                object_uuid = object_ref.get('com.bbn.tc.schema.avro.cdm18.UUID')
                                if object_uuid:
                                    raw_subject_object_ids[subId].add(str(object_uuid))
                    predicate_object = data.get("predicateObject")
                    if not isinstance(predicate_object, dict):
                        continue
                    objId=predicate_object.get("com.bbn.tc.schema.avro.cdm18.UUID")
                    if not objId:
                        continue
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
                            "subject_type": str(data.get("type", "")),
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
    canonical_semantic_event_histories = _remap_semantic_event_histories(raw_semantic_event_counts, raw_to_canonical)
    canonical_event_action_counts = collections.defaultdict(collections.Counter)
    for raw_subject_id, action_counts in raw_event_action_counts.items():
        canonical_subject_id = raw_to_canonical.get(str(raw_subject_id), str(raw_subject_id))
        for action, count in action_counts.items():
            canonical_event_action_counts[canonical_subject_id][str(action)] += int(count)
    known_object_ids = {str(row[1]) for row in object_list if len(row) >= 2}
    canonical_subject_object_ids = (
        _cross_subject_object_ids(raw_subject_object_ids, raw_to_canonical, known_object_ids)
        if raw_subject_object_ids is not None
        else {}
    )

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
        "canonical_event_action_counts": {
            str(subject_id): {str(action): int(count) for action, count in action_counts.items()}
            for subject_id, action_counts in canonical_event_action_counts.items()
        },
        "canonical_subject_object_ids": canonical_subject_object_ids,
        "raw_event_type_counts": {str(action): int(count) for action, count in raw_event_type_counts.items()},
        "semantic_event_vocabulary": {name: int(value) for name, value in _SEMANTIC_EVENT_IDS.items()},
        "canonical_semantic_event_histories": canonical_semantic_event_histories,
        "canonical_subject_time_ranges": _canonicalize_subject_time_ranges(
            raw_subject_time_ranges,
            raw_to_canonical,
        ),
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


def _canonicalize_subject_time_ranges(raw_subject_time_ranges, raw_to_canonical):
    """Merge raw Subject event ranges after thread/identity normalization."""
    canonical_ranges = {}
    for raw_subject_id, value in raw_subject_time_ranges.items():
        if not isinstance(value, (list, tuple)) or len(value) < 3:
            continue
        canonical_subject_id = str(raw_to_canonical.get(str(raw_subject_id), raw_subject_id))
        first_seen = _to_seconds_like(value[0])
        last_seen = _to_seconds_like(value[1])
        if first_seen is None or last_seen is None:
            continue
        current = canonical_ranges.get(canonical_subject_id)
        if current is None:
            canonical_ranges[canonical_subject_id] = [float(first_seen), float(last_seen), int(value[2])]
            continue
        current[0] = min(float(current[0]), float(first_seen))
        current[1] = max(float(current[1]), float(last_seen))
        current[2] = int(current[2]) + int(value[2])
    return {
        subject_id: {
            "first_timestamp_sec": float(value[0]),
            "last_timestamp_sec": float(value[1]),
            "event_count": int(value[2]),
        }
        for subject_id, value in canonical_ranges.items()
    }


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
    subjswap = {}
    subject_seen = set()
    apg_subject_tgids = {}
    thread_subjects_merged_by_tgid = 0
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
                        raw_subjectuuid = subject_data['uuid']
                        subjectuuid = raw_subjectuuid
                        parentuuid = subject_data['parentSubject']['com.bbn.tc.schema.avro.cdm18.UUID']
                        subject_seen.add(raw_subjectuuid)
                        subtgid = "Unknown"
                        if "tgid" in subject_data['properties']['map']:
                            subtgid = subject_data['properties']['map']['tgid']

                        # The TAPAS thread rule merges a Subject only when its
                        # already-known parent has the same tgid.  Matching a
                        # sibling's parent/tgid/path is not evidence of a thread.
                        canonical_parent = subjswap.get(parentuuid, parentuuid)
                        parent_tgid = apg_subject_tgids.get(parentuuid)
                        if subtgid != "Unknown" and parent_tgid == subtgid:
                            subjswap[raw_subjectuuid] = canonical_parent
                            apg_subject_tgids[raw_subjectuuid] = parent_tgid
                            thread_subjects_merged_by_tgid += 1
                            continue

                        apg_subject_tgids[raw_subjectuuid] = subtgid
                        parentuuid = canonical_parent
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

    thread_merge_metadata = {
        'raw_subject_to_canonical_node': {
            str(subject_uuid): str(subjswap.get(subject_uuid, subject_uuid))
            for subject_uuid in subject_seen
        },
        'thread_merge_rule': 'parent_subject_known_and_same_tgid',
        'thread_subjects_merged_by_tgid': int(thread_subjects_merged_by_tgid),
    }
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
            'parser_metadata': thread_merge_metadata,
        }, subjhisvec
    return chi_pa, subjhisvec


def filters_theia_e5(
        data_path,
        return_task_components=False,
        child_threshold=2,
        split_mode="fanout",
        count_segmented_children_upstream=False,
        ground_truth_object_uuids=None,
        return_sequence_histories=False,
):
    """Build THEIA E5 process tasks from CDM20 JSON.

    E5 keeps the TC3 event/object layout but changes the Avro namespace to
    cdm20 and represents unknown parents with the all-zero UUID.  Keeping this
    parser separate protects the historical TC3 THEIA path from format drift.
    """
    syspathdict = load_fix('./data/linux_system_path.txt')
    filetypedict = load_fix('./data/linux_file_type.txt')
    aimevetype = {
        'EVENT_ACCEPT': 1,
        'EVENT_CONNECT': 2,
        'EVENT_EXECUTE': 3,
        'EVENT_EXIT': 4,
        'EVENT_READ': 5,
        'EVENT_RECVFROM': 6,
        'EVENT_RECVMSG': 7,
        'EVENT_SENDTO': 8,
        'EVENT_SENDMSG': 9,
        'EVENT_WRITE': 10,
    }
    data_list = sorted(
        filename
        for filename in os.listdir(data_path)
        if os.path.isfile(os.path.join(data_path, filename))
    )
    events_seen = {}
    objvec = {}
    raw_subject_time_ranges = {}
    raw_subject_to_canonical = {}
    raw_subject_rows = {}
    raw_subject_order = []
    canonical_subjects = {}
    canonical_order = []
    alias_key_to_subject = {}
    event_type_counts = collections.Counter()
    parser_counts = collections.Counter()
    gt_object_uuids = {
        str(value).strip()
        for value in (ground_truth_object_uuids or [])
        if str(value).strip()
    }
    gt_object_event_subjects = {object_uuid: set() for object_uuid in gt_object_uuids}
    gt_object_event_counts = collections.Counter()
    gt_object_event_types = {object_uuid: collections.Counter() for object_uuid in gt_object_uuids}

    for filename in tqdm(data_list, desc="Parsing THEIA E5", unit="file"):
        path = os.path.join(data_path, filename)
        with open(path, 'r', encoding='utf-8') as handle:
            for line in handle:
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    parser_counts['malformed_json_lines'] += 1
                    continue

                event_data = _cdm_datum_payload(record, 'Event')
                if event_data is not None:
                    event_type = str(event_data.get('type', 'EVENT_OTHER'))
                    event_type_counts[event_type] += 1
                    raw_subject = _cdm_uuid(event_data.get('subject'))
                    timestamp_sec = _event_timestamp_seconds(event_data)
                    _update_subject_time_range(raw_subject_time_ranges, raw_subject, timestamp_sec)
                    event_objects = {
                        str(value).strip().upper()
                        for value in (
                            _cdm_uuid(event_data.get('predicateObject')),
                            _cdm_uuid(event_data.get('predicateObject2')),
                        )
                        if value
                    }
                    for gt_object_uuid in event_objects & gt_object_uuids:
                        if raw_subject and not _is_zero_uuid(raw_subject):
                            gt_object_event_subjects[gt_object_uuid].add(raw_subject)
                            gt_object_event_counts[gt_object_uuid] += 1
                            gt_object_event_types[gt_object_uuid][event_type] += 1
                    if event_type not in aimevetype:
                        continue
                    object_uuid = _cdm_uuid(event_data.get('predicateObject'))
                    if not raw_subject or not object_uuid or _is_zero_uuid(raw_subject):
                        parser_counts['selected_events_missing_subject_or_object'] += 1
                        continue
                    key = (aimevetype[event_type], raw_subject, object_uuid)
                    events_seen[key] = events_seen.get(key, 0) + 1
                    continue

                subject_data = _cdm_datum_payload(record, 'Subject')
                if subject_data is not None:
                    raw_subject = _cdm_uuid(subject_data.get('uuid'))
                    if not raw_subject or _is_zero_uuid(raw_subject):
                        parser_counts['zero_or_missing_subject_records'] += 1
                        continue
                    raw_parent = _cdm_uuid(subject_data.get('parentSubject'))
                    if not raw_parent or _is_zero_uuid(raw_parent):
                        raw_parent = 'Unknow'
                        parser_counts['root_subject_records'] += 1
                    props = _subject_properties_map(subject_data)
                    if raw_subject not in raw_subject_rows:
                        raw_subject_order.append(raw_subject)
                    raw_subject_rows[raw_subject] = {
                        'uuid': raw_subject,
                        'parentuuid': raw_parent,
                        'tgid': str(props.get('tgid', '')).strip(),
                        'subpath': str(props.get('path') or _unwrap_avro_scalar(subject_data.get('cmdLine')) or 'Unknown'),
                        'process_id': str(_unwrap_avro_scalar(subject_data.get('cid')) or '0'),
                        'subject_type': str(subject_data.get('type', '')),
                    }
                    continue

                file_data = _cdm_datum_payload(record, 'FileObject')
                if file_data is not None:
                    object_uuid = _cdm_uuid(file_data.get('uuid'))
                    if not object_uuid:
                        parser_counts['file_records_missing_uuid'] += 1
                        continue
                    base_object = file_data.get('baseObject')
                    properties = base_object.get('properties') if isinstance(base_object, dict) else {}
                    prop_map = properties.get('map', {}) if isinstance(properties, dict) else {}
                    if not isinstance(prop_map, dict):
                        prop_map = {}
                    filename_value = prop_map.get('filename') or prop_map.get('path')
                    filename = str(filename_value) if filename_value else 'Unknown'
                    dev_value = prop_map.get('dev')
                    dev = str(dev_value) if dev_value is not None else 'Unknown'
                    max_length = 0
                    subpath_vec = 90
                    for match in syspathdict:
                        if filename.startswith(match) and len(match) > max_length:
                            max_length = len(match)
                            subpath_vec = int(syspathdict[match]) + 1
                    filetype_vec = 0
                    if filename != 'Unknown':
                        last_part = filename.rsplit('/', 1)[-1]
                        if 'python' not in last_part and '.' in last_part:
                            extension = last_part.split('.', 1)[-1]
                            if 'so' in extension:
                                extension = 'so'
                            if '.' in extension:
                                extension = last_part.rsplit('.', 1)[-1]
                            if extension in filetypedict:
                                filetype_vec = int(filetypedict[extension]) + 1
                    if (
                        len(dev) > 5
                        or 'Unknown' in dev
                        or '/' in dev
                        or 'con' in dev
                        or 'Empty' in dev
                        or 'Labs' in dev
                        or 'with' in dev
                    ):
                        dev_vec = '0'
                    else:
                        dev_vec = dev
                    objvec[object_uuid] = ['2', str(subpath_vec), str(filetype_vec), str(dev_vec)]
                    continue

                netflow_data = _cdm_datum_payload(record, 'NetFlowObject')
                if netflow_data is not None:
                    object_uuid = _cdm_uuid(netflow_data.get('uuid'))
                    if not object_uuid:
                        parser_counts['netflow_records_missing_uuid'] += 1
                        continue
                    local_address = _unwrap_avro_scalar(netflow_data.get('localAddress')) or 'unknown'
                    remote_address = _unwrap_avro_scalar(netflow_data.get('remoteAddress')) or 'unknown'
                    local_port = _unwrap_avro_scalar(netflow_data.get('localPort'))
                    remote_port = _unwrap_avro_scalar(netflow_data.get('remotePort'))
                    local_port = str(local_port if local_port is not None else 1024)
                    remote_port = str(remote_port if remote_port is not None else 1024)
                    objvec[object_uuid] = [
                        '3',
                        str(compare_address(str(local_address), str(remote_address))),
                        str(getportcode(local_port)),
                        str(getportcode(remote_port)),
                    ]

    # Apply the TAPAS thread rule before process-graph construction.  A child
    # Subject with the same tgid as its parent is represented by that parent's
    # process node; all of its later events are remapped to the same owner.
    owner_by_uuid, process_parent_by_owner = _resolve_thread_subject_owners(
        list(raw_subject_rows.values())
    )
    owner_to_canonical = {}
    for raw_subject in raw_subject_order:
        owner_subject = owner_by_uuid.get(raw_subject, raw_subject)
        if owner_subject != raw_subject:
            parser_counts['thread_subjects_merged_by_tgid'] += 1
            continue
        row = raw_subject_rows.get(owner_subject)
        if row is None:
            continue
        parent_owner = process_parent_by_owner.get(owner_subject, 'Unknow')
        canonical_parent = owner_to_canonical.get(parent_owner, parent_owner)
        alias_key = (canonical_parent, row.get('tgid', ''), row.get('subpath', 'Unknown'))
        canonical_subject = alias_key_to_subject.get(alias_key)
        if canonical_subject is None:
            canonical_subject = owner_subject
            alias_key_to_subject[alias_key] = canonical_subject
            canonical_order.append(canonical_subject)
            canonical_subjects[canonical_subject] = {
                'parent_raw': parent_owner,
                'process_id': row.get('process_id', '0'),
                'subject_type': row.get('subject_type', ''),
            }
        else:
            parser_counts['same_parent_tgid_path_aliases'] += 1
        owner_to_canonical[owner_subject] = canonical_subject

    for raw_subject in raw_subject_order:
        owner_subject = owner_by_uuid.get(raw_subject, raw_subject)
        raw_subject_to_canonical[raw_subject] = owner_to_canonical.get(owner_subject, owner_subject)

    gt_object_event_canonical_subjects = sorted({
        raw_subject_to_canonical.get(raw_subject, raw_subject)
        for subjects in gt_object_event_subjects.values()
        for raw_subject in subjects
        if raw_subject_to_canonical.get(raw_subject, raw_subject)
    })

    subject_list = []
    for canonical_subject in canonical_order:
        row = canonical_subjects[canonical_subject]
        parent_raw = row.get('parent_raw', 'Unknow')
        parent_owner = owner_by_uuid.get(parent_raw, parent_raw)
        canonical_parent = owner_to_canonical.get(parent_owner, parent_owner)
        if canonical_parent == canonical_subject or _is_zero_uuid(canonical_parent):
            canonical_parent = 'Unknow'
        subject_list.append(['1', canonical_subject, canonical_parent, row.get('process_id', '0')])

    padict, chdict = _normalize_task_maps(subject_list)
    segmented = set()
    task_components = None
    task_component_diagnostics = []
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

    canonical_event_count = _remap_event_subjects(events_seen, raw_subject_to_canonical)
    subjhistory = {}
    for event, count in canonical_event_count.items():
        if event[2] not in objvec:
            parser_counts['selected_events_without_supported_object'] += int(count)
            continue
        subjhistory.setdefault(event[1], []).append([str(event[0]), str(count)] + objvec[event[2]])

    if return_sequence_histories:
        # The offline TAPAS objective consumes each process history directly:
        # x[t] predicts the event vector x[t + 1] for the same process.
        return subjhistory, {
            'raw_subject_count': int(len(raw_subject_rows)),
            'canonical_process_subject_count': int(len(subject_list)),
            'active_sequence_subject_count': int(len(subjhistory)),
            'event_type_counts': dict(event_type_counts),
            'parser_counts': {key: int(value) for key, value in parser_counts.items()},
        }

    lstm_model = LSTM(6, 256, 6)
    lstm_model.load_state_dict(torch.load('./model/stackedlstm_tc.pt', map_location=device))
    lstm_model.to(device)
    lstm_model.eval()
    subjhisvec = {}

    def _e5_numeric_feature(value):
        """Normalize CDM20 scalar fields, including hexadecimal device values."""
        try:
            return float(value)
        except (TypeError, ValueError):
            try:
                return float(int(str(value).strip(), 0))
            except (TypeError, ValueError):
                parser_counts['non_numeric_sequence_features'] += 1
                return 0.0

    with torch.no_grad():
        for subject_uuid, history in tqdm(subjhistory.items(), desc="Getting E5 node vector", unit="node"):
            values = [[_e5_numeric_feature(value) for value in event] for event in history]
            if not values:
                subjhisvec[subject_uuid] = [0.0] * 42
                continue
            tensor = torch.tensor(np.array([values]), dtype=torch.float32).to(device)
            subjhisvec[subject_uuid] = torch.Tensor.tolist(lstm_model(tensor))

    canonical_time_ranges = {}
    for raw_subject, value in raw_subject_time_ranges.items():
        canonical_subject = raw_subject_to_canonical.get(raw_subject, raw_subject)
        if _is_zero_uuid(canonical_subject):
            continue
        current = canonical_time_ranges.get(canonical_subject)
        if current is None:
            canonical_time_ranges[canonical_subject] = list(value)
        else:
            current[0] = min(current[0], value[0])
            current[1] = max(current[1], value[1])
            current[2] += int(value[2])

    edge_rows = []
    for parent, children in padict.items():
        for child in children:
            if child != 'Unknow':
                edge_rows.append([str(parent), str(child)])
    if return_task_components:
        return {
            'edge_list': edge_rows,
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
                for subject_uuid, value in canonical_time_ranges.items()
            },
            'parser_metadata': {
                'format': 'theia_e5_cdm20',
                'raw_subject_to_canonical_node': raw_subject_to_canonical,
                'raw_subject_count': int(len(raw_subject_rows)),
                'canonical_process_subject_count': int(len(subject_list)),
                'event_type_counts': dict(event_type_counts),
                'parser_counts': {key: int(value) for key, value in parser_counts.items()},
                # E5 ORTHRUS node exports include FileObject/NetFlowObject rows.
                # Their event Subjects are the process nodes that own the behavior.
                'gt_object_event_canonical_subjects': gt_object_event_canonical_subjects,
                'gt_object_event_linkage': {
                    object_uuid: {
                        'raw_subject_count': len(gt_object_event_subjects[object_uuid]),
                        'canonical_subject_count': len({
                            raw_subject_to_canonical.get(raw_subject, raw_subject)
                            for raw_subject in gt_object_event_subjects[object_uuid]
                        }),
                        'event_count': int(gt_object_event_counts[object_uuid]),
                        'event_type_counts': {
                            event_type: int(count)
                            for event_type, count in gt_object_event_types[object_uuid].items()
                        },
                    }
                    for object_uuid in sorted(gt_object_uuids)
                },
            },
        }, subjhisvec
    return edge_rows, subjhisvec

def cut_task(
        subject_list,
        return_task_components=False,
        child_threshold=2,
        split_mode="fanout",
        count_segmented_children_upstream=False,
        use_release_legacy=False,
):
    if use_release_legacy:
        return _cut_task_release_legacy(subject_list)
    return _cut_task(
        subject_list,
        return_task_components=return_task_components,
        child_threshold=child_threshold,
        split_mode=split_mode,
        count_segmented_children_upstream=count_segmented_children_upstream,
    )


def _cut_task_release_legacy(subject_list):
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
        else:
            chdict[subj] = pare
            if pare in padict:
                padict[pare].append(subj)
            else:
                padict[pare] = [subj]

    for key, value in padict.items():
        for xvalue in value:
            if xvalue in padict.keys():
                padict[key].remove(xvalue)

    chi_pa = []
    for key, value in padict.items():
        for var in value:
            if var != 'Unknow':
                chi_pa.append([var, key])
    return chi_pa


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
        return _decompose_task_components(
            edgeList['task_components'],
            nodeVec,
            onedataname,
            canonical_ground_truth=canonical_ground_truth,
        )
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


def _decompose_task_components(task_components, nodeVec, onedataname, canonical_ground_truth=None):
    if isinstance(nodeVec, list):
        nodeVec = {
            str(row[0]): [float(x) for x in row[1:]]
            for row in nodeVec
            if isinstance(row, (list, tuple)) and len(row) >= 43
        }
    attackNode = set()
    if canonical_ground_truth is None:
        f = open('./groundtruth/{}.txt'.format(onedataname), 'r')
        for line in f:
            attackNode.add(line.strip())
    else:
        attackNode = {str(item).strip() for item in canonical_ground_truth if str(item).strip()}

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


def dataenhance(x, addnum, onedataname, return_metadata=False):
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
    # E5 uses the same Linux THEIA event encoding and LSTM checkpoint as the
    # TC3 THEIA corpus, so it intentionally shares that benign template set.
    template_dataset = 'theia' if onedataname == 'theia_e5' else onedataname
    actlist = benignTop10actdict[template_dataset]

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
        if return_metadata:
            addx.append(
                {
                    'nodes': newx,
                    'replaced_index': int(randomnode),
                    'template_index': int(randomact),
                }
            )
        else:
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


