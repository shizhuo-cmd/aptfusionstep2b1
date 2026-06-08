import os, json, traceback, sys, re, gc
sys.dont_write_bytecode = True
import collections
import random
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

def parser_cadets(data_path):
    data_list = os.listdir(data_path)
    event_map = {'EVENT_ACCEPT': 1, 'EVENT_CONNECT': 2, 'EVENT_EXECUTE': 3, 'EVENT_EXIT': 4, 'EVENT_READ': 5,
                 'EVENT_RECVFROM': 6, 'EVENT_RECVMSG': 7, 'EVENT_SENDTO': 8, 'EVENT_SENDMSG': 9, 'EVENT_WRITE': 10}
    subject_list = []
    object_list = []
    event_count = {}
    file_path = {}

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
                    parentuuid = data['parentSubject']['com.bbn.tc.schema.avro.cdm18.UUID'] if data['parentSubject'] is not None else 'Unknow'
                    pid = str(data["cid"])
                    subject_list.append(['1', uuid, parentuuid, pid])
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

    return subject_list, object_list, event_count


def parser_fivedirections(data_path):
    data_list = os.listdir(data_path)
    event_map = {'EVENT_ACCEPT': 1, 'EVENT_CONNECT': 2, 'EVENT_EXECUTE': 3, 'EVENT_EXIT': 4, 'EVENT_READ': 5,
                 'EVENT_RECVFROM': 6, 'EVENT_RECVMSG': 7, 'EVENT_SENDTO': 8, 'EVENT_SENDMSG': 9, 'EVENT_WRITE': 10}
    subject_list = []
    object_list = []
    event_count = {}

    file_path = {}

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
                    parentuuid = data['parentSubject']['com.bbn.tc.schema.avro.cdm18.UUID'] if data[
                                                                                                   'parentSubject'] is not None else 'Unknow'
                    pid = str(data["cid"])
                    subject_list.append(['1', uuid, parentuuid, pid])
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

    return subject_list, object_list, event_count

def parser_trace(data_path):
    data_list=os.listdir(data_path)
    event_map={'EVENT_RENAME': 1, 'EVENT_CONNECT': 2, 'EVENT_EXECUTE': 3, 'EVENT_EXIT': 4, 'EVENT_READ': 5,
                'EVENT_RECVFROM': 6, 'EVENT_RECVMSG': 7, 'EVENT_SENDTO': 8, 'EVENT_SENDMSG': 9, 'EVENT_WRITE': 10, 'EVENT_CREATE_OBJECT':11}
    subject_list=[]
    object_list=[]
    event_count={}
    cid_map={}
    for file in tqdm(data_list, desc=f"Parsing", unit="file"):
        f=open(data_path+file,'r')
        for line in f:
            try:
                event=json.loads(line)
                if "com.bbn.tc.schema.avro.cdm18.Event" in event["datum"]:
                    data=event["datum"]["com.bbn.tc.schema.avro.cdm18.Event"]
                    subId=str(data["threadId"]["int"])
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
                    parentuuid = data['parentSubject']['com.bbn.tc.schema.avro.cdm18.UUID'] if data['parentSubject'] is not None  else 'Unknow'
                    parentuuid=cid_map[parentuuid] if parentuuid in cid_map else 'Unknow'
                    cid=str(data["cid"])
                    path=data["properties"]["map"]["cwd"] if "cwd" in data["properties"]["map"] else ''
                    name=data["properties"]["map"]["name"]
                    subject_list.append(['1',cid,parentuuid,cid,path+'/'+name])
                    cid_map[uuid]=cid
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
    return subject_list,object_list,event_count

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

def filters(data_path):
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
                    event_type = js['datum']['com.bbn.tc.schema.avro.cdm18.Event']['type']
                    if event_type in aimevetype:
                        eveid = aimevetype[event_type]
                        subject_uuid = js['datum']['com.bbn.tc.schema.avro.cdm18.Event']['subject'][
                            'com.bbn.tc.schema.avro.cdm18.UUID']
                        object_uuid = js['datum']['com.bbn.tc.schema.avro.cdm18.Event']['predicateObject'][
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
            subjhistory[event[1]] = []

    del events_seen
    del objvec
    gc.collect()

    for key, value in padict.items():
        for xvalue in value:
            if xvalue in padict.keys():
                padict[key].remove(xvalue)
    chi_pa = []
    for key, value in padict.items():
        for var in value:
            if var != 'Unknow':
                chi_pa.append([str(var), str(key)])

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

    return chi_pa, subjhisvec

def cut_task(subject_list):
    padict = {}
    chdict = {}
    for var in subject_list:
        # print(var)
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


def decompose(edgeList, nodeVec, onedataname):
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
    f = open('./groundtruth/{}.txt'.format(onedataname), 'r')
    for line in f:
        attackNode.add(line.strip())

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
            vec = nodeVec[node] if node in nodeVec else [0.0] * 42
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
        newx = x
        newx[randomnode] = vec
        addx.append(newx)
    return addx


def data_deal(data_list, onedataname):
    data_pro = []
    atttack_num = 0
    count = len(data_list)
    for x in data_list:
        if x['label'] == 1:
            # needadd = count//600
            needadd = count // 2000
            atttack_num += needadd
            data_pro.append(x)
            addx = dataenhance(x['nodes'], needadd, onedataname)
            for a in addx:
                data = x
                data['nodes'] = a
                data_pro.append(data)
        else:
            data_pro.append(x)
    print(f'Total Task:{len(data_pro)}\t Attack Tasks:{atttack_num}')
    return data_pro


class GraphSAGE(torch.nn.Module):
    def __init__(self, input_dim, hidden_dim, output_dim):
        super(GraphSAGE, self).__init__()
        self.conv1 = SAGEConv(input_dim, hidden_dim)
        self.conv2 = SAGEConv(hidden_dim, hidden_dim)
        # self.conv3 = SAGEConv(hidden_dim, hidden_dim)
        self.lin = Linear(hidden_dim, output_dim)

    def forward(self, x, edge_index, batch):
        x = self.conv1(x, edge_index)
        x = F.relu(x)
        x = self.conv2(x, edge_index)
        x = F.relu(x)
        embedding = global_max_pool(x, batch)
        x = F.dropout(x, p=0.5, training=self.training)
        x = self.lin(embedding)
        return embedding, x


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


def train(params, onedataname):
    torch.manual_seed(2025)
    lr, epoch, batchSize = params
    data = torch.load('./data/{}/data.pt'.format(onedataname))
    dataset = MyOwnDataset(data)
    dataset = dataset.shuffle()
    index = int(0.8 * len(dataset))
    train_data = dataset[0:index]
    test_data = dataset[index:]
    train_loader = DataLoader(train_data, batch_size=batchSize, shuffle=True)
    test_loader = DataLoader(test_data, batch_size=batchSize, shuffle=False)
    model = GraphSAGE(input_dim=dataset.num_features, hidden_dim=64, output_dim=dataset.num_classes)
    print(model)
    model.to(device)
    optimizer = Adam(model.parameters(), lr=lr, weight_decay=5e-4)
    weight = torch.tensor([0.75, 0.25]).to(device)
    criterion = torch.nn.CrossEntropyLoss()

    for e in range(epoch):
        optimizer.zero_grad()
        total_loss = 0
        model.train()
        for data in train_loader:
            data.to(device)
            _, out = model(data.x, data.edge_index, data.batch)
            loss = criterion(out, data.y)
            total_loss += loss
        total_loss.backward()
        optimizer.step()
        print(f"\nEpoch {e + 1}/{epoch}, Loss: {total_loss:.4f}")
        eval(model, train_loader, 'Train')
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
            subject_list, object_list, event_count = parser_cadets(data_path)
            subjectnode = encode_cadets(subject_list, object_list, event_count)
            chi_pa = cut_task(subject_list)
            device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
            subvec = get_node_vec(subjectnode)
        elif dataname == 'fivedirections':
            subject_list, object_list, event_count = parser_fivedirections(data_path)
            subjectnode = encode_fivedirections(subject_list, object_list, event_count)
            chi_pa = cut_task(subject_list)
            device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
            subvec = get_node_vec(subjectnode)
        elif dataname == 'theia':
            chi_pa, subvec = filters(data_path)
        else:
            subject_list, object_list, event_count = parser_trace(data_path)
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


