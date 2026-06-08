import os
from tqdm import tqdm
import gzip
import io
from collections import defaultdict
import re
from tqdm import tqdm
from torch import nn
import numpy as np
import torch, csv
from collections import defaultdict
import random
from torch import nn
import torch.nn.functional as F
import torch
from torch_geometric.data import Data, InMemoryDataset
from torch_geometric.nn import SAGEConv, global_mean_pool, Linear, global_add_pool, global_max_pool
from torch_geometric.loader import DataLoader
from torch.optim import Adam
from sklearn.metrics import accuracy_score, precision_recall_fscore_support


data_path = './data/optc/'


def Extract_logs():
    log_files = [
        ("AIA-201-225.ecar-2019-12-08T11-05-10.046.json.gz", "0201"),
        ("AIA-201-225.ecar-last.json.gz", "0201"),

        ("AIA-501-525.ecar-2019-11-17T04-01-58.625.json.gz", "0501"),
        ("AIA-501-525.ecar-last.json.gz", "0501"),

        ("AIA-51-75.ecar-last.json.gz", "0051")
    ]
    if os.path.exists(data_path + "SysClient0201.systemia.com.txt"):
        os.remove(data_path + "SysClient0201.systemia.com.txt")
    if os.path.exists(data_path + "SysClient0501.systemia.com.txt"):
        os.remove(data_path + "SysClient0501.systemia.com.txt")
    if os.path.exists(data_path + "SysClient0051.systemia.com.txt"):
        os.remove(data_path + "SysClient0051.systemia.com.txt")

    for file, hostid in tqdm(log_files, desc="Extracting logs", unit="file"):
        search_pattern = f'SysClient{hostid}'
        output_filename = f'SysClient{hostid}.systemia.com.txt'

        with gzip.open(data_path + 'logs/' + file, 'rt', encoding='utf-8') as fin:
            with open(data_path + output_filename, 'ab') as f:
                out = io.BufferedWriter(f)
                for line in fin:
                    if search_pattern in line:
                        out.write(line.encode('utf-8'))
                out.flush()
            f.close()
        fin.close()



def get_field(field, data):
    pattern_template = r'"{field}"\s*:\s*"([^"]*)"'
    match = re.search(pattern_template.format(field=re.escape(field)), data)
    result = match.group(1) if match else None
    return str(result)


def parser_logs(hostid):
    event_map = {'START': 1, 'MESSAGE': 2, 'OPEN': 3, 'MODIFY': 4, 'READ': 5, 'WRITE': 6, 'CREATE': 7, 'RENAME': 8,
                 'DELETE': 9, 'TERMINATE': 10}

    subject_map = {}
    object_map = {}
    event_count = defaultdict(int)

    pre_flow = None
    f = open(data_path + 'SysClient{}.systemia.com.txt'.format(hostid), 'r', encoding='utf-8')
    for line in f:
        action = get_field('action', line)
        if action not in event_map:
            continue
        object = get_field('object', line)

        if object not in ['FILE', 'PROCESS', 'FLOW']:
            continue

        sub_id = get_field('actorID', line)
        image_path = get_field('image_path', line)
        if sub_id not in subject_map:
            subject_map[sub_id] = ['1', sub_id, 'Unknow', 'Unknow', image_path]

        obj_id = get_field('objectID', line)
        if object == 'FILE':
            file_path = get_field('file_path', line)
            object_map[obj_id] = ['2', obj_id, file_path]
        elif object == 'FLOW':
            src_ip = get_field('src_ip', line)
            src_port = get_field('src_port', line)
            dest_ip = get_field('dest_ip', line)
            dest_port = get_field('dest_port', line)
            key = sub_id + dest_ip + dest_port
            if key == pre_flow:
                continue
            else:
                pre_flow = key
                object_map[obj_id] = ['3', obj_id, src_ip, dest_ip, src_port, dest_port]
        else:
            pass
        event_count[(str(event_map[action]), sub_id, obj_id)] += 1

        if object == 'PROCESS' and action == 'CREATE':
            image_path = get_field('image_path', line)
            subject_map[obj_id] = ['1', obj_id, sub_id, 'Unknow', image_path]

    subject_list = []
    object_list = []
    for key, value in subject_map.items():
        subject_list.append(value)
    for key, value in object_map.items():
        object_list.append(value)

    return subject_list, object_list, event_count


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
    if port == 'None':
        dstpVec = 2
    elif int(port) < 1024:
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


def encode(sub_list, obj_list, event_list):
    sys_path_dict = load_fix('./data/windows_system_path.txt')
    file_type_dict = load_fix('./data/windows_file_type.txt')

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
            sub_list_hat[eve[1]].append([eve[0], str(event_list[eve])] + obj_list_hat[eve[2]])

    return sub_list_hat


def cut_task(subject_list):
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


class LSTM_GRU(nn.Module):
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
    LSTMmodel = LSTM_GRU(6, 256, 6)
    LSTMmodel.load_state_dict(torch.load('./model/stackedlstm_optc.pt'))
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


def decompose(subjectvec, edgeList):
    nodeVec = {}
    for x in subjectvec:
        nodeVec[x[0]] = x[1:]
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

    node_map = defaultdict(list)
    edge_map = defaultdict(list)
    for node in nodeList:
        root = find(node)
        node_map[root].append(node)
    for edge in edgeList:
        root = find(edge[0])
        edge_map[root].append(edge)

    graphList = []
    for key in node_map:
        if len(edge_map[key]) == 0 or len(node_map[key]) == 1:
            continue
        graphList.append([node_map[key], edge_map[key]])

    attackNode = set()
    f = open('./groundtruth/optc.txt', 'r')
    for line in f:
        attackNode.add(line.strip())

    data = []

    for graph in graphList:
        label = 0
        attacknum = 0
        nodenum = 0
        nodeId = {}

        node_list_hat = []
        edge_list_hat = []

        for node in graph[0]:
            if node in attackNode:
                label = 1
            if node not in nodeId:
                nodeId[node] = nodenum
                nodenum += 1
                node_list_hat.append([float(x) for x in nodeVec[node]] if node in nodeVec else [0.0] * 42)
        for edge in graph[1]:
            if edge[0] in nodeId and edge[1] in nodeId:
                edge_list_hat.append([nodeId[edge[0]], nodeId[edge[1]]])
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
        h_l0 = torch.zeros(batch_size, 16).to(device)
        c_l0 = torch.zeros(batch_size, 16).to(device)
        h_l1 = torch.zeros(batch_size, 10).to(device)
        if hidden != None:
            h_l0 = hidden[:, 0:16].to(device)
            c_l0 = hidden[:, 16:32].to(device)
            h_l1 = hidden[:, 32:].to(device)
        output = []
        h_l0, c_l0 = self.lstm0(input_seq, (h_l0, c_l0))
        h_l0, c_l0 = self.dropout(h_l0), self.dropout(c_l0)
        h_l1 = self.gru(h_l0, h_l1)
        h_l1 = self.dropout(h_l1)
        output.append(h_l1)
        pred = self.linear(output[-1])
        result = torch.cat([h_l0[-1], c_l0[-1], h_l1[-1]], dim=0)
        return result


def dataenhance(x, dataname, addnum):
    LSTMmodel = LSTM_GRU_HAT(6, 256, 6)
    LSTMmodel.load_state_dict(torch.load('./model/stackedlstm_optc.pt'))
    LSTMmodel.to(device)
    LSTMmodel.eval()
    addx = []
    all_actlist = {
        '0201': [[1, 1, 3, 7, 1, 1], [7, 1, 2, 90, 0, 0], [4, 1, 2, 90, 0, 0], [2, 1, 3, 4, 1, 1], [6, 1, 2, 90, 0, 0],
                 [5, 1, 2, 90, 0, 0], [1, 1, 3, 4, 1, 1], [2, 1, 3, 4, 2, 1], [1, 1, 3, 7, 2, 1], [1, 1, 3, 4, 2, 1],
                 [2, 1, 3, 4, 1, 1], [5, 1, 2, 90, 0, 0], [1, 1, 3, 4, 1, 1], [2, 1, 3, 4, 2, 1], [6, 1, 2, 90, 0, 0],
                 [2, 1, 3, 4, 0, 0], [4, 1, 2, 90, 0, 0], [1, 1, 3, 4, 0, 0], [1, 1, 3, 7, 2, 1], [1, 1, 3, 4, 2, 1]],
        '0501': [[4, 1, 2, 90, 0, 0], [5, 1, 2, 90, 17, 0], [2, 1, 3, 4, 2, 1], [1, 1, 3, 4, 2, 0], [2, 1, 3, 4, 1, 2],
                 [5, 1, 2, 90, 26, 0], [2, 1, 3, 4, 2, 2], [2, 1, 3, 4, 0, 2], [2, 1, 3, 4, 2, 0], [5, 1, 2, 90, 0, 0],
                 [7, 1, 2, 90, 0, 0], [1, 1, 3, 4, 1, 1], [5, 1, 2, 90, 0, 0], [2, 1, 3, 4, 2, 1], [6, 1, 2, 90, 0, 0],
                 [2, 1, 3, 4, 0, 0], [4, 1, 2, 90, 0, 0], [1, 1, 3, 4, 0, 0], [1, 1, 3, 4, 2, 1], [1, 1, 3, 7, 2, 1]],
        '0051': [[2, 1, 3, 4, 1, 1], [1, 1, 3, 4, 1, 1], [6, 1, 2, 90, 0, 0], [2, 1, 3, 4, 2, 1], [5, 1, 2, 90, 0, 0],
                 [4, 1, 2, 90, 0, 0], [2, 1, 3, 4, 0, 0], [1, 1, 3, 7, 2, 1], [1, 1, 3, 4, 2, 1], [1, 1, 3, 4, 0, 0],
                 [2, 1, 3, 4, 1, 1], [1, 1, 3, 4, 1, 1], [6, 1, 2, 90, 0, 0], [2, 1, 3, 4, 2, 1], [5, 1, 2, 90, 0, 0],
                 [4, 1, 2, 90, 0, 0], [2, 1, 3, 4, 0, 0], [1, 1, 3, 7, 2, 1], [1, 1, 3, 4, 2, 1], [1, 1, 3, 4, 0, 0]]
    }

    actlist = all_actlist[dataname]

    nodenum = len(x) - 1
    for i in range(addnum):
        randomnode = random.randint(0, nodenum)
        randomact = random.randint(0, 19)
        data = []
        act = actlist[randomact]
        act = [float(x) for x in act]
        data.append(act)
        train_x_tensor = torch.tensor(np.array([act]), dtype=torch.float32).to(device)

        h1 = torch.tensor(np.array(x[randomnode]).reshape(1, 42), dtype=torch.float32).to(device)
        newnodevec = LSTMmodel(train_x_tensor, h1)

        #vec = newnodevec[0]
        vec = torch.Tensor.tolist(newnodevec)
        newx = x
        newx[randomnode] = vec
        addx.append(newx)
    return addx


def data_deal(data, host):
    data_pro = []
    atttack_num = 0
    count = len(data)
    for x in data:
        if x['label'] == 1:
            needadd = count // 60
            atttack_num += needadd
            data_pro.append(x)
            addx = dataenhance(x['nodes'], host, needadd)
            for a in addx:
                data = x
                data['nodes'] = a
                data_pro.append(data)
        else:
            data_pro.append(x)
    return data_pro


class MyOwnDataset(InMemoryDataset):
    def __init__(self, data):
        super().__init__(root='dataset_temp')

        data_list = []
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


class GraphSAGE(torch.nn.Module):

    def __init__(self, input_dim, hidden_dim, output_dim):
        super(GraphSAGE, self).__init__()
        self.conv1 = SAGEConv(input_dim, hidden_dim)
        self.conv2 = SAGEConv(hidden_dim, hidden_dim)
        self.lin = Linear(hidden_dim, output_dim)

    def forward(self, x, edge_index, batch):
        x = self.conv1(x, edge_index)
        x = F.relu(x)

        x = self.conv2(x, edge_index)

        x = F.relu(x)

        embedding = global_mean_pool(x, batch)

        x = F.dropout(x, p=0.5, training=self.training)
        x = self.lin(embedding)
        return embedding, x


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


def train(params):
    torch.manual_seed(2024)
    lr, epoch, batchSize = params
    data = torch.load('./data/optc/data_all.pt')
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
    weight = torch.tensor([0.7, 0.3]).to(device)
    criterion = torch.nn.CrossEntropyLoss()

    for e in range(epoch):
        total_loss = 0
        model.train()
        for data in train_loader:
            data.to(device)
            optimizer.zero_grad()
            _, out = model(data.x, data.edge_index, data.batch)
            loss = criterion(out, data.y)
            total_loss += loss
            loss.backward()
            optimizer.step()
        print(f"\nEpoch {e + 1}/{epoch}, Loss: {total_loss:.4f}")
        eval(model, train_loader, 'Train')
        eval(model, test_loader, 'Test ')
    torch.save(model, './model/optc.pkl')


def get_eval_result(data_name, all_labels, all_preds):
    accuracy = accuracy_score(all_labels, all_preds)
    precision, recall, f1, _ = precision_recall_fscore_support(all_labels, all_preds, average='macro', zero_division=0)

    print(
        f"[{data_name}]:\n\tAccuracy: {accuracy:.4f}\n\tPrecision: {precision:.4f}\n\tRecall: {recall:.4f}\n\tF1 Score: {f1:.4f}")


def eval_final(data_name, model):
    torch.manual_seed(2024)
    dataset = torch.load('./data/optc/{}.pt'.format(data_name))
    dataset = MyOwnDataset(dataset)
    dataset = dataset.shuffle()
    index = int(0.8 * len(dataset))
    test_data = dataset[index:]
    test_loader = DataLoader(dataset, shuffle=False)
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
    #Extract_logs()
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    random.seed(202520252025)
    torch.set_printoptions(profile="full")
    host_list = ["0201", "0051", "0501"]
    data_all = []
    for host in host_list:
        subject_list, object_list, event_count = parser_logs(host)
        subjectndoe = encode(subject_list, object_list, event_count)
        chi_pa = cut_task(subject_list)
        subjectvec = get_node_vec(subjectndoe)
        data = decompose(subjectvec, chi_pa)
        data = data_deal(data, host)
        data_all += data
        torch.save(data, './data/optc/{}.pt'.format(host))
    torch.save(data_all, './data/optc/data_all.pt')
    params = [0.001, 200, 500]
    train(params)
    eval_final('data_all', 'optc')
    eval_final('0051', 'optc')
    eval_final('0201', 'optc')
    eval_final('0501', 'optc')