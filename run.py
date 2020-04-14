#!/usr/bin/env python3
import sys
import json
import time
import networkx as nx
import networkx.algorithms.dag as dag

def write_dot_with_labels(G, path):
    for n, attrs in G.nodes(data=True):
        lbl = str(n)
        if 'type' in attrs:
            lbl += ' t:' + attrs['type']
        attrs['label'] = lbl
    nx.drawing.nx_pydot.write_dot(G, 'G.dot')

def bits_to_int(bits):
    acc = 0
    # reversed??
    for b in reversed(bits):
        acc <<= 1
        if b:
            acc += 1
    return acc

class CleartextComputer:
    def __init__(self, G, dffs):
        self.G = G
        self.dffs = dffs
        self.reset()

    def reset(self):
        for n, attrs in self.G.nodes.items():
            attrs['value'] = False

    def step(self):
        for n in dag.topological_sort(self.G):
            attrs = self.G.nodes[n]
            if 'type' not in attrs:
                continue
            if attrs['type'] == 'DFF':
                assert 'value' in attrs, 'uninitialized dff'
            elif attrs['type'] == 'NOT':
                preds = list(self.G.predecessors(n))
                assert len(preds) == 1
                inp = self.G.nodes[preds[0]]['value']
                attrs['value'] = not inp
            elif attrs['type'] == 'AND':
                preds = list(self.G.predecessors(n))
                assert len(preds) == 2
                inp0 = self.G.nodes[preds[0]]['value']
                inp1 = self.G.nodes[preds[1]]['value']
                attrs['value'] = inp0 and inp1
            else:
                print('unhandled node type during eval:', attrs['type'])
                assert False
        # set dffs
        for n in self.dffs:
            inp_node = self.G.nodes[n]['input_node']
            self.G.nodes[n]['value'] = self.G.nodes[inp_node]['value']

    def get_bits(self, bits):
        return [self.G.nodes[b]['value'] for b in bits]

class EncryptedComputer:
    def __init__(self, G, dffs):
        self.G = G
        self.dffs = dffs
        sys.path.append('../brainfreeze')
        import tfhe
        self.tfhe = tfhe
        self.gate_params = tfhe.create_gate_params()
        self.secret_key = tfhe.create_secret_keyset(self.gate_params)
        self.cloud_key = tfhe.get_cloud_keyset(self.secret_key)
        self.reset()

    def new_bit(self):
        return self.tfhe.create_ciphertext(self.gate_params)

    def reset(self):
        for n, attrs in self.G.nodes.items():
            nb = self.new_bit()
            self.tfhe.tfhe.bootsCONSTANT(nb, 0, self.cloud_key)
            attrs['value'] = nb

    def step(self):
        for n in dag.topological_sort(self.G):
            attrs = self.G.nodes[n]
            if 'type' not in attrs:
                continue
            if attrs['type'] == 'DFF':
                assert 'value' in attrs, 'uninitialized dff'
            elif attrs['type'] == 'NOT':
                preds = list(self.G.predecessors(n))
                assert len(preds) == 1
                inp = self.G.nodes[preds[0]]['value']
                self.tfhe.tfhe.bootsNOT(attrs['value'], inp, self.cloud_key)
            elif attrs['type'] == 'AND':
                preds = list(self.G.predecessors(n))
                assert len(preds) == 2
                inp0 = self.G.nodes[preds[0]]['value']
                inp1 = self.G.nodes[preds[1]]['value']
                self.tfhe.tfhe.bootsAND(attrs['value'], inp0, inp1, self.cloud_key)
            else:
                print('unhandled node type during eval:', attrs['type'])
                assert False
        # set dffs
        for n in self.dffs:
            inp_node = self.G.nodes[n]['input_node']
            self.tfhe.tfhe.bootsCOPY(
                self.G.nodes[n]['value'],
                self.G.nodes[inp_node]['value'],
                self.cloud_key)

    def get_bits(self, bits):
        return [self.tfhe.decrypt(self.G.nodes[b]['value'], self.secret_key) 
                for b in bits]

if __name__ == '__main__':
    with open('gates.json', 'r') as f:
        gates = json.load(f)['modules']['top']
    ports, cells = gates['ports'], gates['cells']

    print('ports:')
    clk_bit = None
    outputs = {}
    for name, p in ports.items():
        print(' ', name, p['direction'], 'bits:', p['bits'])
        if name == 'clk':
            assert p['direction'] == 'input'
            assert len(p['bits']) == 1
            clk_bit = p['bits'][0]
        if p['direction'] == 'output':
            outputs[name] = p['bits']
    assert clk_bit is not None

    print(len(cells), 'cells')
    print('cell types:', set(c['type'] for c in cells.values()))

    G = nx.DiGraph()
    dffs = set()
    unhandled_types = set()
    for name, c in cells.items():
        def assert_only_one(lst):
            assert len(lst) == 1
            return lst[0]
        def conns(*names):
            return [assert_only_one(c['connections'][n]) for n in names]
        if c['type'] == 'NOT':
            a, y = conns('A', 'Y')
            G.add_edge(a, y)
            G.nodes[y]['type'] = 'NOT'
        elif c['type'] == 'AND':
            a, b, y = conns('A', 'B', 'Y')
            G.add_edge(a, y)
            G.add_edge(b, y)
            G.nodes[y]['type'] = 'AND'
        elif c['type'] == 'DFF':
            c, d, q = conns('C', 'D', 'Q')
            assert c == clk_bit
            G.nodes[q]['type'] = 'DFF'
            G.nodes[q]['input_node'] = d
            dffs.add(q)
        else:
            unhandled_types.add(c['type'])
    if unhandled_types:
        print('didn\'t handle cell types:', unhandled_types)

    write_dot_with_labels(G, 'G.dot')
    assert nx.is_weakly_connected(G)
    assert dag.is_directed_acyclic_graph(G)

    cc = CleartextComputer(G.copy(), dffs)
    ec = EncryptedComputer(G.copy(), dffs)

    for cycle in range(10):
        print('evaluating cycle', cycle)
        print('eval cleartext')
        cc.step()
        print('eval encrypted')
        t0 = time.time()
        ec.step()
        t1 = time.time()
        dt = (t1-t0)
        print(f'evaluated {len(G)} gates in {dt:.03f} s', end='')
        print(f', or {(dt/len(G)*1000):.03f} ms/gate')
        for name, bitnums in outputs.items():
            cv = bits_to_int(cc.get_bits(bitnums))
            print(f'cc output {name}: {cv}')
            ev = bits_to_int(ec.get_bits(bitnums))
            print(f'ec output {name}: {ev}')

