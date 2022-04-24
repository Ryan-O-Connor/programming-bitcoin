
import unittest
import io

from script import Script

from primitives import *


class Tx:

    def __init__(self, version, tx_ins, tx_outs, locktime, testnet=False):
        self.version = version
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        self.locktime = locktime
        self.testnet = testnet

    def __repr__(self):
        tx_ins_repr = ''
        for tx_in in self.tx_ins:
            tx_ins_repr += tx_in.__repr__() + '\n'
        tx_outs_repr = ''
        for tx_out in self.tx_outs:
            tx_outs_repr += tx_out.__repr__() + '\n'
        return 'tx: {}\nversion: {}\ntx_ins:\n{}tx_outs:\n{}locktime: {}'.format(
            self.id(),
            self.version,
            tx_ins_repr,
            tx_outs_repr,
            self.locktime
        )

    def id(self):
        return self.hash().hex()

    def hash(self):
        return hash256(self.serialize())[::-1]

    def serialize(self):
        serialization = int_to_little_endian(self.version, 4)
        serialization += encode_varint(len(self.tx_ins))
        for tx_in in self.tx_ins:
            serialization += tx_in.serialize()
        serialization += encode_varint(len(self.tx_outs))
        for tx_out in self.tx_outs:
            serialization += tx_out.serialize()
        serialization += int_to_little_endian(self.locktime)


    @classmethod
    def parse(cls, stream):
        version = little_endian_to_int(stream.read(4))
        tx_ins = []
        n_tx_ins = read_varint(stream)
        for _ in range(n_tx_ins):
            tx_ins.append(TxIn.parse(stream))
        tx_outs = []
        n_tx_outs = read_varint(stream)
        for _ in range(n_tx_ins):
            tx_outs.append(TxOut.parse(stream))
        locktime = little_endian_to_int(stream.read(4))
        return cls(version, tx_ins, tx_outs, locktime)


class TxIn:

    def __init__(self, prev_tx, prev_index, script_sig=None, sequence=0xffffffff):
        self.prev_tx = prev_tx
        self.prev_index = prev_index
        if script_sig is None:
            self.script_sig = Script()
        else:
            self.script_sig = script_sig
        self.sequence = sequence

    def __repr__(self):
        return '{}:{}'.format(self.prev_tx.hex(), self.prev_index)

    def serialize(self):
        serialization = int_to_little_endian(self.prev_tx, 32)
        serialization += int_to_little_endian(self.prev_index, 4)
        serialization += self.script_sig.serialize()
        serialization += int_to_little_endian(self.sequence, 4)
        return serialization

    @classmethod
    def parse(cls, stream):
        prev_tx = little_endian_to_int(stream.read(32))
        prev_index = little_endian_to_int(stream.read(4))
        script_sig = Script.parse(stream)
        sequence = little_endian_to_int(stream.read(4))
        return cls(prev_tx, prev_index, script_sig, sequence)


class TxOut:

    def __init__(self, amount, script_pubkey):
        self.amount = amount
        self.script_pubkey = script_pubkey

    def __repr__(self):
        return '{}: {}'.format(self.amount, self.script_pubkey)

    def serialize(self):
        serialization = int_to_little_endian(self.amount, 8)
        serialization += self.script_pubkey.serialize()
        return serialization

    @classmethod
    def parse(cls, stream):
        amount = little_endian_to_int(stream.read(8))
        script_pubkey = Script.parse(stream)
        return cls(amount, script_pubkey)
