
import unittest
import requests

from io import BytesIO
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
        input_amount = 0
        for tx_in in self.tx_ins:
            tx_ins_repr += tx_in.__repr__() + '\n'
            input_amount += tx_in.amount()
        tx_outs_repr = ''
        output_amount = 0
        for tx_out in self.tx_outs:
            tx_outs_repr += tx_out.__repr__() + '\n'
            output_amount += tx_out.amount
        fee = input_amount - output_amount
        return 'tx: {}\nversion: {}\ntx_ins:\n{}tx_outs:\n{}locktime: {}\nInput (BTC): {}\nOutput (BTC): {}\nFee (Satoshi): {} ({:.2f}%)'.format(
            self.id(),
            self.version,
            tx_ins_repr,
            tx_outs_repr,
            self.locktime,
            input_amount/100000000,
            output_amount/100000000,
            fee,
            fee/input_amount*100
        )

    def id(self):
        return self.hash().hex()

    def hash(self):
        return hash256(self.serialize())[::-1]

    def fee(self):
        fee = 0
        for tx_in in self.tx_ins:
            fee += tx_in.amount()
        for tx_out in self.tx_outs:
            fee -= tx_out.amount
        return fee

    def serialize(self):
        serialization = int_to_little_endian(self.version, 4)
        serialization += encode_varint(len(self.tx_ins))
        for tx_in in self.tx_ins:
            serialization += tx_in.serialize()
        serialization += encode_varint(len(self.tx_outs))
        for tx_out in self.tx_outs:
            serialization += tx_out.serialize()
        serialization += int_to_little_endian(self.locktime, 4)
        return serialization

    @classmethod
    def parse(cls, stream, testnet=False):
        version = little_endian_to_int(stream.read(4))
        tx_ins = []
        n_tx_ins = read_varint(stream)
        for _ in range(n_tx_ins):
            tx_ins.append(TxIn.parse(stream))
        tx_outs = []
        n_tx_outs = read_varint(stream)
        for _ in range(n_tx_outs):
            tx_outs.append(TxOut.parse(stream))
        locktime = little_endian_to_int(stream.read(4))
        return cls(version, tx_ins, tx_outs, locktime, testnet)


class TxIn:

    def __init__(self, prev_txid, prev_index, script_sig=None, sequence=0xffffffff):
        self.prev_txid = prev_txid
        self.prev_index = prev_index
        if script_sig is None:
            self.script_sig = Script()
        else:
            self.script_sig = script_sig
        self.sequence = sequence

    def __repr__(self):
        return '{}:{}'.format(self.prev_txid.hex(), self.prev_index)

    def amount(self):
        tx = TxFetcher.fetch(self.prev_txid.hex())
        utxo = tx.tx_outs[self.prev_index]
        return utxo.amount

    def script_pubkey(self):
        tx = TxFetcher.fetch(self.prev_txid.hex())
        utxo = tx.tx_outs[self.prev_index]
        return utxo.script_pubkey

    def serialize(self):
        serialization = self.prev_txid[::-1]
        serialization += int_to_little_endian(self.prev_index, 4)
        serialization += self.script_sig.serialize()
        serialization += int_to_little_endian(self.sequence, 4)
        return serialization

    @classmethod
    def parse(cls, stream):
        prev_txid = stream.read(32)[::-1]
        prev_index = little_endian_to_int(stream.read(4))
        script_sig = Script.parse(stream)
        sequence = little_endian_to_int(stream.read(4))
        return cls(prev_txid, prev_index, script_sig, sequence)


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


class TxFetcher:
    cache = {}

    @classmethod
    def get_url(cls, testnet=False):
        if testnet:
            return 'https://blockchain.info/rawtx'
        else:
            return 'https://blockchain.info/rawtx'

    @classmethod
    def fetch(cls, tx_id, testnet=False, fresh=False):
        if fresh or (tx_id not in cls.cache):
            url = '{}/{}?format=hex'.format(cls.get_url(testnet), tx_id)
            response = requests.get(url)
            try:
                raw = bytes.fromhex(response.text.strip())
            except ValueError:
                raise ValueError('unexpected response: {}'.format(response.text))
            if raw[4] == 0:
                raw = raw[:4] + raw[6:]
                tx = Tx.parse(BytesIO(raw), testnet=testnet)
                tx.locktime = little_endian_to_int(raw[-4:])
            else:
                tx = Tx.parse(BytesIO(raw), testnet=testnet)
            if tx.id() != tx_id:
                raise ValueError('not the same id: {} vs {}'.format(tx.id(),
            tx_id))
            cls.cache[tx_id] = tx
        cls.cache[tx_id].testnet = testnet
        return cls.cache[tx_id]


class TxTests(unittest.TestCase):

    def testParse(self):
        pass


if __name__ == '__main__':
    # unittest.main()
    tx_hex = '''010000000456919960ac691763688d3d3bcea9ad6ecaf875df5339e148a1fc61c6ed7a069e0100
00006a47304402204585bcdef85e6b1c6af5c2669d4830ff86e42dd205c0e089bc2a821657e951
c002201024a10366077f87d6bce1f7100ad8cfa8a064b39d4e8fe4ea13a7b71aa8180f012102f0
da57e85eec2934a82a585ea337ce2f4998b50ae699dd79f5880e253dafafb7feffffffeb8f51f4
038dc17e6313cf831d4f02281c2a468bde0fafd37f1bf882729e7fd3000000006a473044022078
99531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b84
61cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba
1f686f15f009ded7c62efe85a872e6a19b43c15a2937feffffff567bf40595119d1bb8a3037c35
6efd56170b64cbcc160fb028fa10704b45d775000000006a47304402204c7c7818424c7f7911da
6cddc59655a70af1cb5eaf17c69dadbfc74ffa0b662f02207599e08bc8023693ad4e9527dc42c3
4210f7a7d1d1ddfc8492b654a11e7620a0012102158b46fbdff65d0172b7989aec8850aa0dae49
abfb84c81ae6e5b251a58ace5cfeffffffd63a5e6c16e620f86f375925b21cabaf736c779f88fd
04dcad51d26690f7f345010000006a47304402200633ea0d3314bea0d95b3cd8dadb2ef79ea833
1ffe1e61f762c0f6daea0fabde022029f23b3e9c30f080446150b23852028751635dcee2be669c
2a1686a4b5edf304012103ffd6f4a67e94aba353a00882e563ff2722eb4cff0ad6006e86ee20df
e7520d55feffffff0251430f00000000001976a914ab0c0b2e98b1ab6dbf67d4750b0a56244948
a87988ac005a6202000000001976a9143c82d7df364eb6c75be8c80df2b3eda8db57397088ac46
430600'''
    tx_hex = ''.join(tx_hex.split('\n'))
    stream = BytesIO(bytes.fromhex(tx_hex))
    tx = Tx.parse(stream)
    print(tx)
