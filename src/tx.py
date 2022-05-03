import unittest
import requests
import time

from io import BytesIO
from pprint import pprint
from ecc import PrivateKey
from script import Script, Interpreter, Token, T_OP_CODE, T_ELEMENT
from primitives import *


class TxGenerator:

    @staticmethod
    def tx_out(addr, amnt):
        addr_hash = decode_base58_checksum(addr)
        pubkey = TxGenerator.p2pkh_script(addr_hash)
        return TxOut(amount=amnt, script_pubkey=pubkey)

    @staticmethod
    def p2pkh_script(addr_hash):
        return Script([Token(value=0x76, type=T_OP_CODE),
                        Token(value=0xa9, type=T_OP_CODE),
                        Token(value=addr_hash, type=T_ELEMENT),
                        Token(value=0x88, type=T_OP_CODE),
                        Token(value=0xac, type=T_OP_CODE),])

    @staticmethod
    def p2pkh_sig(private_key, tx, input_index):
        z = tx.sig_hash(input_index)
        sig = private_key.sign(z).der() + SIGHASH_ALL.to_bytes(1, 'big')
        sec = private_key.public_key().sec()
        return Script([Token(value=sig, type=T_ELEMENT),
                        Token(value=sec, type=T_ELEMENT)])


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

    def sig_hash(self, input_index):
        # Transaction message hashed for signing
        signed_tx = self.serialize(signing=True, signing_index=input_index)
        signed_tx += int_to_little_endian(1, 4) # SIGHASH_ALL
        return int.from_bytes(hash256(signed_tx), 'big')

    def verify_input(self, input_index):
        tx_in = self.tx_ins[input_index]
        z = self.sig_hash(input_index)
        interpreter = Interpreter(tx_in.script_sig + tx_in.script_pubkey())
        if interpreter.evaluate(z):
            return True
        return False

    def verify(self):
        if self.fee() < 0:
            return False
        for i in range(len(self.tx_ins)):
            if not self.verify_input(i):
                print("Input {} is not valid".format(i))
                return False
        return True

    def sign_input(self, index, private_key):
        z = self.sig_hash(index)
        sig = private_key.sign(z).der() + SIGHASH_ALL.to_bytes(1, 'big')
        sec = private_key.public_key().sec()
        self.tx_ins[index].script_sig = Script([Token(value=sig, type=T_ELEMENT),
                                                Token(value=sec, type=T_ELEMENT)])
        return self.verify_input(index)

    def serialize(self, signing=False, signing_index=0):
        # Return byte serialization of tx
        serialization = int_to_little_endian(self.version, 4)
        serialization += encode_varint(len(self.tx_ins))
        for i, tx_in in enumerate(self.tx_ins):
            if signing:
                if i == signing_index:
                    serialization += tx_in.serialize(option=1)
                else:
                    serialization += tx_in.serialize(option=2)
            else:
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
            tx_ins.append(TxIn.parse(stream, testnet))
        tx_outs = []
        n_tx_outs = read_varint(stream)
        for _ in range(n_tx_outs):
            tx_outs.append(TxOut.parse(stream))
        locktime = little_endian_to_int(stream.read(4))
        return cls(version, tx_ins, tx_outs, locktime, testnet)


class TxIn:

    def __init__(self, prev_txid, prev_index, script_sig=None, sequence=0xffffffff, testnet=False):
        self.prev_txid = prev_txid
        self.prev_index = prev_index
        self.prev_txout = TxFetcher.fetch(prev_txid, prev_index, testnet=testnet)
        if script_sig is None:
            self.script_sig = Script()
        else:
            self.script_sig = script_sig
        self.sequence = sequence

    def __repr__(self):
        return '{}:{}'.format(self.prev_txid.hex(), self.prev_index)

    def amount(self):
        return self.prev_txout.amount

    def script_pubkey(self):
        return self.prev_txout.script_pubkey

    def serialize(self, option=0):
        serialization = self.prev_txid[::-1]
        serialization += int_to_little_endian(self.prev_index, 4)
        if option == 0:
            serialization += self.script_sig.serialize()
        elif option == 1:
            serialization += self.script_pubkey().serialize()
        serialization += int_to_little_endian(self.sequence, 4)
        return serialization

    @classmethod
    def parse(cls, stream, testnet):
        prev_txid = stream.read(32)[::-1]
        prev_index = little_endian_to_int(stream.read(4))
        script_sig = Script.parse(stream)
        sequence = little_endian_to_int(stream.read(4))
        return cls(prev_txid, prev_index, script_sig, sequence, testnet)


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

    @staticmethod
    def get_url(txid, testnet=False):
        if testnet:
            return 'https://api.bitaps.com/btc/testnet/v1/blockchain/transaction/{}'.format(txid.hex())
        else:
            return 'https://api.bitaps.com/btc/v1/blockchain/transaction/{}'.format(txid.hex())

    @staticmethod
    def fetch(txid, tx_index, testnet=False):
        if TxFetcher.cache.get(txid) is not None:
            return TxFetcher.cache[txid]
        # Fetch output transaction
        url = TxFetcher.get_url(txid, testnet)
        try:
            response = requests.get(url)
            tx_json = response.json()
            tx_out_data = tx_json['data']['vOut'][str(tx_index)]
            tx_amount = tx_out_data['value']
        except KeyError:
            raise RuntimeError("Failed to fetch tx {} at output index {}.  Testnet: {}.\n Page dump\n{}".format(txid.hex(), tx_index, testnet, response.text))
        time.sleep(2)
        tx_pubkey_bytes = bytes.fromhex(tx_out_data['scriptPubKey'])
        tx_script_pubkey = Script.parse(BytesIO(tx_pubkey_bytes), len(tx_pubkey_bytes))
        tx_out = TxOut(amount=tx_amount, script_pubkey=tx_script_pubkey)
        TxFetcher.cache[txid] = tx_out
        return tx_out


class TxTests(unittest.TestCase):

    def testParseVersion(self):
        raw_tx = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(tx.version, 1)

    def testParseInputs(self):
        raw_tx = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(len(tx.tx_ins), 1)
        want = bytes.fromhex('d1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81')
        self.assertEqual(tx.tx_ins[0].prev_txid, want)
        self.assertEqual(tx.tx_ins[0].prev_index, 0)
        want = bytes.fromhex('6b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278a')
        self.assertEqual(tx.tx_ins[0].script_sig.serialize(), want)
        self.assertEqual(tx.tx_ins[0].sequence, 0xfffffffe)

    def testParseOutputs(self):
        raw_tx = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(len(tx.tx_outs), 2)
        want = 32454049
        self.assertEqual(tx.tx_outs[0].amount, want)
        want = bytes.fromhex('1976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac')
        self.assertEqual(tx.tx_outs[0].script_pubkey.serialize(), want)
        want = 10011545
        self.assertEqual(tx.tx_outs[1].amount, want)
        want = bytes.fromhex('1976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac')
        self.assertEqual(tx.tx_outs[1].script_pubkey.serialize(), want)

    def testParseLocktime(self):
        raw_tx = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(tx.locktime, 410393)

    def testSerialize(self):
        raw_tx = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(tx.serialize(), raw_tx)

    def testInputValue(self):
        tx_hash = 'd1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81'
        index = 0
        want = 42505594
        tx_in = TxIn(bytes.fromhex(tx_hash), index)
        self.assertEqual(tx_in.amount(), want)

    def testInputPubkey(self):
        tx_hash = 'd1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81'
        index = 0
        tx_in = TxIn(bytes.fromhex(tx_hash), index)
        want = bytes.fromhex('1976a914a802fc56c704ce87c42d7c92eb75e7896bdc41ae88ac')
        self.assertEqual(tx_in.script_pubkey().serialize(), want)

    def testFee(self):
        raw_tx = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(tx.fee(), 40000)
        raw_tx = bytes.fromhex('010000000456919960ac691763688d3d3bcea9ad6ecaf875df5339e148a1fc61c6ed7a069e010000006a47304402204585bcdef85e6b1c6af5c2669d4830ff86e42dd205c0e089bc2a821657e951c002201024a10366077f87d6bce1f7100ad8cfa8a064b39d4e8fe4ea13a7b71aa8180f012102f0da57e85eec2934a82a585ea337ce2f4998b50ae699dd79f5880e253dafafb7feffffffeb8f51f4038dc17e6313cf831d4f02281c2a468bde0fafd37f1bf882729e7fd3000000006a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937feffffff567bf40595119d1bb8a3037c356efd56170b64cbcc160fb028fa10704b45d775000000006a47304402204c7c7818424c7f7911da6cddc59655a70af1cb5eaf17c69dadbfc74ffa0b662f02207599e08bc8023693ad4e9527dc42c34210f7a7d1d1ddfc8492b654a11e7620a0012102158b46fbdff65d0172b7989aec8850aa0dae49abfb84c81ae6e5b251a58ace5cfeffffffd63a5e6c16e620f86f375925b21cabaf736c779f88fd04dcad51d26690f7f345010000006a47304402200633ea0d3314bea0d95b3cd8dadb2ef79ea8331ffe1e61f762c0f6daea0fabde022029f23b3e9c30f080446150b23852028751635dcee2be669c2a1686a4b5edf304012103ffd6f4a67e94aba353a00882e563ff2722eb4cff0ad6006e86ee20dfe7520d55feffffff0251430f00000000001976a914ab0c0b2e98b1ab6dbf67d4750b0a56244948a87988ac005a6202000000001976a9143c82d7df364eb6c75be8c80df2b3eda8db57397088ac46430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(tx.fee(), 140500)

    def testSigHash(self):
        raw_tx = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        want = int('27e0c5994dec7824e56dec6b2fcb342eb7cdb0d0957c2fce9882f715e85d81a6', 16)
        self.assertEqual(tx.sig_hash(0), want)

    def testVerifyp2pkh(self):
        raw_tx = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertTrue(tx.verify())
        raw_tx = bytes.fromhex('010000000148dcc16482f5c835828020498ec1c35f48a578585721b5a77445a4ce93334d18000000006a4730440220636b9f822ea2f85e6375ecd066a49cc74c20ec4f7cf0485bebe6cc68da92d8ce022068ae17620b12d99353287d6224740b585ff89024370a3212b583fb454dce7c160121021f955d36390a38361530fb3724a835f4f504049492224a028fb0ab8c063511a7ffffffff0220960705000000001976a914d23541bd04c58a1265e78be912e63b2557fb439088aca0860100000000001976a91456d95dc3f2414a210efb7188d287bff487df96c688ac00000000')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream, testnet=True)
        self.assertTrue(tx.verify())

    # def testVerifyp2sh(self):
    #     pass

    def testSignInput(self):
        private_key = PrivateKey(8675309)
        stream = BytesIO(bytes.fromhex('010000000199a24308080ab26e6fb65c4eccfadf76749bb5bfa8cb08f291320b3c21e56f0d0d00000000ffffffff02408af701000000001976a914d52ad7ca9b3d096a38e752c2018e6fbc40cdf26f88ac80969800000000001976a914507b27411ccf7f16f10297de6cef3f291623eddf88ac00000000'))
        tx_obj = Tx.parse(stream, testnet=True)
        self.assertTrue(tx_obj.sign_input(0, private_key))
        want = '010000000199a24308080ab26e6fb65c4eccfadf76749bb5bfa8cb08f291320b3c21e56f0d0d0000006b4830450221008ed46aa2cf12d6d81065bfabe903670165b538f65ee9a3385e6327d80c66d3b502203124f804410527497329ec4715e18558082d489b218677bd029e7fa306a72236012103935581e52c354cd2f484fe8ed83af7a3097005b2f9c60bff71d35bd795f54b67ffffffff02408af701000000001976a914d52ad7ca9b3d096a38e752c2018e6fbc40cdf26f88ac80969800000000001976a914507b27411ccf7f16f10297de6cef3f291623eddf88ac00000000'
        self.assertEqual(tx_obj.serialize().hex(), want)


if __name__ == '__main__':
    unittest.main(verbosity=2)
    

