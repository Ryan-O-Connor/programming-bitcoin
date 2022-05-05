import unittest

from io import BytesIO
from primitives import *

class Block:

    def __init__(self, version, prev_block, merkle_root, timestamp, bits, nonce):
        self.version = version
        self.prev_block = prev_block
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce

    def __repr__(self):
        targ = "{:x}".format(self.target()).zfill(64)
        return "Block: {}\nTarget: {}\n".format(self.hash().hex(), targ)

    def target(self):
        exponent = self.bits[-1]
        coefficient = little_endian_to_int(self.bits[:-1])
        return coefficient * 256**(exponent - 3)

    def difficulty(self):
        return 0xffff * 256**(0x1d-3) / self.target()

    def check_pow(self):
        return little_endian_to_int(hash256(self.serialize())) < self.target()

    def hash(self):
        return hash256(self.serialize())[::-1]

    def bip9(self):
        return self.version >> 29 == 0b001

    def bip91(self):
        return self.version >> 4 & 1 == 1

    def bip141(self):
        return self.version >> 1 & 1 == 1

    def serialize(self):
        serialization = int_to_little_endian(self.version, 4)
        serialization += int_to_little_endian(self.prev_block, 32)
        serialization += int_to_little_endian(self.merkle_root, 32)
        serialization += int_to_little_endian(self.timestamp, 4)
        serialization += self.bits
        serialization += int_to_little_endian(self.nonce, 4)
        return serialization

    @classmethod
    def parse(cls, stream):
        version = little_endian_to_int(stream.read(4))
        prev_block = little_endian_to_int(stream.read(32))
        merkle_root = little_endian_to_int(stream.read(32))
        timestamp = little_endian_to_int(stream.read(4))
        bits = stream.read(4)
        nonce = little_endian_to_int(stream.read(4))
        return cls(version, prev_block, merkle_root, timestamp, bits, nonce)


class BlockTests(unittest.TestCase):

    def testParse(self):
        stream = BytesIO(bytes.fromhex('020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d'))
        block = Block.parse(stream)
        block_id = '0000000000000000007e9e4c586439b0cdbe13b1370bdd9435d76a644d047523'
        self.assertEqual(block_id, block.hash().hex())

    def testVersion(self):
        stream = BytesIO(bytes.fromhex('020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d'))
        block = Block.parse(stream)
        self.assertTrue(block.bip9())
        self.assertFalse(block.bip91())
        self.assertTrue(block.bip141())

    def testPOW(self):
        stream = BytesIO(bytes.fromhex('020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d'))
        block = Block.parse(stream)
        self.assertEqual(int(block.difficulty()), 888171856257)
        self.assertTrue(block.check_pow())


if __name__ == '__main__':
    unittest.main(verbosity=2)
    
    
