import unittest

from merkle import MerkleTree
from io import BytesIO
from primitives import *

class Block:

    def __init__(self, version, prev_block, merkle_root, timestamp, bits, nonce, tx_hashes=None):
        self.version = version
        self.prev_block = prev_block
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce
        self.tx_hashes = tx_hashes

    def __repr__(self):
        targ = "{:x}".format(self.target()).zfill(64)
        return "Block {}\n\tPrevious Block: {}\n\tMerkle Root: {}\n\tTarget: {}\n".format(
            self.hash().hex(), self.prev_block.hex(), self.merkle_root.hex(), targ)

    def validate_merkle_root(self):
        if self.tx_hashes is None:
            return False
        hashes = [h[::-1] for h in self.tx_hashes]
        merkle_root = MerkleTree.merkleRoot(hashes)[::-1]
        return merkle_root == self.merkle_root

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
        serialization += self.prev_block[::-1]
        serialization += self.merkle_root[::-1]
        serialization += int_to_little_endian(self.timestamp, 4)
        serialization += self.bits
        serialization += int_to_little_endian(self.nonce, 4)
        return serialization

    @classmethod
    def parse(cls, stream):
        version = little_endian_to_int(stream.read(4))
        prev_block = stream.read(32)[::-1]
        merkle_root = stream.read(32)[::-1]
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

    def testMerkleRoot(self):
        hashes_hex = [
            'f54cb69e5dc1bd38ee6901e4ec2007a5030e14bdd60afb4d2f3428c88eea17c1',
            'c57c2d678da0a7ee8cfa058f1cf49bfcb00ae21eda966640e312b464414731c1',
            'b027077c94668a84a5d0e72ac0020bae3838cb7f9ee3fa4e81d1eecf6eda91f3',
            '8131a1b8ec3a815b4800b43dff6c6963c75193c4190ec946b93245a9928a233d',
            'ae7d63ffcb3ae2bc0681eca0df10dda3ca36dedb9dbf49e33c5fbe33262f0910',
            '61a14b1bbdcdda8a22e61036839e8b110913832efd4b086948a6a64fd5b3377d',
            'fc7051c8b536ac87344c5497595d5d2ffdaba471c73fae15fe9228547ea71881',
            '77386a46e26f69b3cd435aa4faac932027f58d0b7252e62fb6c9c2489887f6df',
            '59cbc055ccd26a2c4c4df2770382c7fea135c56d9e75d3f758ac465f74c025b8',
            '7c2bf5687f19785a61be9f46e031ba041c7f93e2b7e9212799d84ba052395195',
            '08598eebd94c18b0d59ac921e9ba99e2b8ab7d9fccde7d44f2bd4d5e2e726d2e',
            'f0bb99ef46b029dd6f714e4b12a7d796258c48fee57324ebdc0bbc4700753ab1',
        ]
        hashes = [bytes.fromhex(x) for x in hashes_hex]
        stream = BytesIO(bytes.fromhex('00000020fcb19f7895db08cadc9573e7915e3919fb76d59868a51d995201000000000000acbcab8bcc1af95d8d563b77d24c3d19b18f1486383d75a5085c4e86c86beed691cfa85916ca061a00000000'))
        block = Block.parse(stream)
        block.tx_hashes = hashes
        self.assertTrue(block.validate_merkle_root())


if __name__ == '__main__':
    unittest.main(verbosity=2)
    
    
