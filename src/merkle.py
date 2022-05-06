

import math
import unittest

from pprint import pprint
from primitives import *


class MerkleTree:

    def __init__(self, n_hashes):
        self.n_hashes = n_hashes
        self.max_depth = math.ceil(math.log(self.n_hashes, 2))
        self.nodes = []
        for depth in range(self.max_depth + 1):
            num_items = math.ceil(self.n_hashes / 2**(self.max_depth - depth))
            self.nodes.append([None] * num_items)
        self.current_depth = 0
        self.current_index = 0

    def __repr__(self):
        return ''

    

    @staticmethod
    def parent(hashL, hashR):
        return hash256(hashL + hashR)

    @staticmethod
    def parentLevel(hash_list):
        n = len(hash_list)
        if n % 2 == 1:
            hash_list.append(hash_list[-1])
        parent_list = []
        for i in range(0, n, 2):
            parent_list.append(MerkleTree.parent(hash_list[i], hash_list[i+1]))
        return parent_list

    @staticmethod
    def merkleRoot(hash_list):
        while len(hash_list) > 1:
            hash_list = MerkleTree.parentLevel(hash_list)
        return hash_list[0]


class MerkleTests(unittest.TestCase):

    def testParent(self):
        hashL = bytes.fromhex('c117ea8ec828342f4dfb0ad6bd140e03a50720ece40169ee38bdc15d9eb64cf5')
        hashR = bytes.fromhex('c131474164b412e3406696da1ee20ab0fc9bf41c8f05fa8ceea7a08d672d7cc5')
        parent_hash = MerkleTree.parent(hashL, hashR).hex()
        self.assertEqual(parent_hash, '8b30c5ba100f6f2e5ad1e2a742e5020491240f8eb514fe97c713c31718ad7ecd')

    def testParentLevel(self):
        hex_hashes = ['c117ea8ec828342f4dfb0ad6bd140e03a50720ece40169ee38bdc15d9eb64cf5',
                        'c131474164b412e3406696da1ee20ab0fc9bf41c8f05fa8ceea7a08d672d7cc5',
                        'f391da6ecfeed1814efae39e7fcb3838ae0b02c02ae7d0a5848a66947c0727b0',
                        '3d238a92a94532b946c90e19c49351c763696cff3db400485b813aecb8a13181',
                        '10092f2633be5f3ce349bf9ddbde36caa3dd10dfa0ec8106bce23acbff637dae',]
        hashes = [bytes.fromhex(hex) for hex in hex_hashes]
        parent_level = MerkleTree.parentLevel(hashes)
        self.assertEqual(parent_level[0].hex(), '8b30c5ba100f6f2e5ad1e2a742e5020491240f8eb514fe97c713c31718ad7ecd')
        self.assertEqual(parent_level[1].hex(), '7f4e6f9e224e20fda0ae4c44114237f97cd35aca38d83081c9bfd41feb907800')
        self.assertEqual(parent_level[2].hex(), '3ecf6115380c77e8aae56660f5634982ee897351ba906a6837d15ebc3a225df0')

    def testMerkleRoot(self):
        hex_hashes = ['c117ea8ec828342f4dfb0ad6bd140e03a50720ece40169ee38bdc15d9eb64cf5',
                        'c131474164b412e3406696da1ee20ab0fc9bf41c8f05fa8ceea7a08d672d7cc5',
                        'f391da6ecfeed1814efae39e7fcb3838ae0b02c02ae7d0a5848a66947c0727b0',
                        '3d238a92a94532b946c90e19c49351c763696cff3db400485b813aecb8a13181',
                        '10092f2633be5f3ce349bf9ddbde36caa3dd10dfa0ec8106bce23acbff637dae',
                        '7d37b3d54fa6a64869084bfd2e831309118b9e833610e6228adacdbd1b4ba161',
                        '8118a77e542892fe15ae3fc771a4abfd2f5d5d5997544c3487ac36b5c85170fc',
                        'dff6879848c2c9b62fe652720b8df5272093acfaa45a43cdb3696fe2466a3877',
                        'b825c0745f46ac58f7d3759e6dc535a1fec7820377f24d4c2c6ad2cc55c0cb59',
                        '95513952a04bd8992721e9b7e2937f1c04ba31e0469fbe615a78197f68f52b7c',
                        '2e6d722e5e4dbdf2447ddecc9f7dabb8e299bae921c99ad5b0184cd9eb8e5908',
                        'b13a750047bc0bdceb2473e5fe488c2596d7a7124b4e716fdd29b046ef99bbf0']
        hashes = [bytes.fromhex(hex) for hex in hex_hashes]
        merkle_root = MerkleTree.merkleRoot(hashes)
        self.assertEqual(merkle_root.hex(), 'acbcab8bcc1af95d8d563b77d24c3d19b18f1486383d75a5085c4e86c86beed6')



if __name__ == '__main__':
    unittest.main(verbosity=2)
    
    
