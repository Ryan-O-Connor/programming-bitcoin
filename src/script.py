
import unittest

from io import BytesIO
from ecc import secp256k1Point, Signiture
from primitives import *

T_ELEMENT = 0
T_OP_CODE = 1


OP_NAMES = {0: "OP_0",
            81: "OP_1",
            118: "OP_DUP",
            136: "OP_EQUALVERIFY",
            169: "OP_HASH160",
            170: "OP_HASH256",
            172: "OP_CHECKSIG"}


class Interpreter:

    def __init__(self):
        self.stack = []
        self.altstack = []

    def assert_stack_length(self, length):
        if len(self.stack) < length:
            raise RuntimeError("Invalid stack length: {}".format(length))

    def evaluate(self, script, message_hash):
        for token in script:
            if token.getType() == T_ELEMENT:
                self.stack.append(token.getValue())
            else:
                op_code = token.getValue()
                try:
                    match op_code:
                        case 0:
                            # OP_0
                            self.stack.append(b'')
                        case 81:
                            # OP_1
                            self.stack.append(b'\x01')
                        case 118:
                            # OP_DUP
                            self.assert_stack_length(1)
                            self.stack.append(self.stack[-1])
                        case 136:
                            # OP_EQUALVERIFY
                            self.assert_stack_length(2)
                            element1 = self.stack.pop()
                            element2 = self.stack.pop()
                            if element1 != element2:
                                raise RuntimeError("Top two stack elements are not equal")
                        case 169:
                            # OP_HASH160
                            self.assert_stack_length(1)
                            top_element = self.stack.pop()
                            self.stack.append(hash160(top_element))
                        case 170:
                            # OP_HASH256
                            self.assert_stack_length(1)
                            top_element = self.stack.pop()
                            self.stack.append(hash256(top_element))
                        case 172:
                            # OP_CHECKSIG
                            self.assert_stack_length(2)
                            pubkey = secp256k1Point.parse(self.stack.pop())
                            sig = Signiture.parse(self.stack.pop())
                            if pubkey.verify(message_hash, sig):
                                self.stack.append(b'')
                            else:
                                self.stack.append(b'\x01')
                except RuntimeError:
                    print("Invalid transaction")
                    return False
        if len(self.stack) == 0:
            return False
        if self.stack.pop() == b'':
            return False
        return True      


class Token:

    def __init__(self, value, type):
        self.value = value
        self.type = type

    def __repr__(self):
        if self.type == T_ELEMENT:
            return "Element token: {}".format(self.value.hex())
        else:
            return "Op code token: {}".format(OP_NAMES[self.value])

    def getValue(self):
        return self.value

    def getType(self):
        return self.type

    def serialize(self):
        if self.type == T_ELEMENT:
            serialization = int_to_little_endian(len(self.value), 1)
            serialization += self.value
        else:
            serialization = int_to_little_endian(self.value, 1)
        return serialization


class Script:

    def __init__(self, tokens=None):
        if tokens is None:
            self.tokens = []
        else:
            self.tokens = tokens

    def __repr__(self):
        string = "Script:\n"
        for token in self:
            string += '\t' + token.__repr__() + '\n'
        return string

    def __add__(self, other):
        return self.__class__(tokens=self.tokens + other.tokens)

    def __iter__(self):
        return iter(self.tokens)

    def length(self):
        return len(self.tokens)

    def serialize(self):
        serialization = b''
        for token in self.tokens:
            serialization += token.serialize()
        return encode_varint(len(serialization)) + serialization

    @classmethod
    def parse(cls, stream):
        byte_length = read_varint(stream)
        tokens = []
        byte_count = 0
        while byte_count < byte_length:
            next_byte = stream.read(1)[0]
            if next_byte >= 1 and next_byte <= 75:
                num_bytes = next_byte
                new_token = Token(value=stream.read(num_bytes), type=T_ELEMENT)
                byte_count += num_bytes
            else:
                op_code = next_byte
                new_token = Token(value=op_code, type=T_OP_CODE)
            tokens.append(new_token)
            byte_count += 1
        if byte_count != byte_length:
            raise SyntaxError("Parsing script failed")
        return cls(tokens)


class ScriptTests(unittest.TestCase):

    def test_parse(self):
        script_hex = '6a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937'
        stream = BytesIO(bytes.fromhex(script_hex))
        script_sig = Script.parse(stream)
        expected_sig = bytes.fromhex('304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a71601')
        self.assertTrue(expected_sig == script_sig.tokens[0].value)
        expected_key = bytes.fromhex('035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937')
        self.assertTrue(expected_key == script_sig.tokens[1].value)

    def test_serialize(self):
        script_hex = '6a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937'
        script_pubkey = BytesIO(bytes.fromhex(script_hex))
        script = Script.parse(script_pubkey)
        self.assertTrue(script.serialize().hex() == script_hex)

if __name__ == '__main__':
    # unittest.main()
    script_hex = '6b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278a'
    stream = BytesIO(bytes.fromhex(script_hex))
    script_sig = Script.parse(stream)
    print(script_sig)
    
