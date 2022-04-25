import unittest

from primitives import *


class FieldElement:

    def __init__(self, num, prime):
        if num >= prime or num < 0:
            error = "Num {} not in field range 0 to {}".format(num, prime-1)
            raise ValueError(error)
        self.num = num
        self.prime = prime

    def __repr__(self):
        return 'FFE_{}({})'.format(self.prime, self.num)

    def _assert_same_field(self, other):
        if self.prime != other.prime:
            raise TypeError("Cannot add two numbers in different fields")

    def __eq__(self, other):
        if other is None:
            return False
        return self.num == other.num and self.prime == other.prime

    def __ne__(self, other):
        return not self == other

    def __add__(self, other):
        self._assert_same_field(other)
        num = (self.num + other.num) % self.prime
        return self.__class__(num, self.prime)

    def __sub__(self, other):
        self._assert_same_field(other)
        num = (self.num - other.num) % self.prime
        return self.__class__(num, self.prime)

    def __mul__(self, other):
        self._assert_same_field(other)
        num = (self.num * other.num) % self.prime
        return self.__class__(num, self.prime)

    def __pow__(self, exp):
        exp = exp % (self.prime - 1)
        num = pow(self.num, exp, self.prime)
        return self.__class__(num, self.prime)

    def __truediv__(self, other):
        other_inv_num = pow(other.num, other.prime - 2, other.prime)
        other_inv = self.__class__(other_inv_num, other.prime)
        return self * other_inv

    def __rmul__(self, coefficient):
        num = coefficient*self.num % self.prime
        return self.__class__(num, self.prime)


secp256k1_PRIME = 2**256 - 2**32 - 977

class secp256k1FieldElement(FieldElement):

    def __init__(self, num, prime=None):
        super().__init__(num, prime=secp256k1_PRIME)

    def __repr__(self):
        return 'secp256k1FFE_({})'.format(self.num)

    def sqrt(self):
        return self**((secp256k1_PRIME + 1) // 4)


class ECPoint:

    def __init__(self, x, y, a, b):
        if x is not None and y is not None:
            if y**2 != x**3 + a * x + b:
                raise ValueError("({}, {}) is not on the elliptic curve".format(x, y))
        self.a = a
        self.b = b
        self.x = x
        self.y = y

    def __repr__(self):
        if self.x is None and self.y is None:
            pt = "Point(infinity)"
        else:
            pt = "Point({:x}, {:x})".format(self.x.num, self.y.num)
        return "{} on elliptic curve a={}, b={}".format(pt, self.a, self.b)

    def _assert_same_curve(self, other):
        if self.a != other.a or self.b != other.b:
            raise TypeError("Points {} and {} are not on the same curve".format(self, other))

    def __eq__(self, other):
        return self.x == other.x and self.y == other.y \
            and self.a == other.a and self.b == other.b

    def __ne__(self, other):
        return not self == other

    def __add__(self, other):
        # Let self = P1 and other = P2
        self._assert_same_curve(other)
        if self.x is None and self.y is None:
            x3 = other.x
            y3 = other.y
        elif other.x is None and other.y is None:
            x3 = self.x
            y3 = self.y
        elif self.x == other.x and self.y != other.y or \
                self == other and self.y == 0 * self.x:
            x3 = None
            y3 = None
        elif self.x != other.x and self.y != other.y:
            s = (other.y - self.y) / (other.x - self.x)
            x3 = s**2 - self.x - other.x
            y3 = s*(self.x - x3) - self.y
        elif self == other:
            s = (3*self.x**2 + self.a)/(2*self.y)
            x3 = s**2 - 2*self.x
            y3 = s*(self.x - x3) - self.y
        else:
            raise RuntimeError("Failed to add {} and {}".format(self, other))
        return self.__class__(x3, y3, self.a, self.b)

    def __rmul__(self, coefficient):
        # Scalar multiplication by binary expansion
        current = self
        result = self.__class__(None, None, self.a, self.b)
        while coefficient:
            if coefficient & 1:
                result += current
            current += current
            coefficient >>= 1
        return result


# secp256k1 curve parameters
secp256k1_A = secp256k1FieldElement(0)
secp256k1_B = secp256k1FieldElement(7)
secp256k1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

class secp256k1Point(ECPoint):

    def __init__(self, x, y, a=None, b=None):
        if type(x) == int:
            super().__init__(secp256k1FieldElement(x), secp256k1FieldElement(y), secp256k1_A, secp256k1_B)
        else:
            super().__init__(x, y, secp256k1_A, secp256k1_B)

    def __repr__(self):
        if self.x is None and self.y is None:
            pt = "Point(infinity)"
        else:
            pt = "Point({:x}, {:x})".format(self.x.num, self.y.num)
        return "{} on secp256k1".format(pt)

    def __rmul__(self, coefficient):
        return super().__rmul__(coefficient % secp256k1_N)

    def verify(self, z, sig):
        '''Verify signiture associated with public key'''
        s_inv = pow(sig.s, secp256k1_N - 2, secp256k1_N)
        u = z*s_inv % secp256k1_N
        v = sig.r * s_inv % secp256k1_N
        R = u*secp256k1_G + v*self
        return R.x.num == sig.r

    def address(self, compressed=True, testnet=False):
        '''Public key address'''
        if testnet:
            prefix = b'\x6f'
        else:
            prefix = b'\x00'
        return encode_base58_checksum(prefix + self.hash160(compressed))

    def hash160(self, compressed=True):
        return hash160(self.sec(compressed))

    def sec(self, compressed):
        # Serialize public key in SEC format
        if compressed:
            if self.y.num % 2 == 0:
                prefix = b'\x02'
            else:
                prefix = b'\x03'
            sec_bin = prefix + self.x.num.to_bytes(32, 'big')
        else:
            sec_bin = b'\x04' + self.x.num.to_bytes(32, 'big') + self.y.num.to_bytes(32, 'big')
        return sec_bin

    @classmethod
    def parse(cls, sec_bin):
        # Parse binary SEC format into public key
        prefix = sec_bin[0]
        x = int.from_bytes(sec_bin[1:33], 'big')
        if prefix == '\x04':
            # Uncompressed SEC format
            y = int.from_bytes(sec_bin[33:65], 'big')
        else:
            # Compressed SEC format
            x = secp256k1FieldElement(x)
            v = x**3 + secp256k1_B
            w = v.sqrt()
            if w.num % 2 == 0:
                even_root = w
                odd_root = secp256k1FieldElement(secp256k1_PRIME - w.num)
            else:
                even_root = secp256k1FieldElement(secp256k1_PRIME - w.num)
                odd_root = w
            if prefix == b'\x02':
                y = even_root
            elif prefix == b'\x03':
                y = odd_root
            else:
                raise SyntaxError("Invalid SEC prefix {}".format(prefix))
        return cls(x, y)


# secp256k1 generator point
secp256k1_G = secp256k1Point(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, 
                            0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)


class Signiture:

    def __init__(self, r, s):
        self.r = r
        self.s = s

    def __repr__(self):
        return "Signiture ({:x}, {:x})".format(self.r, self.s)

    def der(self):
        # Serialize signiture in DER format
        result = b'\x02'
        # Encode r
        r_bin = self.r.to_bytes(32, 'big')
        r_bin = r_bin.lstrip(b'\x00')
        if r_bin[0] >= 0x80:
            r_bin = b'\x00' + r_bin
        result += len(r_bin).to_bytes(1, 'big') + r_bin
        # Add marker
        result += b'\x02'
        # Encode s
        s_bin = self.s.to_bytes(32, 'big')
        s_bin = s_bin.lstrip(b'\x00')
        if s_bin[0] >= 0x80:
            s_bin = b'\x00' + s_bin
        result += len(s_bin).to_bytes(1, 'big') + s_bin
        # Encode length of result and prepend
        return b'\x30' + len(result).to_bytes(1, 'big') + result

    @classmethod
    def parse(cls, der_bin):
        # Parse binary DER format into signiture
        start_byte = der_bin[0]
        if start_byte != b'\x30':
            raise SyntaxError("Bad signiture: Invalid start byte {}".format(start_byte))
        total_length = der_bin[1]
        if total_length != len(der_bin[2:]):
            raise SyntaxError("Bad signiture: Invalid total length {}".format(total_length))
        marker = der_bin[2]
        if marker != b'\x02':
            raise SyntaxError("Bad signiture: Invalid marker {}".format(marker))
        r_length = der_bin[3]
        r = int.from_bytes(der_bin[4:4+r_length], 'big')
        next_marker_index = 4 + r_length
        marker = der_bin[next_marker_index]
        if marker != b'\x02':
            raise SyntaxError("Bad signiture: Invalid marker {}".format(marker))
        s_length = der_bin[next_marker_index + 1]
        s = int.from_bytes(der_bin[next_marker_index + 2:next_marker_index + 2 + s_length], 'big')
        return cls(r, s)

class PrivateKey:

    def __init__(self, private_key):
        self.key = private_key

    def __repr__(self):
        return "Private Key: {:x}".format(self.key)

    def public_key(self):
        return self.key * secp256k1_G

    def sign(self, z):
        '''Sign message hash'''
        k = 123456789
        k_inv = pow(k, secp256k1_N-2, secp256k1_N)
        R = (k*secp256k1_G)
        r = R.x.num
        s = (z + r*self.key) * k_inv % secp256k1_N
        if s > secp256k1_N / 2:
            s = secp256k1_N - s
        return Signiture(r, s)

    def wif(self, compressed=True, testnet=False):
        '''Encode private key in WIF format'''
        if testnet:
            prefix = b'\xef'
        else:
            prefix = b'\x80'
        if compressed:
            suffix = b'\x01'
        else:
            suffix = b''
        return encode_base58_checksum(prefix + self.key.to_bytes(32, 'big') + suffix)
        



class FFETests(unittest.TestCase):

    def testAdd(self):
        a = FieldElement(7, 13)
        b = FieldElement(12, 13)
        c = FieldElement(6, 13)
        self.assertTrue(a+b==c)

    def testMult(self):
        a = FieldElement(3, 13)
        b = FieldElement(12, 13)
        c = FieldElement(10, 13)
        self.assertTrue(a*b==c)

    def testPow(self):
        a = FieldElement(3, 13)
        b = FieldElement(1, 13)
        self.assertTrue(a**3==b)
        c = FieldElement(7, 13)
        d = FieldElement(8, 13)
        self.assertTrue(c**-3 == d)

    def testFermat(self):
        prime = 13
        for i in range(prime):
            n = FieldElement(i, prime)
            one = FieldElement(1, prime)
            self.assertTrue(n**(prime-1)==one)

    def testDiv(self):
        a = FieldElement(2, 19)
        b = FieldElement(7, 19)
        c = FieldElement(3, 19)
        self.assertTrue(a/b==c)


class ECPTests(unittest.TestCase):

    def testCreate(self):
        p1 = ECPoint(-1, -1, 5, 7)
        p2 = ECPoint(18, 77, 5, 7)
        self.assertTrue(p1 == p1)
        self.assertFalse(p1 == p2)
        self.assertTrue(p1 != p2)

    def testAdd(self):
        p1 = ECPoint(-1, -1, 5, 7)
        p2 = ECPoint(-1, 1, 5, 7)
        p3 = ECPoint(2, 5, 5, 7)
        p4 = ECPoint(3, -7, 5, 7)
        p5 = ECPoint(18, 77, 5, 7)
        inf = ECPoint(None, None, 5, 7)
        self.assertTrue(p1 == p1 + inf)
        self.assertTrue(inf + p2 == p2)
        self.assertTrue(p1 + p2 == inf)
        self.assertTrue(p4 == p1 + p3)
        self.assertTrue(p1 + p1 == p5)


class ECoFFTests(unittest.TestCase):

    def testCreate(self):
        prime = 223
        a = FieldElement(0, prime)
        b = FieldElement(7, prime)
        valid_points = ((192, 105), (17, 56), (1, 193))
        invalid_points = ((200, 119), (42, 99))
        for x, y in valid_points:
            ECPoint(FieldElement(x, prime), FieldElement(y, prime), a, b)
        for x, y in invalid_points:
            with self.assertRaises(ValueError):
                ECPoint(FieldElement(x, prime), FieldElement(y, prime), a, b)

    def testAdd(self):
        prime = 223
        a = FieldElement(0, prime)
        b = FieldElement(7, prime)
        addition_triplets = (((192, 105), (17, 56), (170, 142)),
                             ((170, 142), (60, 139), (220, 181)),
                             ((47, 71), (17, 56), (215, 68)),
                             ((143, 98), (76, 66), (47, 71)),)
        for (x1, y1), (x2, y2), (x3, y3) in addition_triplets:
            p1 = ECPoint(FieldElement(x1, prime), FieldElement(y1, prime), a, b)
            p2 = ECPoint(FieldElement(x2, prime), FieldElement(y2, prime), a, b)
            p3 = ECPoint(FieldElement(x3, prime), FieldElement(y3, prime), a, b)
            self.assertTrue(p1 + p2 == p3)

    def testRMul(self):
        prime = 223
        a = FieldElement(0, prime)
        b = FieldElement(7, prime)
        g = ECPoint(FieldElement(47, prime), FieldElement(71, prime), a, b)
        p1 = ECPoint(FieldElement(92, prime), FieldElement(47, prime), a, b)
        inf = ECPoint(None, None, a, b)
        self.assertTrue(7*g == p1)
        self.assertTrue(21*g == inf)


class signingTests(unittest.TestCase):

    def testVerify(self):
        public_key1 = secp256k1Point(0x04519fac3d910ca7e7138f7013706f619fa8f033e6ec6e09370ea38cee6a7574, 
                                    0x82b51eab8c27c66e26c858a079bcdf4f1ada34cec420cafc7eac1a42216fb6c4)
        public_key2 = secp256k1Point(0x887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c,
                                    0x61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34)
        z = 0xbc62d4b80d9e36da29c16c5d4d9f11731f36052c72401a76c23c0fb5a9b74423
        r = 0x37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6
        s = 0x8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec
        self.assertTrue(public_key1.verify(z, Signiture(r, s)))
        z = 0xec208baa0fc1c19f708a9ca96fdeff3ac3f230bb4a7ba4aede4942ad003c0f60
        r = 0xac8d1c87e51d0d441be8b3dd5b05c8795b48875dffe00b7ffcfac23010d3a395
        s = 0x68342ceff8935ededd102dd876ffd6ba72d6a427a3edb13d26eb0781cb423c4
        self.assertTrue(public_key2.verify(z, Signiture(r, s)))
        z = 0x7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d
        r = 0xeff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c
        s = 0xc7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6
        self.assertTrue(public_key2.verify(z, Signiture(r, s)))

    def testSign(self):
        private_key = PrivateKey(12345)
        z = int.from_bytes(hash256('Programming Bitcoin!'.encode()), 'big')
        sig = private_key.sign(z)
        public_key = private_key.public_key()
        self.assertTrue(public_key.verify(z, sig))


class serializationTests(unittest.TestCase):

    def testUncompressedSEC(self):
        keys = (5000 , 2018**5, 0xdeadbeef12345)
        secs = ("04ffe558e388852f0120e46af2d1b370f85854a8eb0841811ece0e3e03d282d57c315dc72890a4f10a1481c031b03b351b0dc79901ca18a00cf009dbdb157a1d10", 
                "04027f3da1918455e03c46f659266a1bb5204e959db7364d2f473bdf8f0a13cc9dff87647fd023c13b4a4994f17691895806e1b40b57f4fd22581a4f46851f3b06", 
                "04d90cd625ee87dd38656dd95cf79f65f60f7273b67d3096e68bd81e4f5342691f842efa762fd59961d0e99803c61edba8b3e3f7dc3a341836f97733aebf987121")
        for key, sec in zip(keys, secs):
            private_key = PrivateKey(key)
            public_key = private_key.public_key()
            sec_hex = public_key.sec(compressed=False).hex()
            self.assertTrue(sec_hex == sec)

    def testCompressedSEC(self):
        keys = (5001 , 2019**5, 0xdeadbeef54321)
        secs = ("0357a4f368868a8a6d572991e484e664810ff14c05c0fa023275251151fe0e53d1", 
                "02933ec2d2b111b92737ec12f1c5d20f3233a0ad21cd8b36d0bca7a0cfa5cb8701", 
                "0296be5b1292f6c856b3c5654e886fc13511462059089cdf9c479623bfcbe77690")
        for key, sec in zip(keys, secs):
            private_key = PrivateKey(key)
            public_key = private_key.public_key()
            sec_hex = public_key.sec(compressed=True).hex()
            self.assertTrue(sec_hex == sec)

    def testDER(self):
        r = 0x37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6
        s = 0x8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec
        der = "3045022037206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c60221008ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec"
        sig = Signiture(r, s)
        der_hex = sig.der().hex()
        self.assertTrue(der_hex == der)

    def testBase58(self):
        hex_codes = ("7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d", 
                        "c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6",
                        "eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c")
        base58_codes = ("9MA8fRQrT4u8Zj8ZRd6MAiiyaxb2Y1CMpvVkHQu5hVM6", 
                        "EQJsjkd6JaGwxrjEhfeqPenqHwrBmPQZjJGNSCHBkcF7",
                        "4fE3H2E6XMp4SsxtwinF7w9a34ooUrwWe4WsW1458Pd")
        for hex_code, base58_code in zip(hex_codes, base58_codes):
            hex_base58 = encode_base58(bytes.fromhex(hex_code))
            self.assertTrue(hex_base58 == base58_code)

    def testAddresses(self):
        keys = (5002 , 2020**5, 0x12345deadbeef)
        addresses = ("mmTPbXQFxboEtNRkwfh6K51jvdtHLxGeMA",
                    "mopVkxp8UhXqRYbCYJsbeE1h1fiF64jcoH",
                    "1F1Pn2y6pDb68E5nYJJeba4TLg2U7B6KF1")
        compressions = (False, True, True)
        networks = (True, True, False)
        for key, correct_address, compression, network in zip(keys, addresses, compressions, networks):
            private_key = PrivateKey(key)
            public_key = private_key.public_key()
            address = public_key.address(compression, network)
            self.assertTrue(address == correct_address)

    def testWif(self):
        keys = (5003 , 2021**5, 0x54321deadbeef)
        wifs = ("cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN8rFTv2sfUK",
                "91avARGdfge8E4tZfYLoxeJ5sGBdNJQH4kvjpWAxgzczjbCwxic",
                "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgiuQJv1h8Ytr2S53a")
        compressions = (True, False, True)
        networks = (True, True, False)
        for key, correct_wif, compression, network in zip(keys, wifs, compressions, networks):
            private_key = PrivateKey(key)
            wif = private_key.wif(compression, network)
            self.assertTrue(wif == correct_wif)

        

if __name__ == '__main__':
    unittest.main(verbosity=2)
