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
            pt = "Point ({}, {})".format(self.x, self.y)
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
            pt = "Point ({}, {})".format(self.x, self.y)
        return "{} on secp256k1".format(pt, self.a, self.b)

    def __rmul__(self, coefficient):
        return super().__rmul__(coefficient % secp256k1_N)

    def verify(self, z, sig):
        s_inv = pow(sig.s, secp256k1_N - 2, secp256k1_N)
        u = z*s_inv % secp256k1_N
        v = sig.r * s_inv % secp256k1_N
        R = u*secp256k1_G + v*self
        return R.x.num == sig.r


# secp256k1 generator point
secp256k1_G = secp256k1Point(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, 
                            0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)


class Signiture:

    def __init__(self, r, s):
        self.r = r
        self.s = s

    def __repr__(self):
        return "Signiture ({:x}, {:x})".format(self.r, self.s)


class PrivateKey:

    def __init__(self, private_key):
        self.key = private_key

    def __repr__(self):
        return "Private Key: {:x}".format(self.key)

    def public_key(self):
        return self.key * secp256k1_G

    def sign(self, z):
        k = 123456789
        k_inv = pow(k, secp256k1_N-2, secp256k1_N)
        R = (k*secp256k1_G)
        r = R.x.num
        s = (z + r*self.key) * k_inv % secp256k1_N
        if s > secp256k1_N / 2:
            s = secp256k1_N - s
        return Signiture(r, s)



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
        z = int.from_bytes(hash256(b'Programming Bitcoin!'), 'big')
        sig = private_key.sign(z)
        public_key = private_key.public_key()
        self.assertTrue(public_key.verify(z, sig))


if __name__ == '__main__':
    unittest.main(verbosity=2)
    
    
    
