import unittest


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
		return "Point ({}, {}) on elliptic curve a={}, b={}".format(self.x, self.y, self.a, self.b)

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


class FFETests(unittest.TestCase):

	def testadd(self):
		a = FieldElement(7, 13)
		b = FieldElement(12, 13)
		c = FieldElement(6, 13)
		self.assertTrue(a+b==c)

	def testmult(self):
		a = FieldElement(3, 13)
		b = FieldElement(12, 13)
		c = FieldElement(10, 13)
		self.assertTrue(a*b==c)

	def testpow(self):
		a = FieldElement(3, 13)
		b = FieldElement(1, 13)
		self.assertTrue(a**3==b)
		c = FieldElement(7, 13)
		d = FieldElement(8, 13)
		self.assertTrue(c ** -3 == d)

	def testfermat(self):
		prime = 13
		for i in range(prime):
			n = FieldElement(i, prime)
			one = FieldElement(1, prime)
			self.assertTrue(n**(prime-1)==one)

	def testdiv(self):
		a = FieldElement(2, 19)
		b = FieldElement(7, 19)
		c = FieldElement(3, 19)
		self.assertTrue(a/b==c)


class ECPTests(unittest.TestCase):

	def testcreate(self):
		p1 = ECPoint(-1, -1, 5, 7)
		p2 = ECPoint(18, 77, 5, 7)
		self.assertTrue(p1 == p1)
		self.assertFalse(p1 == p2)
		self.assertTrue(p1 != p2)

	def testadd(self):
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

	def testcreate(self):
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

	def testadd(self):
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


if __name__ == '__main__':
	unittest.main(verbosity=2)
