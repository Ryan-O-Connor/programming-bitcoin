import hashlib

BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def little_endian_to_int(s):
    return int.from_bytes(s, 'little')

def int_to_little_endian(i, length):
    return i.to_bytes(length, 'little')


def hash160(s):
    '''Apply sha256 followed by ripemd160 to byte string'''
    return hashlib.new('ripemd160', hashlib.sha256(s).digest()).digest()

def hash256(s):
    '''Apply two rounds of sha256 to byte string'''
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()

def encode_base58(s):
    '''Encode byte string in base 58'''
    zero_byte_count = 0
    for c in s:
        if c == 0:
            zero_byte_count += 1
        else:
            break
    num = int.from_bytes(s, 'big')
    result = ''
    while num > 0:
        num, mod = divmod(num, 58)
        result = BASE58_ALPHABET[mod] + result
    return '1' * zero_byte_count + result

def encode_base58_checksum(s):
    '''Encode in base 58 and add checksum'''
    return encode_base58(s + hash256(s)[:4])
