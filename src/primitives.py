import hashlib

BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3

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

def decode_base58_checksum(address):
    num = 0
    for c in address:
        num *= 58
        num += BASE58_ALPHABET.index(c)
    byte_address = num.to_bytes(25, 'big')
    base_address = byte_address[1:-4]
    given_checksum = byte_address[-4:]
    actual_checksum = hash256(byte_address[:-4])[:4]
    if actual_checksum != given_checksum:
        raise ValueError("Bad address: {} {}").format(actual_checksum.hex(), given_checksum.hex())
    return base_address

def read_varint(s):
    '''Reads variable integer from a stream'''
    i = s.read(1)[0]
    if i == 0xfd:
        # 0xfd means the next two bytes are the number
        return little_endian_to_int(s.read(2))
    elif i == 0xfe:
        # 0xfe means the next four bytes are the number
        return little_endian_to_int(s.read(4))
    elif i == 0xff:
        # 0xff means the next eight bytes are the number
        return little_endian_to_int(s.read(8))
    else:
        # anything else is just the integer
        return i

def encode_varint(i):
    '''Encodes an integer as a varint'''
    if i < 0xfd:
        return bytes([i])
    elif i < 0x10000:
        return b'\xfd' + int_to_little_endian(i, 2)
    elif i < 0x100000000:
        return b'\xfe' + int_to_little_endian(i, 4)
    elif i < 0x10000000000000000:
        return b'\xff' + int_to_little_endian(i, 8)
    else:
        raise ValueError('integer too large: {}'.format(i))

