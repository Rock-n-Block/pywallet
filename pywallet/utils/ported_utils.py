import base58
import codecs
import hashlib
import random
import struct
import os
from ecdsa_utils import openssl as ossl
import math
from collections import namedtuple

Point = namedtuple('Point', ['x', 'y'])


def bytes_to_str(b):
    """ Converts bytes into a hex-encoded string.
    Args:
        b (bytes): bytes to encode
    Returns:
        h (str): hex-encoded string corresponding to b.
    """
    return codecs.encode(b, 'hex_codec').decode('ascii')

def address_to_key_hash(s):
    """ Given a Bitcoin address decodes the version and
    RIPEMD-160 hash of the public key.
    Args:
        s (bytes): The Bitcoin address to decode
    Returns:
        (version, h160) (tuple): A tuple containing the version and
        RIPEMD-160 hash of the public key.
    """
    n = base58.b58decode_check(s)
    version = n[0]
    h160 = n[1:]
    return version, h160

def rand_bytes(n, secure=True):
    """ Returns n random bytes.
    Args:
        n (int): number of bytes to return.
        secure (bool): If True, uses os.urandom to generate
            cryptographically secure random bytes. Otherwise, uses
            random.randint() which generates pseudo-random numbers.
    Returns:
        b (bytes): n random bytes.
    """
    if secure:
        return os.urandom(n)
    else:
        return bytes([random.randint(0, 255) for i in range(n)])
