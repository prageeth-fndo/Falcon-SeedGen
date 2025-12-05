#!/usr/bin/env python3
"""
Deterministic Falcon keypair generation.
 - falcon-512
 - falcon-512-padded
 - falcon-1024
 - falcon-1024-padded
Same seed + same scheme => same (sk, pk).
This is a demo implementation, not production-hardened.
"""

import os
import ctypes
from ctypes import c_uint8, c_size_t, c_int, POINTER

# Path to shared library
LIB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "c", "libfalconseedgen.so"))
_lib = ctypes.CDLL(LIB_PATH)

# Key sizes (from PQClean api.h files)
# These values must match the macros in:
#   PQClean/crypto_sign/falcon-512/clean/api.h
#   PQClean/crypto_sign/falcon-512-padded/clean/api.h
#   PQClean/crypto_sign/falcon-1024/clean/api.h
#   PQClean/crypto_sign/falcon-1024-padded/clean/api.h
# Adjust if your PQClean version is different.

FALCON512_PK_BYTES        = 897
FALCON512_SK_BYTES        = 1281

FALCON512PADDED_PK_BYTES  = 897
FALCON512PADDED_SK_BYTES  = 1281

FALCON1024_PK_BYTES       = 1793
FALCON1024_SK_BYTES       = 2305

FALCON1024PADDED_PK_BYTES = 1793
FALCON1024PADDED_SK_BYTES = 2305

# C function signatures

_lib.falcon512_keypair_from_seed.argtypes = [
    POINTER(c_uint8), c_size_t,
    POINTER(c_uint8), c_size_t,
    POINTER(c_uint8), c_size_t,
]
_lib.falcon512_keypair_from_seed.restype = c_int

_lib.falcon512_padded_keypair_from_seed.argtypes = [
    POINTER(c_uint8), c_size_t,
    POINTER(c_uint8), c_size_t,
    POINTER(c_uint8), c_size_t,
]
_lib.falcon512_padded_keypair_from_seed.restype = c_int

_lib.falcon1024_keypair_from_seed.argtypes = [
    POINTER(c_uint8), c_size_t,
    POINTER(c_uint8), c_size_t,
    POINTER(c_uint8), c_size_t,
]
_lib.falcon1024_keypair_from_seed.restype = c_int

_lib.falcon1024_padded_keypair_from_seed.argtypes = [
    POINTER(c_uint8), c_size_t,
    POINTER(c_uint8), c_size_t,
    POINTER(c_uint8), c_size_t,
]
_lib.falcon1024_padded_keypair_from_seed.restype = c_int


# Python wrappers

def _ensure_bytes(seed):
    if not isinstance(seed, (bytes, bytearray)):
        raise TypeError("seed must be bytes or bytearray")
    return seed


def falcon512_from_seed(seed: bytes):
    seed = _ensure_bytes(seed)
    seed_arr = (c_uint8 * len(seed))(*seed)
    pk_buf = (c_uint8 * FALCON512_PK_BYTES)()
    sk_buf = (c_uint8 * FALCON512_SK_BYTES)()

    rc = _lib.falcon512_keypair_from_seed(
        seed_arr, len(seed),
        pk_buf, FALCON512_PK_BYTES,
        sk_buf, FALCON512_SK_BYTES,
    )
    if rc != 0:
        raise RuntimeError(f"falcon512_keypair_from_seed failed with rc={rc}")
    return bytes(sk_buf), bytes(pk_buf)


def falcon512_padded_from_seed(seed: bytes):
    seed = _ensure_bytes(seed)
    seed_arr = (c_uint8 * len(seed))(*seed)
    pk_buf = (c_uint8 * FALCON512PADDED_PK_BYTES)()
    sk_buf = (c_uint8 * FALCON512PADDED_SK_BYTES)()

    rc = _lib.falcon512_padded_keypair_from_seed(
        seed_arr, len(seed),
        pk_buf, FALCON512PADDED_PK_BYTES,
        sk_buf, FALCON512PADDED_SK_BYTES,
    )
    if rc != 0:
        raise RuntimeError(f"falcon512_padded_keypair_from_seed failed with rc={rc}")
    return bytes(sk_buf), bytes(pk_buf)


def falcon1024_from_seed(seed: bytes):
    seed = _ensure_bytes(seed)
    seed_arr = (c_uint8 * len(seed))(*seed)
    pk_buf = (c_uint8 * FALCON1024_PK_BYTES)()
    sk_buf = (c_uint8 * FALCON1024_SK_BYTES)()

    rc = _lib.falcon1024_keypair_from_seed(
        seed_arr, len(seed),
        pk_buf, FALCON1024_PK_BYTES,
        sk_buf, FALCON1024_SK_BYTES,
    )
    if rc != 0:
        raise RuntimeError(f"falcon1024_keypair_from_seed failed with rc={rc}")
    return bytes(sk_buf), bytes(pk_buf)


def falcon1024_padded_from_seed(seed: bytes):
    seed = _ensure_bytes(seed)
    seed_arr = (c_uint8 * len(seed))(*seed)
    pk_buf = (c_uint8 * FALCON1024PADDED_PK_BYTES)()
    sk_buf = (c_uint8 * FALCON1024PADDED_SK_BYTES)()

    rc = _lib.falcon1024_padded_keypair_from_seed(
        seed_arr, len(seed),
        pk_buf, FALCON1024PADDED_PK_BYTES,
        sk_buf, FALCON1024PADDED_SK_BYTES,
    )
    if rc != 0:
        raise RuntimeError(f"falcon1024_padded_keypair_from_seed failed with rc={rc}")
    return bytes(sk_buf), bytes(pk_buf)


# Self-test

if __name__ == "__main__":
    import os
    seed = b"\x01" * 32

    print("[TEST] falcon-512")
    sk1, pk1 = falcon512_from_seed(seed)
    sk2, pk2 = falcon512_from_seed(seed)
    print("  pk1 == pk2:", pk1 == pk2, "len(pk) =", len(pk1))
    print("  sk1 == sk2:", sk1 == sk2, "len(sk) =", len(sk1))

    print("[TEST] falcon-512-padded")
    sk1, pk1 = falcon512_padded_from_seed(seed)
    sk2, pk2 = falcon512_padded_from_seed(seed)
    print("  pk1 == pk2:", pk1 == pk2, "len(pk) =", len(pk1))
    print("  sk1 == sk2:", sk1 == sk2, "len(sk) =", len(sk1))

    print("[TEST] falcon-1024")
    sk1, pk1 = falcon1024_from_seed(seed)
    sk2, pk2 = falcon1024_from_seed(seed)
    print("  pk1 == pk2:", pk1 == pk2, "len(pk) =", len(pk1))
    print("  sk1 == sk2:", sk1 == sk2, "len(sk) =", len(sk1))

    print("[TEST] falcon-1024-padded")
    sk1, pk1 = falcon1024_padded_from_seed(seed)
    sk2, pk2 = falcon1024_padded_from_seed(seed)
    print("  pk1 == pk2:", pk1 == pk2, "len(pk) =", len(pk1))
    print("  sk1 == sk2:", sk1 == sk2, "len(sk) =", len(sk1))
