// Deterministic Falcon key generation from a seed for following schemes:
//   - falcon-512          (clean)
//   - falcon-padded-512   (clean)
//   - falcon-1024         (clean)
//   - falcon-padded-1024  (clean)
// This is a demo code, NOT production-hardened.

#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Include each scheme's api.h with explicit paths
#include "../PQClean/falcon/falcon-512/api.h"
#include "../PQClean/falcon/falcon-padded-512/api.h"
#include "../PQClean/falcon/falcon-1024/api.h"
#include "../PQClean/falcon/falcon-padded-1024/api.h"

// SHAKE256 / FIPS202 from PQClean common
#include "../PQClean/common/fips202.h"

static uint8_t  g_seed[64];
static size_t   g_seedlen = 0;
static uint64_t g_counter = 0;
static int      g_initialized = 0;

static void drbg_init(const uint8_t *seed, size_t seedlen) {
    if (seedlen > sizeof(g_seed)) {
        seedlen = sizeof(g_seed);
    }
    memcpy(g_seed, seed, seedlen);
    g_seedlen = seedlen;
    g_counter = 0;
    g_initialized = 1;
}

static void drbg_randombytes(uint8_t *out, size_t outlen) {
    if (!g_initialized) {
        // Should not happen if used correctly.
        memset(out, 0, outlen);
        return;
    }

    while (outlen > 0) {
        // input = seed || counter (big-endian)
        uint8_t input[64 + 8];
        memcpy(input, g_seed, g_seedlen);
        uint64_t ctr = g_counter;
        for (int i = 0; i < 8; i++) {
            input[g_seedlen + 7 - i] = (uint8_t)(ctr & 0xFF);
            ctr >>= 8;
        }

        uint8_t block[64];
        size_t block_len = (outlen < sizeof(block)) ? outlen : sizeof(block);

        // shake256(output, outlen, input, inlen)
        shake256(block, block_len, input, g_seedlen + 8);

        memcpy(out, block, block_len);
        out     += block_len;
        outlen  -= block_len;
        g_counter++;
    }
}

// randombytes hooks used by PQClean

void randombytes(uint8_t *out, size_t outlen) {
    drbg_randombytes(out, outlen);
}

// Some PQClean code calls PQCLEAN_randombytes()
void PQCLEAN_randombytes(uint8_t *out, size_t outlen) {
    randombytes(out, outlen);
}

// Export macro

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

// 512-clean

EXPORT int falcon512_keypair_from_seed(
    const uint8_t *seed, size_t seedlen,
    uint8_t *pk, size_t pk_len,
    uint8_t *sk, size_t sk_len
) {
    if (seed == NULL || pk == NULL || sk == NULL) {
        return -1;
    }
    if (pk_len != PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES ||
        sk_len != PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES) {
        return -2;
    }

    drbg_init(seed, seedlen);
    return PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(pk, sk);  // 0 on success
}

// 512-padded  (falcon-padded-512)

EXPORT int falcon512_padded_keypair_from_seed(
    const uint8_t *seed, size_t seedlen,
    uint8_t *pk, size_t pk_len,
    uint8_t *sk, size_t sk_len
) {
    if (seed == NULL || pk == NULL || sk == NULL) {
        return -1;
    }
    if (pk_len != PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_PUBLICKEYBYTES ||
        sk_len != PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_SECRETKEYBYTES) {
        return -2;
    }

    drbg_init(seed, seedlen);
    return PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_keypair(pk, sk);
}

// 1024-clean

EXPORT int falcon1024_keypair_from_seed(
    const uint8_t *seed, size_t seedlen,
    uint8_t *pk, size_t pk_len,
    uint8_t *sk, size_t sk_len
) {
    if (seed == NULL || pk == NULL || sk == NULL) {
        return -1;
    }
    if (pk_len != PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES ||
        sk_len != PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES) {
        return -2;
    }

    drbg_init(seed, seedlen);
    return PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair(pk, sk);
}

// 1024-padded (falcon-padded-1024)

EXPORT int falcon1024_padded_keypair_from_seed(
    const uint8_t *seed, size_t seedlen,
    uint8_t *pk, size_t pk_len,
    uint8_t *sk, size_t sk_len
) {
    if (seed == NULL || pk == NULL || sk == NULL) {
        return -1;
    }
    if (pk_len != PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES ||
        sk_len != PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_SECRETKEYBYTES) {
        return -2;
    }

    drbg_init(seed, seedlen);
    return PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_keypair(pk, sk);
}
