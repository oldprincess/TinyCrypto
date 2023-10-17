#ifndef _TINY_CRYPTO_HASH_SHA1_STANDARD_H
#define _TINY_CRYPTO_HASH_SHA1_STANDARD_H

#include <stdint.h>
#include <stddef.h>

#define SHA1_BLOCK_SIZE  64
#define SHA1_DIGEST_SIZE 20

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * cite from https://www.rfc-editor.org/rfc/rfc3174#section-7.1
 */
typedef struct SHA1Context
{
    uint32_t Intermediate_Hash[SHA1_DIGEST_SIZE / 4]; /* Message Digest  */

    uint32_t Length_Low;  /* Message length in bits      */
    uint32_t Length_High; /* Message length in bits      */

    /* Index into message block array   */
    int_least16_t Message_Block_Index;
    uint8_t       Message_Block[64]; /* 512-bit message blocks      */

    int Computed;  /* Is the digest computed?         */
    int Corrupted; /* Is the message digest corrupted? */
} SHA1Context;

typedef struct _Sha1StandardCTX
{
    SHA1Context ctx;
} Sha1StandardCTX;

void sha1_standard_init(Sha1StandardCTX* ctx);

void sha1_standard_reset(Sha1StandardCTX* ctx);

int sha1_standard_update(Sha1StandardCTX* ctx, const uint8_t* in, size_t inl);

int sha1_standard_final(Sha1StandardCTX* ctx, uint8_t digest[20]);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif