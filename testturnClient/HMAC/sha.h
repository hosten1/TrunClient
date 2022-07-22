/**
* @file re_sha.h  Interface to SHA (Secure Hash Standard) functions
*
* Copyright (C) 2010 Creytiv.com
*/

#ifndef SHA_H_
#define SHA_H_ (1)

#ifdef USE_OPENSSL
#include <openssl/sha.h>
#else

/* public api for steve reid's public domain SHA-1 implementation */
/* this file is in the public domain */

/** SHA-1 Context */
typedef struct {
    uint32_t state[5];
    /**< Context state */
    uint32_t count[2];
    /**< Counter       */
    uint8_t buffer[64]; /**< SHA-1 buffer  */
} SHA1_CTX;

/** SHA-1 Context (OpenSSL compat) */
typedef SHA1_CTX SHA_CTX;

/** SHA-1 Digest size in bytes */
#define SHA1_DIGEST_SIZE 20
/** SHA-1 Digest size in bytes (OpenSSL compat) */
#define SHA_DIGEST_LENGTH SHA1_DIGEST_SIZE

void SHA1_Init(SHA1_CTX *context);

void SHA1_Update(SHA1_CTX *context, const void *p, size_t len);

void SHA1_Final(uint8_t digest[SHA1_DIGEST_SIZE], SHA1_CTX *context);



enum
{
    shaSuccess = 0,
    shaNull,            /* Null pointer parameter */
    shaInputTooLong,    /* input data too long */
    shaStateError        /* called Input after Result */
};
#endif
#define SHA1HashSize 20

/*
 *    This structure will hold context information for the SHA-1
 *    hashing operation
 */
typedef struct SHA1Context
{
    uint32_t Intermediate_Hash[SHA1HashSize/4]; /* Message Digest  */
    uint32_t Length_Low;            /* Message length in bits       */
    uint32_t Length_High;            /* Message length in bits       */
                               /* Index into message block array   */
    int_least16_t Message_Block_Index;
    uint8_t Message_Block[64];        /* 512-bit message blocks       */
    int Computed;                /* Is the digest computed?           */
    int Corrupted;               /* Is the message digest corrupted? */
} SHA1Context;

/*
 *    Function Prototypes
 */

int SHA1Reset(SHA1Context *);
int SHA1Input(SHA1Context *, const uint8_t *, unsigned int);
int SHA1Result(SHA1Context *, uint8_t Message_Digest[SHA1HashSize]);

#endif // SHA_H_
