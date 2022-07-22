/**
* @file hmac_sha1.c  Implements HMAC-SHA1 as of RFC 2202
*
* Copyright (C) 2010 Creytiv.com
*/
#include <string.h>
#include <stdint.h>

#ifdef USE_OPENSSL
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#else

#include "sha.h"

#endif

#include "hmac.h"

#include <stdio.h>
/** SHA-1 Block size */
#ifndef SHA_BLOCKSIZE
#define SHA_BLOCKSIZE   (64)
#endif


/**
* Function to compute the digest
*
* @param k   Secret key
* @param lk  Length of the key in bytes
* @param d   Data
* @param ld  Length of data in bytes
* @param out Digest output
* @param t   Size of digest output
*/
void hmac_sha1(const uint8_t *k,  /* secret key */
        size_t lk,       /* length of the key in bytes */
        const uint8_t *d,  /* data */
        size_t ld,       /* length of data in bytes */
        uint8_t *out,      /* output buffer, at least "t" bytes */
        size_t *t) {
#ifdef USE_OPENSSL

	if (!HMAC(EVP_sha1(), k, (int)lk, d, ld, out, t)) {
		ERR_clear_error();
	}
#else
    uint8_t cache[76] = {0};
    memcpy(cache, d, ld);
    
    printf("\n 需要加密的数据:\n");
    for (int idx = 0; idx < ld; idx++) {
//           printf("%02x",d[idx]);
        printf("\'%c\'",d[idx]);
//        printf_bin_8(d[idx]);
    }
    printf("\n");
    SHA_CTX ictx, octx;
    uint8_t isha[SHA_DIGEST_LENGTH], osha[SHA_DIGEST_LENGTH];
    uint8_t key[SHA_DIGEST_LENGTH];
    uint8_t buf[SHA_BLOCKSIZE];
    size_t i;

    if (lk > SHA_BLOCKSIZE) {
        SHA_CTX tctx;

        SHA1_Init(&tctx);
        SHA1_Update(&tctx, k, lk);
        SHA1_Final(key, &tctx);

        k = key;
        lk = SHA_DIGEST_LENGTH;
    }

    /**** Inner Digest ****/

    SHA1_Init(&ictx);

    /* Pad the key for inner digest */
    for (i = 0; i < lk; ++i) {
        buf[i] = k[i] ^ 0x36;
    }
    for (i = lk; i < SHA_BLOCKSIZE; ++i) {
        buf[i] = 0x36;
    }

    SHA1_Update(&ictx, buf, SHA_BLOCKSIZE);
    SHA1_Update(&ictx, d, ld);

    SHA1_Final(isha, &ictx);

    /**** Outer Digest ****/

    SHA1_Init(&octx);

    /* Pad the key for outter digest */

    for (i = 0; i < lk; ++i) {
        buf[i] = k[i] ^ 0x5c;
    }
    for (i = lk; i < SHA_BLOCKSIZE; ++i) {
        buf[i] = 0x5c;
    }

    SHA1_Update(&octx, buf, SHA_BLOCKSIZE);
    SHA1_Update(&octx, isha, SHA_DIGEST_LENGTH);

    SHA1_Final(osha, &octx);

    /* truncate and print the results */
    *t = *t > SHA_DIGEST_LENGTH ? SHA_DIGEST_LENGTH : *t;
    memcpy(out, osha, *t);
#endif
}

#define BLOCK_SIZE SHA_BLOCKSIZE

void hmac1_sha1(const char *text, size_t text_len, const char *key, size_t key_len, void *digest) {
    uint8_t cache[76] = {0};
    memcpy(cache, text, text_len);
    
    printf("\n需要加密的数据:\n");
    for (int idx = 0; idx < text_len; idx++) {
//           printf("%02x",d[idx]);
        printf("\'%c\'",text[idx]);
//        printf_bin_8(d[idx]);
    }
    printf("\n");
    unsigned char k_ipad[BLOCK_SIZE+1];
    unsigned char k_opad[BLOCK_SIZE+1];
    unsigned char tk[SHA1HashSize];
    if(key_len > BLOCK_SIZE) {
        SHA1Context ctx;
        SHA1Reset(&ctx);
        SHA1Input(&ctx, key, key_len);
        SHA1Result(&ctx, tk);
        key_len = SHA1HashSize;
        key = tk;
    }
    bzero(k_ipad, sizeof(k_ipad));
    bzero(k_opad, sizeof(k_opad));
    bcopy(key, k_ipad, key_len);
    bcopy(key, k_opad, key_len);
    for(int i=0; i<BLOCK_SIZE; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }
    SHA1Context context;
    // inner
    SHA1Reset(&context);
    SHA1Input(&context, k_ipad, BLOCK_SIZE);
    SHA1Input(&context, text, text_len);
    SHA1Result(&context, digest);
    // outer
    SHA1Reset(&context);
    SHA1Input(&context, k_opad, BLOCK_SIZE);
    SHA1Input(&context, digest, SHA1HashSize);
    SHA1Result(&context, digest);
    return;
}

