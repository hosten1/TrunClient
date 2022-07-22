/**
* @file re_hmac.h  Interface to HMAC functions
*
* Copyright (C) 2010 Creytiv.com
*/

#ifndef HMAC_H_
#define HMAC_H_ (1)

#include <stdint.h>

void hmac_sha1(const uint8_t *k,   /* secret key */
        size_t lk,  /* length of the key in bytes */
        const uint8_t *d,   /* data */
        size_t ld,  /* length of data in bytes */
        uint8_t *out, /* output buffer, at least "t" bytes */
        size_t *t);

#define MD5HashSize 16

// redis sha1: http://download.redis.io/redis-stable/src/sha1.c

void hmac1_sha1(const char *text, size_t text_len, const char *key, size_t key_len, void *digest);
#endif // HMAC_H_
