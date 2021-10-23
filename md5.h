/* See md5.c for explanation and copyright information.  */

#ifndef MD5_H
#define MD5_H

#include <stdint.h>

struct MD5Context {
	uint32_t buf[4];
	uint32_t bits[2];
	unsigned char in[64];
};

typedef struct MD5Context MD5_CTX;

void MD5Init (struct MD5Context *context);
void MD5Update (struct MD5Context *context, unsigned char const *buf, unsigned len);
void MD5Final (unsigned char digest[16], struct MD5Context *context);
void MD5Transform(uint32_t buf[4], const unsigned char inraw[64]);

#endif /* !MD5_H */