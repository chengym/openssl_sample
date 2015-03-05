#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>

#define  MD5_SIZE     (16)
#define  SHA1_SIZE    (20)
#define  SHA224_SIZE  (28)
#define  SHA256_SIZE  (32)
#define  SHA384_SIZE  (48)
#define  SHA512_SIZE  (64)

static const char *_g_openssl_string = "Hello world";

static void _openssl_dump(char *s, uint8_t *buf, uint32_t size)
{
    uint32_t i;
    uint32_t round = size >> 2;

    assert(s);
    assert(buf);

    printf("dump %s\n", s);
    for (i = 0; i < round; i++) {
        printf("0x%02x 0x%02x 0x%02x 0x%02x\n",
                *(buf + (i << 2) + 0),
                *(buf + (i << 2) + 1),
                *(buf + (i << 2) + 2),
                *(buf + (i << 2) + 3));
    }
    printf("\n");
}

static void _openssl_do_sha512(uint8_t *message, uint32_t length)
{
    int         ret;
    uint8_t     digest[SHA512_SIZE];
    unsigned char *openssl_ret = NULL;
    SHA512_CTX sha512c;

    assert(message);

    ret = SHA512_Init(&sha512c);
    assert(1 == ret);
    ret = SHA512_Update(&sha512c, message, length);
    assert(1 == ret);
    ret = SHA512_Final(digest, &sha512c);
    assert(1 == ret);
	OPENSSL_cleanse(&sha512c, sizeof(SHA_CTX));

    _openssl_dump("sha512-multi-step", digest, SHA512_SIZE);

    openssl_ret = SHA512(message, length, digest);
    assert(NULL != openssl_ret);

    _openssl_dump("sha512-one-step", digest, SHA512_SIZE);
}

static void _openssl_do_sha384(uint8_t *message, uint32_t length)
{
    int         ret;
    uint8_t     digest[SHA384_SIZE];
    unsigned char *openssl_ret = NULL;
    SHA512_CTX sha384c;

    assert(message);

    ret = SHA384_Init(&sha384c);
    assert(1 == ret);
    ret = SHA384_Update(&sha384c, message, length);
    assert(1 == ret);
    ret = SHA384_Final(digest, &sha384c);
    assert(1 == ret);
	OPENSSL_cleanse(&sha384c, sizeof(SHA_CTX));

    _openssl_dump("sha384-multi-step", digest, SHA384_SIZE);

    openssl_ret = SHA384(message, length, digest);
    assert(NULL != openssl_ret);

    _openssl_dump("sha384-one-step", digest, SHA384_SIZE);
}


static void _openssl_do_sha256(uint8_t *message, uint32_t length)
{
    int         ret;
    uint8_t     digest[SHA256_SIZE];
    unsigned char *openssl_ret = NULL;
    SHA256_CTX sha256c;

    assert(message);

    ret = SHA256_Init(&sha256c);
    assert(1 == ret);
    ret = SHA256_Update(&sha256c, message, length);
    assert(1 == ret);
    ret = SHA256_Final(digest, &sha256c);
    assert(1 == ret);
	OPENSSL_cleanse(&sha256c, sizeof(SHA_CTX));

    _openssl_dump("sha256-multi-step", digest, SHA256_SIZE);

    openssl_ret = SHA256(message, length, digest);
    assert(NULL != openssl_ret);

    _openssl_dump("sha256-one-step", digest, SHA256_SIZE);
}


static void _openssl_do_sha224(uint8_t *message, uint32_t length)
{
    int         ret;
    uint8_t     digest[SHA224_SIZE];
    unsigned char *openssl_ret = NULL;
    SHA256_CTX sha224c;

    assert(message);

    ret = SHA224_Init(&sha224c);
    assert(1 == ret);
    ret = SHA224_Update(&sha224c, message, length);
    assert(1 == ret);
    ret = SHA224_Final(digest, &sha224c);
    assert(1 == ret);
	OPENSSL_cleanse(&sha224c, sizeof(SHA_CTX));

    _openssl_dump("sha224-multi-step", digest, SHA224_SIZE);

    openssl_ret = SHA224(message, length, digest);
    assert(NULL != openssl_ret);

    _openssl_dump("sha224-one-step", digest, SHA224_SIZE);
}

static void _openssl_do_sha1(uint8_t *message, uint32_t length)
{
    int         ret;
    uint8_t     digest[SHA1_SIZE];
    unsigned char *openssl_ret = NULL;
    SHA_CTX sha1c;

    assert(message);

    ret = SHA1_Init(&sha1c);
    assert(1 == ret);
    ret = SHA1_Update(&sha1c, message, length);
    assert(1 == ret);
    ret = SHA1_Final(digest, &sha1c);
    assert(1 == ret);
	OPENSSL_cleanse(&sha1c, sizeof(SHA_CTX));

    _openssl_dump("sha1-multi-step", digest, SHA1_SIZE);

    openssl_ret = SHA1(message, length, digest);
    assert(NULL != openssl_ret);

    _openssl_dump("sha1-one-step", digest, SHA1_SIZE);
}

static void _openssl_do_md5(uint8_t *message, uint32_t length)
{
    int         ret;
    uint8_t     digest[MD5_SIZE];
    unsigned char *openssl_ret = NULL;
    MD5_CTX md5c;

    assert(message);

    ret = MD5_Init(&md5c);
    assert(1 == ret);
    ret = MD5_Update(&md5c, message, length);
    assert(1 == ret);
    ret = MD5_Final(digest, &md5c);
    assert(1 == ret);
	OPENSSL_cleanse(&md5c, sizeof(MD5_CTX));

    _openssl_dump("md5-multi-step", digest, MD5_SIZE);

    openssl_ret = MD5(message, length, digest);
    assert(NULL != openssl_ret);

    _openssl_dump("md5-one-step", digest, MD5_SIZE);
}

int main(void)
{
    _openssl_do_md5((uint8_t*)_g_openssl_string,
            (uint32_t)strlen(_g_openssl_string));

    _openssl_do_sha1((uint8_t*)_g_openssl_string,
            (uint32_t)strlen(_g_openssl_string));

    _openssl_do_sha224((uint8_t*)_g_openssl_string,
            (uint32_t)strlen(_g_openssl_string));

    _openssl_do_sha256((uint8_t*)_g_openssl_string,
            (uint32_t)strlen(_g_openssl_string));

    _openssl_do_sha384((uint8_t*)_g_openssl_string,
            (uint32_t)strlen(_g_openssl_string));

    _openssl_do_sha512((uint8_t*)_g_openssl_string,
            (uint32_t)strlen(_g_openssl_string));

    return 0;
}
