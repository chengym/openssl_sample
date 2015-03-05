#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <openssl/aes.h>
#include <openssl/des.h>

static uint8_t src[] = {
0x01, 0x01, 0x02, 0x02,
0x01, 0x01, 0x02, 0x02,
0x01, 0x01, 0x02, 0x02,
0x01, 0x01, 0x02, 0x02,
0x01, 0x01, 0x02, 0x02,
0x01, 0x01, 0x02, 0x02,
0x01, 0x01, 0x02, 0x02,
0x01, 0x01, 0x02, 0x02,
};
static uint8_t key_128[] = {
0x01, 0x01, 0x01, 0x01,
0x01, 0x01, 0x01, 0x01,
0x01, 0x01, 0x01, 0x01,
0x01, 0x01, 0x01, 0x01,
};
static uint8_t key_192[] = {
0x01, 0x01, 0x01, 0x01,
0x01, 0x01, 0x01, 0x01,
0x01, 0x01, 0x01, 0x01,
0x01, 0x01, 0x01, 0x01,
0x01, 0x01, 0x01, 0x01,
0x01, 0x01, 0x01, 0x01,
};
static uint8_t key_256[] = {
0x01, 0x01, 0x01, 0x01,
0x01, 0x01, 0x01, 0x01,
0x01, 0x01, 0x01, 0x01,
0x01, 0x01, 0x01, 0x01,
0x01, 0x01, 0x01, 0x01,
0x01, 0x01, 0x01, 0x01,
0x01, 0x01, 0x01, 0x01,
0x01, 0x01, 0x01, 0x01,
};

static void _openssl_dump(char *s, uint8_t *buf, uint32_t size)
{
    uint32_t i;
    uint32_t round = size >> 3;

    assert(s);
    assert(buf);

    printf("dump %s\n", s);
    for (i = 0; i < round; i++) {
        printf("0x%02x 0x%02x 0x%02x 0x%02x  0x%02x 0x%02x 0x%02x 0x%02x\n",
                *(buf + (i << 3) + 0),
                *(buf + (i << 3) + 1),
                *(buf + (i << 3) + 2),
                *(buf + (i << 3) + 3),
                *(buf + (i << 3) + 4),
                *(buf + (i << 3) + 5),
                *(buf + (i << 3) + 6),
                *(buf + (i << 3) + 7));
    }
}

/*===========================================================================================*/
static void _aes_encrypt_ecb_ref(uint8_t *usrkey,
        int bits, uint8_t *in, uint8_t *out, unsigned int len)
{
    int i;
    uint32_t round = len >> 4;
    AES_KEY key;

    assert(usrkey);
    assert(in);
    assert(out);

    if (AES_set_encrypt_key(usrkey, bits, &key) < 0) {
        printf("openssl set key fail\n");
        return;
    }

    for(i=0; i< round; i++) {
        AES_ecb_encrypt(in + (i << 4), out + (i << 4), &key, 1);
    }
}
static void _aes_decrypt_ecb_ref(uint8_t *usrkey,
        int bits, uint8_t *in, uint8_t *out, unsigned int len)
{
    int         i;
    uint32_t    round = len >> 4;
    AES_KEY     key;

    assert(usrkey);
    assert(in);
    assert(out);

    if (AES_set_decrypt_key(usrkey, bits, &key) < 0) {
        printf("openssl set key fail\n");
        return;
    }

    for(i=0; i< round; i++) {
        AES_ecb_encrypt(in + (i << 4), out + (i << 4), &key, 0);
    }
}
static int  _openssl_aes_ecb(uint32_t keysizebit)
{
    int         ret;
    void        *p_src, *p_dest;
    void        *p_plain_openssl;
    uint8_t     *p_key;
    uint32_t    srcLen = 32;
    uint32_t    destLen = srcLen;

    p_src = malloc(srcLen);
    assert(p_src);
    memcpy(p_src, src, srcLen);
    p_dest = malloc(destLen);
    assert(p_dest);
    p_plain_openssl = malloc(destLen);
    assert(p_plain_openssl);

    switch (keysizebit) {
        case 128:
            p_key = key_128;
            break;
        case 192:
            p_key = key_192;
            break;
        case 256:
            p_key = key_256;
            break;
        default:
            assert(0);
    }

    _aes_encrypt_ecb_ref(p_key, keysizebit, p_src, p_dest, destLen);

    _openssl_dump("aes-ecb cipher", p_dest, destLen);

    _aes_decrypt_ecb_ref(p_key, keysizebit, p_dest, p_plain_openssl, destLen);
    ret = memcmp(p_plain_openssl, p_src, srcLen);
    if (0 != ret) {
        printf("---> NOT equal equal with orignal msg -- AES-ECB\n\n");
    } else {
        printf("---> Success equal with orignal msg -- AES-ECB\n\n");
    }

    free(p_src);
    free(p_dest);
    free(p_plain_openssl);
    return 0;
}
static void _openssl_aes_ecb_main(void)
{
    _openssl_aes_ecb(128);
    _openssl_aes_ecb(192);
    _openssl_aes_ecb(256);
}

/*===========================================================================================*/
static char fake_iv16[] = {
    0x01, 0x02, 0x03, 0x04,
    0x01, 0x02, 0x03, 0x04,
    0x01, 0x02, 0x03, 0x04,
    0x01, 0x02, 0x03, 0x04,
};
static void _aes_encrypt_cbc_ref(uint8_t *usrkey, int bits,
        uint8_t *iv, uint8_t *in, uint8_t *out, unsigned int len)
{
    AES_KEY     key;
    uint8_t     usriv[16];

    assert(usrkey);
    assert(iv);
    assert(in);
    assert(out);

    if (AES_set_encrypt_key(usrkey, bits, &key) < 0) {
        printf("openssl set key fail\n");
        return;
    }

    memcpy(usriv, iv, 16);
    AES_cbc_encrypt((unsigned char*)in,
            (unsigned char*)out, len, &key, usriv, 1);
    return;
}

static void _aes_decrypt_cbc_ref(uint8_t *usrkey, int bits,
        uint8_t *iv, uint8_t *in, uint8_t *out, unsigned int len)
{
    AES_KEY     key;
    uint8_t     usriv[16];

    assert(usrkey);
    assert(iv);
    assert(in);
    assert(out);

    if (AES_set_decrypt_key(usrkey, bits, &key) < 0) {
        printf("openssl set key fail\n");
        return;
    }
    memcpy(usriv, iv, 16);
    AES_cbc_encrypt(in, out, len, &key, usriv, 0);
    return;
}
static int  _openssl_aes_cbc(uint32_t keysizebit)
{
    int         ret;
    void        *p_src, *p_dest;
    void        *p_plain_openssl;
    uint8_t     *p_key;
    uint32_t    srcLen = 32;
    uint32_t    destLen = srcLen;

    p_src = malloc(srcLen);
    assert(p_src);
    memcpy(p_src, src, srcLen);
    p_dest = malloc(destLen);
    assert(p_dest);
    p_plain_openssl = malloc(destLen);
    assert(p_plain_openssl);

    switch (keysizebit) {
        case 128:
            p_key = key_128;
            break;
        case 192:
            p_key = key_192;
            break;
        case 256:
            p_key = key_256;
            break;
        default:
            assert(0);
    }

    _aes_encrypt_cbc_ref(p_key, keysizebit, (uint8_t*)fake_iv16, p_src, p_dest, destLen);

    _openssl_dump("aes-cbc cipher", p_dest, destLen);

    _aes_decrypt_cbc_ref(p_key, keysizebit, (uint8_t*)fake_iv16, p_dest, p_plain_openssl, destLen);

    ret = memcmp(p_plain_openssl, p_src, srcLen);
    if (0 != ret) {
        printf("---> NOT equal equal with orignal msg -- AES-CBC\n\n");
    } else {
        printf("---> Success equal with orignal msg -- AES-CBC\n\n");
    }

    free(p_src);
    free(p_dest);
    free(p_plain_openssl);
    return 0;
}
static void _openssl_aes_cbc_main(void)
{
    _openssl_aes_cbc(128);
    _openssl_aes_cbc(192);
    _openssl_aes_cbc(256);
}

/*===========================================================================================*/
static void _openssl_aes_ctr_128(uint8_t *usrkey, int keybits, uint8_t *iv,
        uint8_t *in, uint8_t *out, unsigned int len)
{
    AES_KEY     key;
    uint8_t     usriv[16];
    uint8_t     ecount_buf[16];
    unsigned int num = 0;

    memcpy(usriv, iv, 16);
    memset(ecount_buf, 0, 16);

    if (AES_set_encrypt_key(usrkey, keybits, &key) < 0) {
        printf("openssl set aes key fail\n");
        return;
    }

    AES_ctr128_encrypt(in, out, len, &key, usriv, ecount_buf, &num);
    return;
}
static int  _openssl_aes_ctr(uint32_t keysizebit)
{
    int         ret;
    void        *p_src, *p_dest;
    void        *p_plain_openssl;
    uint8_t     *p_key;
    uint32_t    srcLen = 32;
    uint32_t    destLen = srcLen;

    p_src = malloc(srcLen);
    assert(p_src);
    memcpy(p_src, src, srcLen);
    p_dest = malloc(destLen);
    assert(p_dest);
    p_plain_openssl = malloc(destLen);
    assert(p_plain_openssl);

    switch (keysizebit) {
        case 128:
            p_key = key_128;
            break;
        case 192:
            p_key = key_192;
            break;
        case 256:
            p_key = key_256;
            break;
        default:
            assert(0);
    }

    _openssl_aes_ctr_128(p_key, keysizebit, (uint8_t*)fake_iv16, p_src, p_dest, destLen);

    _openssl_dump("aes-ctr cipher", p_dest, destLen);

    _openssl_aes_ctr_128(p_key, keysizebit, (uint8_t*)fake_iv16, p_dest, p_plain_openssl, destLen);

    ret = memcmp(p_plain_openssl, p_src, srcLen);
    if (0 != ret) {
        printf("---> NOT equal equal with orignal msg -- AES-CTR\n\n");
    } else {
        printf("---> Success equal with orignal msg -- AES-CTR\n\n");
    }

    free(p_src);
    free(p_dest);
    free(p_plain_openssl);
    return 0;
}
static void _openssl_aes_ctr_main(void)
{
    _openssl_aes_ctr(128);
}

/*===========================================================================================*/
static char key_des3_168[] = {
    0x02, 0x02, 0x02, 0x02,
    0x02, 0x02, 0x02, 0x02,
    0x02, 0x02, 0x02, 0x02,
    0x02, 0x02, 0x02, 0x02,
    0x02, 0x02, 0x02, 0x02,
    0x02, 0x02, 0x02, 0x02
};
static void _openssl_des3_ecb_enc(unsigned char *key0,
        unsigned char *key1, unsigned char *key2, unsigned char * iv,
        unsigned char * in, unsigned char * out, unsigned int len)
{
    uint32_t  i;
    unsigned char key1tmp[8];
    unsigned char key2tmp[8];
    unsigned char key3tmp[8];
    unsigned char ivtmp[8];
    DES_key_schedule des_key1;
    DES_key_schedule des_key2;
    DES_key_schedule des_key3;

    memcpy(key1tmp, key0, 8);
    memcpy(key2tmp, key1, 8);
    memcpy(key3tmp, key2, 8);
    memcpy(ivtmp, iv, 8);

    DES_set_key((const_DES_cblock *)key1tmp, &des_key1);
    DES_set_key((const_DES_cblock *)key2tmp, &des_key2);
    DES_set_key((const_DES_cblock *)key3tmp, &des_key3);
    for (i = 0; i < len; i += 8)
        DES_ecb3_encrypt((const_DES_cblock*)(in + i), (DES_cblock*)(out + i),
                &des_key1, &des_key2, &des_key3, DES_ENCRYPT);
    return;
}
static void _openssl_des3_ecb_dec (unsigned char *key0,
        unsigned char *key1, unsigned char *key2, unsigned char *iv,
        unsigned char *in, unsigned char *out, unsigned int len)
{
    uint32_t  i;
    unsigned char key1tmp[8];
    unsigned char key2tmp[8];
    unsigned char key3tmp[8];
    unsigned char ivtmp[8];
    DES_key_schedule des_key1;
    DES_key_schedule des_key2;
    DES_key_schedule des_key3;

    memcpy(key1tmp, key0, 8);
    memcpy(key2tmp, key1, 8);
    memcpy(key3tmp, key2, 8);
    memcpy(ivtmp, iv, 8);

    DES_set_key((const_DES_cblock *)key1tmp, &des_key1);
    DES_set_key((const_DES_cblock *)key2tmp, &des_key2);
    DES_set_key((const_DES_cblock *)key3tmp, &des_key3);
    for (i = 0; i < len; i += 8)
        DES_ecb3_encrypt((const_DES_cblock*)(in + i), (DES_cblock*)(out + i),
                &des_key1, &des_key2, &des_key3, DES_DECRYPT);
    return;
}
static void _openssl_des3_cbc_enc(unsigned char *key0, unsigned char *key1,
        unsigned char *key2, unsigned char *iv,
        unsigned char *in, unsigned char *out,
        unsigned int len)
{
    unsigned char key1tmp[8];
    unsigned char key2tmp[8];
    unsigned char key3tmp[8];
    unsigned char ivtmp[8];
    DES_key_schedule des_key1;
    DES_key_schedule des_key2;
    DES_key_schedule des_key3;

    memcpy(key1tmp, key0, 8);
    memcpy(key2tmp, key1, 8);
    memcpy(key3tmp, key2, 8);
    memcpy(ivtmp, iv, 8);

    DES_set_key((const_DES_cblock *) key1tmp, &des_key1);
    DES_set_key((const_DES_cblock *) key2tmp, &des_key2);
    DES_set_key((const_DES_cblock *) key3tmp, &des_key3);
    DES_ede3_cbc_encrypt(in, out, len,
            &des_key1, &des_key2, &des_key3, (DES_cblock *) ivtmp, DES_ENCRYPT);
    return;
}
static void _openssl_des3_cbc_dec(unsigned char *key0, unsigned char *key1,
        unsigned char *key2, unsigned char *iv,
        unsigned char *in, unsigned char *out,
        unsigned int len)
{
    unsigned char key1tmp[8];
    unsigned char key2tmp[8];
    unsigned char key3tmp[8];
    unsigned char ivtmp[8];
    DES_key_schedule des_key1;
    DES_key_schedule des_key2;
    DES_key_schedule des_key3;

    memcpy(key1tmp, key0, 8);
    memcpy(key2tmp, key1, 8);
    memcpy(key3tmp, key2, 8);
    memcpy(ivtmp, iv, 8);

    DES_set_key((const_DES_cblock *) key1tmp, &des_key1);
    DES_set_key((const_DES_cblock *) key2tmp, &des_key2);
    DES_set_key((const_DES_cblock *) key3tmp, &des_key3);
    DES_ede3_cbc_encrypt(in, out, len,
            &des_key1, &des_key2, &des_key3, (DES_cblock *) ivtmp, DES_DECRYPT);
    return;
}
#define DES3_ECB 0
#define DES3_CBC 1
static int  _openssl_des3_cbc(uint32_t type)
{
    int         ret;
    void        *p_src, *p_dest;
    void        *p_plain_openssl;
    uint8_t     *p_key;
    uint32_t    srcLen = 32;
    uint32_t    destLen = srcLen;
    uint8_t     *iv;

    void (*_g_des3_enc_op)(unsigned char *key0, unsigned char *key1,
        unsigned char *key2, unsigned char *iv,
        unsigned char *in, unsigned char *out,
        unsigned int len);
    void (*_g_des3_dec_op)(unsigned char *key0, unsigned char *key1,
        unsigned char *key2, unsigned char *iv,
        unsigned char *in, unsigned char *out,
        unsigned int len);

    p_src = malloc(srcLen);
    assert(p_src);
    memcpy(p_src, src, srcLen);
    p_dest = malloc(destLen);
    assert(p_dest);
    p_plain_openssl = malloc(destLen);
    assert(p_plain_openssl);

    p_key = (uint8_t*)key_des3_168;
    iv = (uint8_t*)fake_iv16;

    if (DES3_ECB == type) {
        _g_des3_enc_op = _openssl_des3_ecb_enc;
        _g_des3_dec_op = _openssl_des3_ecb_dec;
    } else if (DES3_CBC == type) {
        _g_des3_enc_op = _openssl_des3_cbc_enc;
        _g_des3_dec_op = _openssl_des3_cbc_dec;
    } else {
        assert(0);
    }

    _g_des3_enc_op((unsigned char*)p_key, (unsigned char*)p_key + 8,
            (unsigned char*)p_key + 16, iv, p_src, p_dest, srcLen);

    _openssl_dump("DES3 cipher", p_dest, destLen);

    _g_des3_dec_op((unsigned char*)p_key, (unsigned char*)p_key + 8,
            (unsigned char*)p_key + 16, iv, p_dest, p_plain_openssl, destLen);

    ret = memcmp(p_plain_openssl, p_src, srcLen);
    if (0 != ret) {
        printf("---> NOT equal equal with orignal msg -- DES3-CBC\n\n");
    } else {
        printf("---> Success equal with orignal msg -- DES3-CBC\n\n");
    }

    free(p_src);
    free(p_dest);
    free(p_plain_openssl);
    return 0;
}
static void _openssl_des3_main(void)
{
    _openssl_des3_cbc(DES3_ECB);
    _openssl_des3_cbc(DES3_CBC);
}
/*===========================================================================================*/

int main()
{
    _openssl_aes_ecb_main();
    _openssl_aes_cbc_main();
    _openssl_aes_ctr_main();

    _openssl_des3_main();

    return 0;
}
