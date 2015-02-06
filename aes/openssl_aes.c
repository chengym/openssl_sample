#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <openssl/aes.h>

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


void  aes_encrypt_ecb_ref(uint8_t *usrkey,
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
void  aes_decrypt_ecb_ref(uint8_t *usrkey,
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

    aes_encrypt_ecb_ref(p_key, keysizebit, p_src, p_dest, destLen);

    aes_decrypt_ecb_ref(p_key, keysizebit, p_dest, p_plain_openssl, destLen);
    ret = memcmp(p_plain_openssl, p_src, srcLen);
    if (0 != ret) {
        printf("---> NOT equal equal with orignal msg\n");
    } else {
        printf("---> Success equal with orignal msg\n");
    }

    free(p_src);
    free(p_dest);
    free(p_plain_openssl);
    return 0;
}


int main(void)
{
    _openssl_aes_ecb(128);
    _openssl_aes_ecb(192);
    _openssl_aes_ecb(256);
    return 0;
}
