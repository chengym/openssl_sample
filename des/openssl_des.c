/************************************************************************
 * 本例采用：
 *    3des-ecb加密方式；
 *    24位密钥，不足24位的右补0x00；
 *    加密内容8位补齐，补齐方式为：少1位补一个0x01,少2位补两个0x02,...
 *    本身已8位对齐的，后面补八个0x08。
 * ************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/des.h>

#define LEN_OF_KEY 24

int main(void)
{
    int     docontinue = 1;
    int     len;
    int     data_len;
    int     data_rest;
    int     key_len;
    int     count;
    int     i;
    char    *data = "hello world!";        /* 明文 */
    char    *k = "01234567899876543210";   /* 原始密钥 */
    unsigned char   ch;
    unsigned char   *src = NULL;  /* 补齐后的明文 */
    unsigned char   *dst = NULL;  /* 解密后的明文 */
    unsigned char   tmp[8];
    unsigned char   in[8];
    unsigned char   out[8];
    unsigned char   key[LEN_OF_KEY];      /* 补齐后的密钥 */
    unsigned char   block_key[9];

    DES_key_schedule    ks, ks2, ks3;

    /* 构造补齐后的密钥 */
    key_len = strlen(k);
    memcpy(key, k, key_len);
    memset(key + key_len, 0x0, LEN_OF_KEY - key_len);

    /* 分析补齐明文所需空间及补齐填充数据 */
    data_len = strlen(data);
    data_rest = data_len % 8;
    len = data_len + (8 - data_rest);
    ch = 8 - data_rest;
    src = (unsigned char *) malloc(len);
    dst = (unsigned char *) malloc(len);

    if (NULL == src || NULL == dst) {
        docontinue = 0;
    }

    if (docontinue) {
        /* 构造补齐后的加密内容 */
        memset(src, 0, len);
        memcpy(src, data, data_len);
        memset(src + data_len, ch, 8 - data_rest);

        /* 密钥置换 */
        memset(block_key, 0, sizeof(block_key));
        memcpy(block_key, key + 0, 8);
        DES_set_key_unchecked((const_DES_cblock *) block_key, &ks);
        memcpy(block_key, key + 8, 8);
        DES_set_key_unchecked((const_DES_cblock *) block_key, &ks2);
        memcpy(block_key, key + 16, 8);
        DES_set_key_unchecked((const_DES_cblock *) block_key, &ks3);

        printf("before encrypt:\n");
        for (i = 0; i < len; i++) {
            printf("0x%.2X ", *(src + i));
        }
        printf("\n");

        /* 循环加密/解密，每8字节一次 */
        count = len / 8;
        for (i = 0; i < count; i++) {
            memset(tmp, 0, 8);
            memset(in, 0, 8);
            memset(out, 0, 8);
            memcpy(tmp, src + 8 * i, 8);

            /* 加密 */
            DES_ecb3_encrypt((const_DES_cblock*)tmp,
                    (DES_cblock*)in, &ks, &ks2, &ks3, DES_ENCRYPT);

            /* 解密 */
            DES_ecb3_encrypt((const_DES_cblock*)in,
                    (DES_cblock*)out, &ks, &ks2, &ks3, DES_DECRYPT);

            /* 将解密的内容拷贝到解密后的明文 */
            memcpy(dst + 8 * i, out, 8);
        }

        printf("after decrypt :\n");
        for (i = 0; i < len; i++) {
            printf("0x%.2X ", *(dst + i));
        }
        printf("\n");
    }

    if (NULL != src) {
        free(src);
        src = NULL;
    }
    if (NULL != dst) {
        free(dst);
        dst = NULL;
    }

    return 0;
}
