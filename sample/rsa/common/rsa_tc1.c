#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<assert.h>
#include<openssl/rsa.h>
#include<openssl/pem.h>
#include<openssl/err.h>

void hexprint(char *str, int len)
{
    int i = 0;
    for (i = 0; i < len; i++) {
        printf("%s%02x%s", ((i % 16 == 0 ? "|" : "")),
               *((unsigned char *) str + i),
               (((i + 1) % 16 == 0) ? "|\n" : " "));
    }
    if (i % 16 != 0)
        printf("|\n");
}

static RSA *_getPRV(char *path_key_fullname, char *pwd)
{
    RSA *rsaK = RSA_new();

    OpenSSL_add_all_algorithms();
    BIO *BP = BIO_new_file(path_key_fullname, "rb");
    if (NULL == BP)
        return NULL;

    rsaK = PEM_read_bio_RSAPrivateKey(BP, NULL, NULL, pwd);
    return rsaK;
}

static int _do_rsa_operation(RSA *rsa_ctx, char *instr,
        char *path_key, int inlen, char **outstr, int type)
{
    int rsa_len, num = -1;

    if (!rsa_ctx ||
            !instr ||
            !path_key) {
        perror("input elems error,please check them!");
        return -1;
    }

    rsa_len = RSA_size(rsa_ctx);

    *outstr = (char*)malloc(rsa_len + 1);
    assert(*outstr);
    memset(*outstr, 0, rsa_len + 1);

    switch (type) {
        case 1:
            {
                if (!inlen) {
                    perror("input str len is zero!");
                    goto err;
                }

                num = RSA_public_encrypt(inlen, (unsigned char*)instr,
                        (unsigned char*)*outstr, rsa_ctx, RSA_PKCS1_OAEP_PADDING);
                break;
            }
        case 2:
            {
                num = RSA_private_decrypt(inlen, (unsigned char*)instr,
                        (unsigned char*)*outstr, rsa_ctx, RSA_PKCS1_OAEP_PADDING);
            }
        default:
            break;
    }

    if (num == -1) {
        printf("Got error on enc/dec!\n");
    }
    return num;

err:
    free(*outstr);
    *outstr = NULL;

    return num;
}

int rsa_pub_encrypt(char *str, char *path_key, char **outstr)
{
    int     num;
    RSA     *p_rsa;
    FILE    *file;

    file = fopen(path_key, "r");
    if (!file) {
        perror("open key file error");
        return -1;
    }

#ifdef RSAPUBKEY
    /* support "PUBLIC KEY" format */
    if ((p_rsa = PEM_read_RSA_PUBKEY(file, NULL, NULL, NULL)) == NULL) {
#else
    /* support "RSA PUBLIC KEY" format */
    if ((p_rsa = PEM_read_RSAPublicKey(file, NULL, NULL, NULL)) == NULL) {
#endif
        ERR_print_errors_fp(stdout);
        return -1;
    }

    num = _do_rsa_operation(p_rsa, str, path_key, strlen(str), outstr, 1);

    RSA_free(p_rsa);
    fclose(file);

    return num;
}

int rsa_prv_decrypt(char *str, char *path_key, int inlen, char **outstr)
{
    RSA     *p_rsa;
    FILE    *file;
    int     num;

    file = fopen(path_key, "r");
    if (!file) {
        perror("open key file error");
        return -1;
    }

    //if((p_rsa=PEM_read_RSAPrivateKey(file,NULL,NULL,NULL))==NULL){
    if ((p_rsa = _getPRV(path_key, "123456")) == NULL) {
        ERR_print_errors_fp(stdout);
        return -1;
    }

    num = _do_rsa_operation(p_rsa, str, path_key, inlen, outstr, 2);

    RSA_free(p_rsa);
    fclose(file);

    return num;
}

int main(int argc, char **argv)
{
    char    *ptr_en = NULL;
    char    *ptr_de = NULL;
    int     len;

    printf("source is :%s\n", argv[1]);
    len = rsa_pub_encrypt(argv[1], argv[2], &ptr_en);
    printf("pubkey encrypt:\n");
    hexprint(ptr_en, len);

    rsa_prv_decrypt(ptr_en, argv[3], len, &ptr_de);
    printf("prvkey decrypt:%s\n", ptr_de == NULL ? "NULL" : ptr_de);


    /* cleanup */
    if(ptr_en) {
        free(ptr_en);
    }
    if (ptr_de) {
        free(ptr_de);
    }

    return 0;
}
