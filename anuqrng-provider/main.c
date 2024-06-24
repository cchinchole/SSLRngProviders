#include <stdio.h>
#include <openssl/core.h>
#include <openssl/rand.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>

OSSL_provider_init_fn QRNGProviderInit;
int main()
{
    OSSL_PROVIDER* prov = NULL;
    OSSL_LIB_CTX *libCtx = OSSL_LIB_CTX_new();
    const char *provName = "aqrng-seed";

    if(OSSL_PROVIDER_add_builtin(libCtx, provName, &QRNGProviderInit))
        prov = OSSL_PROVIDER_load(libCtx, provName);
    if(prov == NULL)
    {
        printf("Failed to find %s provider!\n", provName);
        return 0;
    }
    else
        printf("%s found!\n", provName);

    if(!OSSL_PROVIDER_available(libCtx, provName)) 
    {
        printf("%s is not available!\n", provName);
        return 0;
    }
    else
        printf("%s is available\n", provName);

    if(!OSSL_PROVIDER_self_test(prov))
    {
        printf("%s self test failed!\n", provName);
        return 0;
    }
    else
    {
        printf("%s self test passed!\n", provName);
    }
        
    unsigned char *buf = malloc(5);
    
    for(int i = 0; i < 5; i++)
        buf[i] = (int)'a';

    EVP_RAND *rand = EVP_RAND_fetch(libCtx, provName, NULL);
  
    if(rand == NULL)
    {
        printf("%s provider context failed to load.\n", provName);
        return 0;
    }

    EVP_RAND_CTX *seedCtx = EVP_RAND_CTX_new(rand, NULL);

    EVP_RAND_instantiate(seedCtx, 0, 0, NULL, 0, NULL);

    EVP_RAND_free(rand);
    if( !(seedCtx) )
    {
        printf("SEED CTX Failed\n");
        return 0;
    }
    else
        printf("SEED CTX Succeeded\n");

    OSSL_PARAM params[2], *p = params;
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER, SN_aes_256_ctr, 0);
    *p = OSSL_PARAM_construct_end();
    
    rand = EVP_RAND_fetch(NULL, "CTR-DRBG", NULL);
    EVP_RAND_CTX* drbgCtx = EVP_RAND_CTX_new(rand, seedCtx);
    EVP_RAND_free(rand);
    EVP_RAND_instantiate(drbgCtx, 128, 0, NULL, 0, params);

    EVP_RAND_generate(drbgCtx, buf, sizeof(buf), 0, 0, NULL, 0);

    printf("BYTES: %s\n", buf);

    return 0;
}
