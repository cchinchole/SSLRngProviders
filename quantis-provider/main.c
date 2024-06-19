#include <stdio.h>
#include <openssl/core.h>
#include <openssl/rand.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/core_dispatch.h>
#include "quantis.h"

#define OPENSSL_NO_ENGINE 1
OSSL_provider_init_fn my_prov_init;
int main()
{
    /* Initialize the provider and make a new context to place it into */
    OSSL_PROVIDER* prov = NULL;
    OSSL_LIB_CTX *libCtx = OSSL_LIB_CTX_new();

    if(OSSL_PROVIDER_add_builtin(libCtx, QUANTIS_RNG_PROV_NAME, &my_prov_init))
        prov = OSSL_PROVIDER_load(libCtx, QUANTIS_RNG_PROV_NAME);
    if(prov == NULL)
        printf("Failed to find provider\n");
    else
        printf("Provider found!\n");
    if(!OSSL_PROVIDER_available(libCtx, QUANTIS_RNG_PROV_NAME)) 
    {
        printf("Failed to find the seed provider\n");
        return 0;
    }
    else
    {
        printf("Found seed provider\n");
    }

    /* This isn't implemented to actually do any checks, but will verify the provider is within the context still */
    if(!OSSL_PROVIDER_self_test(prov))
    {
        printf("SELF TEST FAILED!\n");
        return 0;
    }
    else
    {
        printf("SELF TEST PASSED!\n");
    }
        
    /* Build and fill our test buffer */
    unsigned char *buf = malloc(5);
    for(int i = 0; i < 5; i++)
        buf[i] = (int)'a';

    /* Create the random provider */
    EVP_RAND *rand = EVP_RAND_fetch(libCtx, QUANTIS_RNG_PROV_NAME, NULL);
  
    if(rand == NULL)
        printf("FAILED TO LOAD SKELETON.\n");

    EVP_RAND_CTX *seedCtx = EVP_RAND_CTX_new(rand, NULL);

    if( !(seedCtx) )
        printf("SEED CTX Failed\n");
    else
        printf("SEED CTX Succeeded\n");


    /* We do not support any of the parameters so fill with garbage data */
    EVP_RAND_instantiate(seedCtx, 0, 0, NULL, 0, NULL);
    
    /* Example of how a request and set can be used on the parameters */
    int quantis_cardnum = 0;
    
    OSSL_PARAM request[] = {
        OSSL_PARAM_int(QUANTIS_PARAM_CARDNO, &quantis_cardnum),
        OSSL_PARAM_END,
    };
    /*
    EVP_RAND_CTX_get_params(seedCtx, request);
    printf("Retrieved %s: %d\n", QUANTIS_PARAM_CARDNO,  quantis_cardnum);
    */

    /* Setting to my card number, 0 */
    OSSL_PARAM set[] = {
        OSSL_PARAM_construct_int(QUANTIS_PARAM_CARDNO, &quantis_cardnum),
        OSSL_PARAM_END,
    };

    EVP_RAND_CTX_set_params(seedCtx, set);
    EVP_RAND_CTX_get_params(seedCtx, request);
    printf("(After set) Retrieved %s: %d\n", QUANTIS_PARAM_CARDNO, quantis_cardnum);

    EVP_RAND_free(rand);

    /* Build an AES256 DRBG */
    OSSL_PARAM params[2], *p = params;
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER, SN_aes_256_ctr, 0);
    *p = OSSL_PARAM_construct_end();
    
    rand = EVP_RAND_fetch(NULL, "CTR-DRBG", NULL);
    EVP_RAND_CTX* drbgCtx = EVP_RAND_CTX_new(rand, seedCtx);
    EVP_RAND_free(rand);
    EVP_RAND_instantiate(drbgCtx, 128, 0, NULL, 0, params);

    /* Using the DRBG with our seed to generate random bytes */
    EVP_RAND_generate(drbgCtx, buf, sizeof(buf), 0, 0, NULL, 0);

    printf("BYTES: %s\n", buf);

    return 0;
}
