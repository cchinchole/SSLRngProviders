#include <stdio.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/randerr.h>
#include <openssl/proverr.h>
#include <openssl/provider.h>
#include <unistd.h>
#include <openssl/core_names.h>


static OSSL_FUNC_rand_newctx_fn seed_src_new;
static OSSL_FUNC_rand_freectx_fn seed_src_free;
static OSSL_FUNC_rand_instantiate_fn seed_src_instantiate;
static OSSL_FUNC_rand_uninstantiate_fn seed_src_uninstantiate;
static OSSL_FUNC_rand_generate_fn seed_src_generate;
static OSSL_FUNC_rand_reseed_fn seed_src_reseed;
static OSSL_FUNC_rand_settable_ctx_params_fn seed_src_settable_ctx_params;
static OSSL_FUNC_rand_gettable_ctx_params_fn seed_src_gettable_ctx_params;
static OSSL_FUNC_rand_set_ctx_params_fn seed_src_set_ctx_params;
static OSSL_FUNC_rand_get_ctx_params_fn seed_src_get_ctx_params;
static OSSL_FUNC_rand_verify_zeroization_fn seed_src_verify_zeroization;
static OSSL_FUNC_rand_enable_locking_fn seed_src_enable_locking;
static OSSL_FUNC_rand_lock_fn seed_src_lock;
static OSSL_FUNC_rand_unlock_fn seed_src_unlock;
static OSSL_FUNC_rand_get_seed_fn seed_get_seed;
static OSSL_FUNC_rand_clear_seed_fn seed_clear_seed;


const int RandomNumberBlockSize = 32;
const int OsslRandStrength = 1024;
const int OsslRandMaxRequest = 128;



typedef struct {
    void *provctx;
    int state;
} PROV_SEED_SRC;

static void *seed_src_new(void *provctx, void *parent, const OSSL_DISPATCH *parent_dispatch)
{
    PROV_SEED_SRC *s;

    if(parent != NULL)
    {
        printf("ERROR HAS PARENT\n");
        ERR_raise(ERR_LIB_PROV, PROV_R_SEED_SOURCES_MUST_NOT_HAVE_A_PARENT);
        return NULL;
    }

    s = (PROV_SEED_SRC*)OPENSSL_zalloc(sizeof(*s));

    if(!s)
    {
        printf("NULL CTX\n");
        return NULL;
    }

    s->provctx = provctx;
    s->state = EVP_RAND_STATE_UNINITIALISED;
    return s;
}

static void seed_src_free(void *vseed)
{
    OPENSSL_free(vseed);
}

static int seed_src_instantiate(void *vseed, unsigned int strength, int prediction_resistance, const unsigned char *pstr, size_t pstr_len, ossl_unused const OSSL_PARAM params[])
{
    PROV_SEED_SRC *s = (PROV_SEED_SRC *)vseed;
    s->state = EVP_RAND_STATE_READY;
    return 1;
}

static int seed_src_uninstantiate(void *vseed)
{
    PROV_SEED_SRC *s = (PROV_SEED_SRC *)vseed;
    s->state = EVP_RAND_STATE_UNINITIALISED;
    return 1;
}

static int seed_src_get_ctx_params(void *vseed, OSSL_PARAM params[])
{
    PROV_SEED_SRC *s = (PROV_SEED_SRC *)vseed;
    OSSL_PARAM *p;
    printf("THIS WAS CALLED\n");

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATE);
    if (p != NULL && !OSSL_PARAM_set_int(p, s->state))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1024))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 128))
        return 0;

    return 1;
}

static int seed_src_set_ctx_params(void *vseed, const OSSL_PARAM params[])
{
    PROV_SEED_SRC *s = (PROV_SEED_SRC*)vseed;
    OSSL_PARAM *p;

    if(params == NULL)
        return 1;

    return 1;
}

static const OSSL_PARAM *seed_src_settable_ctx_params(void *vseed, void *provctx)
{
    static const OSSL_PARAM known_settable_ctx_params[] = {
        OSSL_PARAM_END
    };
    return known_settable_ctx_params;
}

static const OSSL_PARAM *seed_src_gettable_ctx_params(ossl_unused void *vseed,
                                                      ossl_unused void *provctx)
{
    static const OSSL_PARAM known_gettable_ctx_params[] = {
        OSSL_PARAM_int(OSSL_RAND_PARAM_STATE, NULL),
        OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, NULL),
        OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, NULL),
        OSSL_PARAM_END
    };
    return known_gettable_ctx_params;
}



static int seed_src_verify_zeroization(ossl_unused void *vseed)
{
    return 1;
}

static void seed_clear_seed(ossl_unused void *vdrbg,
                            unsigned char *out, size_t outlen)
{
    OPENSSL_secure_clear_free(out, outlen);
}

static int seed_src_enable_locking(ossl_unused void *vseed)
{
    return 1;
}

int seed_src_lock(ossl_unused void *vctx)
{
    return 1;
}

void seed_src_unlock(ossl_unused void *vctx)
{
}


static int seed_src_reseed(void *vseed,
                           ossl_unused int prediction_resistance,
                           ossl_unused const unsigned char *ent,
                           ossl_unused size_t ent_len,
                           ossl_unused const unsigned char *adin,
                           ossl_unused size_t adin_len)
{
    PROV_SEED_SRC *s = (PROV_SEED_SRC *)vseed;

    if (s->state != EVP_RAND_STATE_READY) {
        ERR_raise(ERR_LIB_PROV,
                  s->state == EVP_RAND_STATE_ERROR ? PROV_R_IN_ERROR_STATE
                                                   : PROV_R_NOT_INSTANTIATED);
        return 0;
    }
    return 1;
}


static size_t seed_get_seed(void *vseed, unsigned char **pout,
                            int entropy, size_t min_len, size_t max_len,
                            int prediction_resistance,
                            const unsigned char *adin, size_t adin_len)
{
    size_t bytesNeeded;
    unsigned char *buffer;

    bytesNeeded = entropy >= 0 ? (entropy + 7) / 8 : 0;
    if (bytesNeeded < min_len)
        bytesNeeded = min_len;

    if (bytesNeeded > max_len) {
        ERR_raise(ERR_LIB_PROV, PROV_R_ENTROPY_SOURCE_STRENGTH_TOO_WEAK);
        return 0;
    }

    buffer = (unsigned char*)(OPENSSL_secure_malloc(bytesNeeded));
    if (!buffer) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    if (seed_src_generate(vseed, buffer, bytesNeeded, 0, prediction_resistance, adin, adin_len) != 0) {
        *pout = buffer;
        return bytesNeeded;
    }

    OPENSSL_secure_clear_free(buffer, bytesNeeded);
    return 1;
}


static int seed_src_generate(void *seed, unsigned char *out, size_t out_len, unsigned int strength, ossl_unused int predictionResistance, ossl_unused const unsigned char *adin, ossl_unused size_t adinLength)
{
    srand(time(NULL));

    for(int i = 0; i < out_len; i++)
        out[i] = rand() % 255;
    return 1;
}


static const OSSL_DISPATCH seedSrcFncs[] = {
    { OSSL_FUNC_RAND_NEWCTX, (void(*)(void))seed_src_new},
    { OSSL_FUNC_RAND_FREECTX, (void(*)(void))seed_src_free},
    { OSSL_FUNC_RAND_INSTANTIATE, (void(*)(void))seed_src_instantiate},
    { OSSL_FUNC_RAND_UNINSTANTIATE, (void(*)(void))seed_src_uninstantiate},
    { OSSL_FUNC_RAND_GENERATE, (void(*)(void))seed_src_generate},
    { OSSL_FUNC_RAND_RESEED, (void(*)(void))seed_src_reseed},
    { OSSL_FUNC_RAND_ENABLE_LOCKING, (void(*)(void))seed_src_enable_locking},
    { OSSL_FUNC_RAND_LOCK, (void(*)(void))seed_src_enable_locking},
    { OSSL_FUNC_RAND_UNLOCK, (void(*)(void))seed_src_unlock},
    { OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, (void(*)(void))seed_src_gettable_ctx_params},
    { OSSL_FUNC_RAND_GET_CTX_PARAMS, (void(*)(void))seed_src_get_ctx_params},
    { OSSL_FUNC_RAND_VERIFY_ZEROIZATION, (void(*)(void))seed_src_verify_zeroization},
    { OSSL_FUNC_RAND_GET_SEED, (void(*)(void))seed_get_seed},
    { OSSL_FUNC_RAND_CLEAR_SEED, (void(*)(void))seed_clear_seed},
    { OSSL_FUNC_RAND_SET_CTX_PARAMS, (void(*)(void))seed_src_set_ctx_params},
    { OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS, (void(*)(void))seed_src_settable_ctx_params},
    OSSL_DISPATCH_END
};

const OSSL_ALGORITHM seed_algorithms[] = {
    { "skeleton", "provider=skeleton", seedSrcFncs },
    {NULL, NULL, NULL}
};

const OSSL_ALGORITHM* seed_provider_query(void* provCtx, int operationId, int* noCache)
{
    *noCache = 0;
    switch (operationId) {
    case OSSL_OP_RAND:
        return seed_algorithms;
    }
    return NULL;
}

void seed_teardown(void *provCtx)
{
    seed_src_free(provCtx);
}

const OSSL_DISPATCH providerFunctions[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void(*)(void))seed_teardown },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void(*)(void))seed_provider_query },
    { 0, NULL }
};

OSSL_provider_init_fn OSSL_provider_init;

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in, const OSSL_DISPATCH **out, void **provctx)
{
    *provctx = seed_src_new(provctx, NULL, in);
    if( *provctx == NULL)
    {
        fprintf(stderr, "Failed to init RNG Provider\n");
        return 0;
    }

    *out = providerFunctions;
    printf("Successfully initialized the RNG Provider\n");
    return 1;
}

