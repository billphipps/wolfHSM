#include <stddef.h>                         /* For NULL */

#include "wolfssl/wolfcrypt/error-crypt.h"  /* For error codes */
#include "wolfssl/wolfcrypt/misc.h"         /* For ForceZero */
#include "wolfssl/wolfcrypt/hmac.h"         /* For HMAC functions */

#include "hmacdrbg.h"

/* Forward declarations of local helper functions */
static int _hmac(const hmacdrbg_Config *config, 
    const byte* key, word32 key_len,
    const byte* data1, word32 data1_len, 
    const byte* data2, word32 data2_len, 
    const byte* data3, word32 data3_len, 
    const byte* data4, word32 data4_len, 
    const byte* data5, word32 data5_len, 
    byte* out, word32 out_len);

static int _update(hmacdrbg_Context *ctx, 
    const byte* data1, word32 data1_len,
    const byte* data2, word32 data2_len,
    const byte* data3, word32 data3_len);



/* Configure context to use a specific type of HMAC (like WC_SHA256) */
int hmacdrbg_Init(  hmacdrbg_Context* ctx, 
                    int hmac_type, word32 reseed_interval, 
                    void* heap, int devid)
{
    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Get actual size of the state based on the HMAC hash type */
    int ret = wc_HmacSizeByType(hmac_type);
    if (ret < 0) {
        return ret;
    }
    /* Make sure the size fits within the context */
    word32 hmac_len = (word32)ret;
    if ((hmac_len > sizeof(ctx->k)) || (hmac_len > sizeof(ctx->v))) {
        return BAD_FUNC_ARG;
    }
    
    /* Set default reseed interval if not specified */
    if (reseed_interval == 0) {
        reseed_interval = HMACDRBG_CFG_RESEED_INTERVAL;
    }

    /* Reasonable config. Clear the context, set the configuration */
    hmacdrbg_Cleanup(ctx);
    ctx->config.hmac_type = hmac_type;
    ctx->config.outlen = hmac_len;
    ctx->config.reseed_interval = reseed_interval;
    ctx->config.heap = heap;
    ctx->config.devid = devid;

    return 0;
}

void hmacdrbg_Cleanup(hmacdrbg_Context* ctx)
{
    if (ctx != NULL) {
        /* Clear context */
        ForceZero(ctx, sizeof(*ctx));
    }
}

int hmacdrbg_CheckInited(const hmacdrbg_Context *ctx)
{
    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Check for reasonable configuration. Note internal failures will trigger 
       Cleanup, which causes this check to fail with invalid configuration */
    if (ctx->config.outlen == 0 ||
        ctx->config.outlen != 
            (word32)wc_HmacSizeByType(ctx->config.hmac_type) ||
        ctx->config.outlen > sizeof(ctx->k) ||
        ctx->config.outlen > sizeof(ctx->v)) {
        return RNG_FAILURE_E;
    }
    return 0;
}

int hmacdrbg_CheckInstantiated(const hmacdrbg_Context *ctx)
{
    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }

    int ret = hmacdrbg_CheckInited(ctx);
    if (ret == 0) {
        if (ctx->c == 0) {
            /* Not instantiated yet */
            ret = RNG_FAILURE_E;
        }
    }
    return ret;
}

/* Helper function to perform HMAC operation on a number of optional parts with 
leftmost truncation.

HMAC construction reference
SP800-224 (FIP198-1 replacement) 
T = HMAC(K, M) :
if (len(K)> hash_block_len) {
    K = H(K) || 0x00[hash_block_len - hash_output_len])
}
if (len(K) < hash_block_len) {
    K = K || 0x00[hash_block_len - len(K)]
}
T = H( (K^opad) || H(K^ipad) || H(M) )
*/
static int _hmac(   const hmacdrbg_Config *config, 
                    const byte* key, word32 key_len,
                    const byte* data1, word32 data1_len, 
                    const byte* data2, word32 data2_len, 
                    const byte* data3, word32 data3_len, 
                    const byte* data4, word32 data4_len, 
                    const byte* data5, word32 data5_len, 
                    byte* out, word32 out_len)
{
    /* III No parameter checks for internal function */

    Hmac hmac;
    int ret = wc_HmacInit(&hmac, config->heap, config->devid);
    if (ret == 0) {
        ret = wc_HmacSetKey(&hmac, config->hmac_type, key, key_len);
        if (ret == 0 && data1 != NULL && data1_len > 0) {
            ret = wc_HmacUpdate(&hmac, data1, data1_len);
        }
        if (ret == 0 && data2 != NULL && data2_len > 0) {
            ret = wc_HmacUpdate(&hmac, data2, data2_len);
        }
        if (ret == 0 && data3 != NULL && data3_len > 0) {
            ret = wc_HmacUpdate(&hmac, data3, data3_len);
        }
        if (ret == 0 && data4 != NULL && data4_len > 0) {
            ret = wc_HmacUpdate(&hmac, data4, data4_len);
        }
        if (ret == 0 && data5 != NULL && data5_len > 0) {
            ret = wc_HmacUpdate(&hmac, data5, data5_len);
        }
        if (ret == 0) {
            if (out_len >= config->outlen) {
                /* HMAC direct output*/
                ret = wc_HmacFinal(&hmac, out);
            } else {
                /* Use temp buffer */
                byte temp[HMACDRBG_CFG_OUTLEN];
                ret = wc_HmacFinal(&hmac, temp);
                if (ret == 0) {
                    XMEMCPY(out, temp, out_len);
                    ForceZero(temp, sizeof(temp));
                }
            }
        }
        /* Clear ephemeral hmac */
        wc_HmacFree(&hmac);
    }
    return ret;
}

/* Helper function to perform HMAC_DRBG_Update on up to 3 optional data parts
SP800-90Ar1 10.1.2.2 
(K,V) = HMAC_DRBG_Update(data, K, V):
K = hmac(K, V || 0x00 || data);
V = hmac(K, V);
if(data!=NULL)
    K = hmac(K, V || 0x01 || data);
    V = hmac(K, V);
}
*/
static int _update( hmacdrbg_Context *ctx, 
                    const byte* data1, word32 data1_len,
                    const byte* data2, word32 data2_len,
                    const byte* data3, word32 data3_len)
{
    /* III No parameter checks for internal function */

    int ret = 0;
    const byte sep0 = 0x00;
    const byte sep1 = 0x01;
    const word32 hmaclen = ctx->config.outlen;

    /* K = hmac(K, V || 0x00 || data); */
    ret = _hmac(&ctx->config, 
                ctx->k, hmaclen,
                ctx->v, hmaclen,
                &sep0, sizeof(sep0),
                data1, data1_len,
                data2, data2_len,
                data3, data3_len,
                ctx->k, hmaclen);

    if (ret == 0) {
        /* V = hmac(K, V); */
        ret = _hmac(    &ctx->config, 
                        ctx->k, hmaclen,
                        ctx->v, hmaclen,
                        NULL, 0,
                        NULL, 0,
                        NULL, 0,
                        NULL, 0,
                        ctx->v, hmaclen);
    }

    if (ret == 0) {
        /* Compute total non-null data length */
        word32 data_len = 0;
        data_len += ( data1 != NULL ) ? data1_len : 0;
        data_len += ( data2 != NULL ) ? data2_len : 0;
        data_len += ( data3 != NULL ) ? data3_len : 0;

        /* If data provided, do another update */
        if (data_len > 0) {
            /* K = hmac(K, V || 0x01 || data); */
            ret = _hmac(&ctx->config, 
                        ctx->k, hmaclen,
                        ctx->v, hmaclen,
                        &sep1, sizeof(sep1),
                        data1, data1_len,
                        data2, data2_len,
                        data3, data3_len,
                        ctx->k, hmaclen);

            if (ret == 0) {
                /* V = hmac(K, V); */
                ret = _hmac(&ctx->config,
                            ctx->k, hmaclen,
                            ctx->v, hmaclen,
                            NULL, 0,
                            NULL, 0,
                            NULL, 0,
                            NULL, 0,
                            ctx->v, hmaclen);
            }
        }
    }

    if (ret != 0) {
        /* Internal state may be inconsistent. Cleanup */
        hmacdrbg_Cleanup((hmacdrbg_Context *)ctx);
    }

    return ret;
}

/*
SP800-90Ar1 10.1.2.3 
(K,V,C) = HMAC_DRBG_Instantiate(entropy, nonce, personalization) :

C = 1;
K = {0x00 0x00 .. };
V = {0x01 0x01 .. };
(K, V) = HMAC_DRBG_Update(entropy||nonce||personalization, K, V);
*/
int hmacdrbg_Instantiate(
    hmacdrbg_Context *ctx,  
    const byte* entropy, word32 entropy_len, 
    const byte* nonce, word32 nonce_len,
    const byte* personalization, word32 personalization_len)
{
    int ret;
    if (ctx == NULL || 
        entropy == NULL || entropy_len == 0 ||
        nonce == NULL || nonce_len == 0 ||
        (personalization == NULL && personalization_len > 0)) {
        return BAD_FUNC_ARG;
    }

    ret = hmacdrbg_CheckInited(ctx);
    if (ret == 0) {
        /* Initialize working state */
        ctx->c = 1;
        XMEMSET(ctx->k, 0x00, ctx->config.outlen);
        XMEMSET(ctx->v, 0x01, ctx->config.outlen);

        /* Update state with provided data */
        ret = _update(ctx,
            entropy, entropy_len,
            nonce, nonce_len,
            personalization, personalization_len);
    }
    return ret;
}

/*
SP800-90Ar1 10.1.2.4 
(K, V, C) = HMAC_DRBG_Reseed(K, V, C, entropy, additional):
(K, V) = HMAC_DRBG_Update(entropy || additional, K, V);
C = 1
*/
int hmacdrbg_Reseed(
    hmacdrbg_Context *ctx, 
    const byte* entropy, word32 entropy_len, 
    const byte* additional_input, word32 additional_input_len)
{
    int ret;
    if (ctx == NULL || entropy == NULL || entropy_len == 0 ||
        (additional_input == NULL && additional_input_len > 0)) {
        return BAD_FUNC_ARG;
    }
    ret = hmacdrbg_CheckInstantiated(ctx);
    if (ret == 0) {
        /* Update state with provided data */
        ret = _update(ctx, 
            entropy, entropy_len,
            additional_input, additional_input_len,
            NULL, 0);
        if (ret == 0) {
            ctx->c = 1; /* Reset reseed counter */
        }
    }
    return ret;
}

/*
SP800-90Ar1 10.1.2.5
(status, out[num_b], K, V, C) = HMAC_DRBG_Generate(K, V, C, num_b, additional)
if (C > reseed_interval) status = RESEED_REQUIRED. Return
if (additional != NULL)
    (K, V) = HMAC_DRBG_Update(addtional, K, V)
temp = NULL
while (len(temp) < num_b)
    V = HMAC(K, V)
    temp = temp || V
out[num_b] = leftmost(temp, num_b);
(K, V) = HMAC_DRBG_Update(additional, K, V);
C = C + 1
status = SUCCESS
*/
int hmacdrbg_Generate(
    hmacdrbg_Context *ctx, 
    const byte* additional_input, word32 additional_input_len,
    byte* output, word32 output_len)
{
    /* Parameter validation */
    if (ctx == NULL || 
        output == NULL || output_len == 0 || 
        (additional_input == NULL && additional_input_len > 0)) {
        return BAD_FUNC_ARG;
    }

    int ret = hmacdrbg_CheckInstantiated(ctx);
    if (ret == 0) {
        
        /* Check reseed counter */
        if (ctx->c <= ctx->config.reseed_interval) {
            /* No reseed required. */

            /* If additional input, mix it in and update state */
            if (additional_input != NULL && additional_input_len > 0) {
                ret = _update(  ctx, 
                                additional_input, additional_input_len,
                                NULL, 0,
                                NULL, 0);
            }

            if (ret == 0) {
                /* Generate output and copy into the provided buffer */
                const word32 hmaclen = ctx->config.outlen;
                word32 thislen = hmaclen;
                while (ret == 0 && output_len > 0) {
                    /* V = HMAC(K, V) */
                    ret = _hmac(&ctx->config, 
                                ctx->k, hmaclen,
                                ctx->v, hmaclen,
                                NULL, 0,
                                NULL, 0,
                                NULL, 0,
                                NULL, 0,
                                ctx->v, hmaclen);
                    if (ret == 0) {
                        if (output_len < hmaclen) {
                            thislen = output_len;
                        }
                        XMEMCPY(output, ctx->v, thislen);
                        output += thislen;
                        output_len -= thislen;
                    } else {
                        /* Error during HMAC. Inconsistent state. Cleanup */
                        hmacdrbg_Cleanup(ctx);
                    }
                }
            }

            if (ret == 0) {
                /* Update state with optional additional input */
                ret = _update(  ctx, 
                                additional_input, additional_input_len,
                                NULL, 0,
                                NULL, 0);
            }

            if (ret == 0) {
                /* All good.  Increment counter */
                ctx->c += 1;
            }
        } else {
            /* Reseed required. Do not update state. */
            ret = RAN_BLOCK_E;
        }
    }
    return ret;
}

