#ifndef DEMO_COMMON_CUSTOMCB_H_
#define DEMO_COMMON_CUSTOMCB_H_

#include <stdint.h>
#include <stddef.h>

#define DCCB_HMACDRBG_GENERATE_ID 0

typedef struct {
    uint32_t size;
} DccbHmacdrbg_GenerateRequest;

typedef struct {
    uint32_t size;
    int32_t rc;
    /* Data follows:
        uint8_t response_data[size]; */
} DccbHmacdrbg_GenerateResponse;

typedef struct {
    uint32_t outlen;  /* Number of Bytes in V and Key */
    uint32_t reseed_counter; /* Number of generate requests */
    uint8_t key[32];    /* Current key value */
    uint8_t v[32];      /* Current state value */
} Hmacdrbg_Context;

/* SP800-224 (FIP198-1 replacement) 
T = HMAC(K, M) :
if (len(K)> hash_block_len) {
    K = H(K) || 0x00[hash_block_len - hash_output_len])
}
if (len(K) < hash_block_len) {
    K = K || 0x00[hash_block_len - len(K)]
}
T = H((K^opad)||H(K^ipad)||H(M))
*/

/*
SP800-90Ar1 10.1.2.2 
HMAC_DRBG_Update(data, K, V) :
ctx->k = hmac(ctx->k, ctx->v || 0x00 || data);
ctx->v = hmac(ctx->k, ctx->v);
if(data) {
    ctx->k = hmac(ctx->k, ctx->v || 0x01 || data);
    ctx->v = hmac(ctx->k, ctx->v);
}
*/
int hmac_drbg_update( Hmacdrbg_Context *ctx, 
    const uint8_t* data1, size_t data1_len,
    const uint8_t* data2, size_t data2_len,
    const uint8_t* data3, size_t data3_len);

/*
SP800-90Ar1 10.1.2.3 HMAC_DRBG_Instantiate(entropy, nonce, personalization)
ctx->outlen = outlen;
ctx->reseed_counter = 1;
ctx->k = {0x00 0x00 .. };
ctx->v = {0x01 0x01 .. };
hmac_drbg_update(entropy, nonce, personalization);
*/
int hmac_drbg_instantiate(
    Hmacdrbg_Context *ctx, size_t out_len, 
    const uint8_t* entropy, size_t entropy_len, 
    const uint8_t* nonce, size_t nonce_len,
    const uint8_t* personalization, size_t personalization_len);


int hmac_drbg_generate(
    Hmacdrbg_Context *ctx, 
    const uint8_t* additional_input, size_t additional_input_len,
    uint8_t* output, size_t output_len);

int hmac_drbg_reseed(
    Hmacdrbg_Context *ctx, 
    const uint8_t* entropy, size_t entropy_len, 
    const uint8_t* additional_input, size_t additional_input_len);


#endif /* !DEMO_COMMON_CUSTOMCB_H_ */