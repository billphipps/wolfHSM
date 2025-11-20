#ifndef HMACDRBG_H_
#define HMACDRBG_H_

/* HMAC DRBG Implementation, similar to wolfCrypt HASH_DRBG */

#if 0

Typical usage:

/* Security strength in bytes when using SHA256 */
#define SEC_STRENGTH 16

void* heap = NULL;       /* Use default heap */
int devid = INVALID_DEVID;  /* No device ID for crypto cb */
word32 reseed_interval = 0; /* Use default reseed interval */

byte entropy_instantiate[SEC_STRENGTH] = {0};  /* Get from entropy source */
byte nonce[SEC_STRENGTH/2] = {0}; /* Get from counter/time source */
byte personalization[] = "This is my personalization string";

byte entropy_reseed[SEC_STRENGTH] = {0}; /* Get from entropy source */
byte addl_reseed[] = "This is additional reseed input";

byte addl_gen[] = "This is additional input used to generate";
byte output[64]; /* Desired output length */

hmacdrbg_Context ctx;
hmacdrbg_Init(  &ctx, 
                WC_SHA256, reseed_interval, 
                heap, devid);

hmacdrbg_Instantiate(   &ctx, 
                        entropy_instantiate, sizeof(entropy_instantiate),
                        nonce, sizeof(nonce),
                        personalization, sizeof(personalization));

hmacdrbg_Generate(  &ctx, 
                    addl_gen, sizeof(addl_gen),
                    output, sizeof(output));

hmacdrbg_Reseed(    &ctx, 
                    entropy_reseed, sizeof(entropy_reseed), 
                    addl_reseed, sizeof(addl_reseed));

hmacdrbg_Generate(  &ctx, 
                    addl_gen, sizeof(addl_gen),
                    output, sizeof(output));

hmacdrbg_Cleanup(&ctx);

#endif

#include <stdint.h>
#include <stddef.h>

#include "wolfssl/wolfcrypt/types.h"    /* For byte, word32 */  
#include "wolfssl/wolfcrypt/hmac.h"     /* For WC_MAX_DIGEST_SIZE*/


/* Maximum size of the mac output, typically WC_MAX_DIGEST_SIZE */
#ifndef HMACDRBG_CFG_OUTLEN
#define HMACDRBG_CFG_OUTLEN WC_MAX_DIGEST_SIZE
#endif

/* If reseed_interval is 0 at Init, use default */
#ifndef HMACDRBG_CFG_RESEED_INTERVAL
#define HMACDRBG_CFG_RESEED_INTERVAL 10000
#endif

/* Configuration for an HMAC DRBG Context. */
typedef struct {
    int hmac_type;              /* Like WC_SHA256 */
    word32 outlen;              /* From wc_HmacSizeByType */
    word32 reseed_interval;     /* Reseed interval */
    void* heap;                 /* Heap hint for HMAC */
    int devid;                  /* Device ID for cryptocb for HMAC */
} hmacdrbg_Config;

/* HMAC DRBG context. Note than any required HMAC instance is ephemeral */
typedef struct {
    /* Configuration (const after Init) */
    hmacdrbg_Config config;

    /* Working state (sensitive after Instantiate) */
    word32 c;                   /* Reseed counter */
    byte k[HMACDRBG_CFG_OUTLEN];    /* Current key value */
    byte v[HMACDRBG_CFG_OUTLEN];    /* Current state value */
} hmacdrbg_Context;


/** Public API */

/* Configure context to use a specific type of HMAC (like WC_SHA256) 

Returns:    0 successful configuration, 
            BAD_FUNC_ARG on invalid configuration or NULL context
*/
int hmacdrbg_Init(  hmacdrbg_Context* ctx, 
                    int hmac_type, word32 reseed_interval, 
                    void* heap, int devid);

/* Clear the context removing any configuration and sensitive state.
Context will be neither inited nor instantiated after Cleanup. */
void hmacdrbg_Cleanup(hmacdrbg_Context* ctx);

/* Helper function to check that context configuration is valid 
Returns:    0 on valid configuration, 
            BAD_FUNC_ARG on NULL context 
            RNG_FAILURE_E if not inited. Invoke Init to configure.
*/
int hmacdrbg_CheckInited(const hmacdrbg_Context *ctx);

/* Helper function to check that context is inited and instantiated
Context must have been configured using Init.
Returns:    0 if instantiated, 
            BAD_FUNC_ARG on NULL context 
            RNG_FAILURE_E if not inited and instantiated
 */
int hmacdrbg_CheckInstantiated(const hmacdrbg_Context *ctx);


/*
SP800-90Ar1 10.1.2.3 
(K,V,C) = HMAC_DRBG_Instantiate(entropy, nonce, personalization)

Context must have been configured using Init.
Entropy must be non-NULL and entropy_len > 0.
Nonce must be non-NULL and nonce_len > 0.
Additional Input may be NULL or zero length.

Returns:    0 on SUCCESS
            BAD_FUNC_ARG on invalid parameters
            RNG_FAILURE_E if not initialized
            OR other wolfCrypt error codes from internal HMAC calls

Note: hmacdrbg_Context is zeroized (Cleanup) on internal HMAC error.
*/
int hmacdrbg_Instantiate(
    hmacdrbg_Context *ctx,  
    const byte* entropy, word32 entropy_len, 
    const byte* nonce, word32 nonce_len,
    const byte* personalization, word32 personalization_len);

    
/*
SP800-90Ar1 10.1.2.4 
(K, V, C) = HMAC_DRBG_Reseed(K, V, C, entropy, additional)

Entropy must be non-NULL and entropy_len > 0.
Additional Input may be NULL or zero length.

Returns:    0 on SUCCESS
            RNG_FAILURE_E if not initialized, instantiated, or bad state
            OR other wolfCrypt error codes from internal HMAC calls

Note: hmacdrbg_Context is zeroized (Cleanup) on internal HMAC error.
*/
int hmacdrbg_Reseed(
    hmacdrbg_Context *ctx, 
    const byte* entropy, word32 entropy_len,
    const byte* additional_input, word32 additional_input_len);

/*
SP800-90Ar1 10.1.2.5
(status, out[num_b], K, V, C) = HMAC_DRBG_Generate(K, V, C, num_b, additional)

Only supports full byte output, not bits.
Output length must be > 0
Additional Input may be NULL or zero length.

Returns:    0 on SUCCESS
            BAD_FUNC_ARG on invalid parameters
            RAN_BLOCK_E on RESEED required (counter > reseed_interval)
            RNG_FAILURE_E if not initialized, instantiated, or bad state
            OR other wolfCrypt error codes from internal HMAC calls

Note: hmacdrbg_Context is zeroized (Cleanup) on internal HMAC error.
*/
int hmacdrbg_Generate(
    hmacdrbg_Context *ctx, 
    const byte* additional_input, word32 additional_input_len,
    byte* output, word32 output_len);


#endif /* !HMACDRBG_H_ */