#ifndef _DEMO_CUSTOMCB_CUSTOM_H_
#define _DEMO_CUSTOMCB_CUSTOM_H_

/* Demo of customcb interface */
#include "wolfhsm/wh_settings.h"


#include <stdint.h>
#include <stddef.h>

/* Common defines */
enum {
    /* Send random data from server to client */
    DCCB_ID_RANDOM = 0,

    /* Compute byte checksum of data sent from client to server */
    DCCB_ID_CHECKSUM = 1,

    /* Convert lowercase ASCII to uppercase ASCII */
    DCCB_ID_UCASE = 2,

    /* Request stateful counter operations: get, increment */
    DCCB_ID_COUNTER_GET = 3,
    DCCB_ID_COUNTER_INC = 4,

    /* Request stateful HMAC_DRBG (SHA-256) operations: 
            Instantiate, Reseed, Generate */
    DCCB_ID_HMACDRBG_INSTANTIATE = 5,
    DCCB_ID_HMACDRBG_RESEED = 6,
    DCCB_ID_HMACDRBG_GENERATE = 7,
};



#ifdef WOLFHSM_CFG_ENABLE_SERVER
/* Server side */
#include "wolfhsm/wh_server.h"
/* Register all of the customcb functions */
int dccb_Server_Init(whServerContext* s);
int dccb_Server_Cleanup(whServerContext s);
#endif /* WOLFHSM_CFG_ENABLE_SERVER */

#ifdef WOLFHSM_CFG_ENABLE_CLIENT
/* Client side */
#include "wolfhsm/wh_client.h"
int dccb_Client_Init(whClientContext* c);
int dccb_Client_Cleanup(whClientContext* c);

int dccb_Client_Random(
    whClientContext* c,
    uint32_t num_bytes,
    uint8_t* output);
int dccb_Client_Checksum(
    whClientContext* c,
    const uint8_t* input, uint32_t num_bytes, 
    uint8_t *out_checksum);
int dccb_Client_Uppercase(
    whClientContext* c,
    const uint8_t* input, uint32_t num_bytes,
    uint8_t *out_checksum);

/* Get counter value */
int dccb_Client_Counter_Get(
    whClientContext* c, 
    uint32_t *out_counter);
/* Increment counter by 1 */
int dccb_Client_Counter_Inc(
    whClientContext* c,
    uint32_t *out_counter);

/* Instantiate an HMAC DRBG.  
    If entropy or nonce is NULL, then use server-provided entropy/nonce */
int dccb_Client_HMAC_DRBG_Instantiate(
    whClientContext* c,
    const byte* entropy, word32 entropy_len,
    const byte* nonce, word32 nonce_len,
    const byte* personalization, word32 personalization_len);

/* Reseed an HMAC DRBG.  
    If entropy is NULL, then use server-provided entropy */
int dccb_Client_HMAC_DRBG_Reseed(
    whClientContext* c,
    const byte* entropy, word32 entropy_len,
    const byte* additional_input, word32 additional_input_len);

int dccb_Client_HMAC_DRBG_Generate(
    whClientContext* c,
    const byte* additional_input, word32 additional_input_len,
    byte* output, word32 output_len);

/* Show each of the customcb's working */
int dccb_ClientDemo(whClientContext* c);
#endif /* WOLFHSM_CFG_ENABLE_CLIENT */

#endif /* !_DEMO_CUSTOMCB_CUSTOM_H_ */