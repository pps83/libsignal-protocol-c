#ifndef SIGNAL_PROTOCOL_INTERNAL_H
#define SIGNAL_PROTOCOL_INTERNAL_H

#include "LocalStorageProtocol.upb.h"
#include "signal_protocol.h"

struct signal_type_base {
    unsigned int ref_count;
    void (*destroy)(signal_type_base *instance);
};

void signal_type_init(signal_type_base *instance,
        void (*destroy_func)(signal_type_base *instance));

#define SIGNAL_INIT(instance, destroy_func) signal_type_init((signal_type_base *)instance, destroy_func)

struct signal_buffer {
    size_t len;
    uint8_t data[];
};

struct signal_context {
    signal_crypto_provider crypto_provider;
    void (*lock)(void *user_data);
    void (*unlock)(void *user_data);
    void (*log)(int level, const char *message, size_t len, void *user_data);
    void *user_data;
};

int signal_crypto_random(signal_context *context, uint8_t *data, size_t len);

int signal_hmac_sha256_init(signal_context *context, void **hmac_context, const uint8_t *key, size_t key_len);
int signal_hmac_sha256_update(signal_context *context, void *hmac_context, const uint8_t *data, size_t data_len);
int signal_hmac_sha256_final(signal_context *context, void *hmac_context, signal_buffer **output);
void signal_hmac_sha256_cleanup(signal_context *context, void *hmac_context);

int signal_sha512_digest_init(signal_context *context, void **digest_context);
int signal_sha512_digest_update(signal_context *context, void *digest_context, const uint8_t *data, size_t data_len);
int signal_sha512_digest_final(signal_context *context, void *digest_context, signal_buffer **output);
void signal_sha512_digest_cleanup(signal_context *context, void *digest_context);


int signal_encrypt(signal_context *context,
        signal_buffer **output,
        int cipher,
        const uint8_t *key, size_t key_len,
        const uint8_t *iv, size_t iv_len,
        const uint8_t *plaintext, size_t plaintext_len);

int signal_decrypt(signal_context *context,
        signal_buffer **output,
        int cipher,
        const uint8_t *key, size_t key_len,
        const uint8_t *iv, size_t iv_len,
        const uint8_t *ciphertext, size_t ciphertext_len);

void signal_lock(signal_context *context);
void signal_unlock(signal_context *context);
void signal_log(signal_context *context, int level, const char *format, ...);
void signal_explicit_bzero(void *v, size_t n);
int signal_constant_memcmp(const void *s1, const void *s2, size_t n);

/*------------------------------------------------------------------------*/

/*
 * Functions used for internal protocol buffers serialization support.
 * Messages are built and parsed with upb; everything they point to lives in the arena passed in.
 */

int ec_public_key_serialize_protobuf(upb_StringView *buffer, const ec_public_key *key, upb_Arena *arena);
int ec_private_key_serialize_protobuf(upb_StringView *buffer, const ec_private_key *key, upb_Arena *arena);

int ratchet_chain_key_get_key_protobuf(const ratchet_chain_key *chain_key, upb_StringView *buffer, upb_Arena *arena);
int ratchet_root_key_get_key_protobuf(const ratchet_root_key *root_key, upb_StringView *buffer, upb_Arena *arena);

int session_state_serialize_prepare(session_state *state, textsecure_SessionStructure *session_structure, upb_Arena *arena);
int session_state_deserialize_protobuf(session_state **state, const textsecure_SessionStructure *session_structure, signal_context *global_context);

int sender_key_state_serialize_prepare(sender_key_state *state, textsecure_SenderKeyStateStructure *state_structure, upb_Arena *arena);
int sender_key_state_deserialize_protobuf(sender_key_state **state, const textsecure_SenderKeyStateStructure *state_structure, signal_context *global_context);

upb_StringView signal_protocol_str_serialize_protobuf(const char *str);
char *signal_protocol_str_deserialize_protobuf(upb_StringView buffer);

/* A copy of len bytes into the arena, or an empty view with a null data pointer when the arena has no room */
upb_StringView signal_protocol_bytes_protobuf(const void *data, size_t len, upb_Arena *arena);
/* A view of a buffer's bytes, valid while the buffer lives */
upb_StringView signal_buffer_protobuf(const signal_buffer *buffer);
/* A new buffer of before + its size + after bytes with the message serialized at offset before */
int signal_buffer_from_protobuf(signal_buffer **buffer, const void *message, const upb_MiniTable *table,
        upb_Arena *arena, size_t before, size_t after);

#endif /* SIGNAL_PROTOCOL_INTERNAL_H */
