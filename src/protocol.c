#include "protocol.h"

#include <string.h>
#include <assert.h>

#include "curve.h"
#include "signal_protocol_internal.h"
#include "WhisperTextProtocol.upb.h"

#define SIGNAL_MESSAGE_MAC_LENGTH 8
#define SIGNATURE_LENGTH 64

struct ciphertext_message
{
    signal_type_base base;
    int message_type;
    signal_context *global_context;
    signal_buffer *serialized;
};

struct signal_message
{
    ciphertext_message base_message;
    uint8_t message_version;
    ec_public_key *sender_ratchet_key;
    uint32_t counter;
    uint32_t previous_counter;
    signal_buffer *ciphertext;
};

struct pre_key_signal_message
{
    ciphertext_message base_message;
    uint8_t version;
    uint32_t registration_id;
    int has_pre_key_id;
    uint32_t pre_key_id;
    uint32_t signed_pre_key_id;
    ec_public_key *base_key;
    ec_public_key *identity_key;
    signal_message *message;
};

struct sender_key_message
{
    ciphertext_message base_message;
    uint8_t message_version;
    uint32_t key_id;
    uint32_t iteration;
    signal_buffer *ciphertext;
};

struct sender_key_distribution_message
{
    ciphertext_message base_message;
    uint32_t id;
    uint32_t iteration;
    signal_buffer *chain_key;
    ec_public_key *signature_key;
};

static int signal_message_serialize(signal_buffer **buffer, const signal_message *message);
static int signal_message_get_mac(signal_buffer **buffer,
        uint8_t message_version,
        ec_public_key *sender_identity_key,
        ec_public_key *receiver_identity_key,
        const uint8_t *mac_key, size_t mac_key_len,
        const uint8_t *serialized, size_t serialized_len,
        signal_context *global_context);

static int pre_key_signal_message_serialize(signal_buffer **buffer, const pre_key_signal_message *message);

static int sender_key_message_serialize(signal_buffer **buffer, const sender_key_message *message, ec_private_key *signature_key, signal_context *global_context);
static int sender_key_distribution_message_serialize(signal_buffer **buffer, const sender_key_distribution_message *message);

/*------------------------------------------------------------------------*/

int ciphertext_message_get_type(const ciphertext_message *message)
{
    assert(message);
    return message->message_type;
}

signal_buffer *ciphertext_message_get_serialized(const ciphertext_message *message)
{
    assert(message);
    return message->serialized;
}

/*------------------------------------------------------------------------*/

int signal_message_create(signal_message **message, uint8_t message_version,
        const uint8_t *mac_key, size_t mac_key_len,
        ec_public_key *sender_ratchet_key, uint32_t counter, uint32_t previous_counter,
        const uint8_t *ciphertext, size_t ciphertext_len,
        ec_public_key *sender_identity_key, ec_public_key *receiver_identity_key,
        signal_context *global_context)
{
    int result = 0;
    signal_buffer *message_buf = 0;
    signal_buffer *mac_buf = 0;
    signal_message *result_message = 0;

    assert(global_context);

    result_message = malloc(sizeof(signal_message));
    if(!result_message) {
        return SG_ERR_NOMEM;
    }
    memset(result_message, 0, sizeof(signal_message));
    SIGNAL_INIT(result_message, signal_message_destroy);

    result_message->base_message.message_type = CIPHERTEXT_SIGNAL_TYPE;
    result_message->base_message.global_context = global_context;

    SIGNAL_REF(sender_ratchet_key);
    result_message->sender_ratchet_key = sender_ratchet_key;

    result_message->counter = counter;
    result_message->previous_counter = previous_counter;

    result_message->ciphertext = signal_buffer_create(ciphertext, ciphertext_len);
    if(!result_message->ciphertext) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    result_message->message_version = message_version;

    result = signal_message_serialize(&message_buf, result_message);
    if(result < 0) {
        goto complete;
    }

    result = signal_message_get_mac(&mac_buf,
            message_version, sender_identity_key, receiver_identity_key,
            mac_key, mac_key_len,
            signal_buffer_data(message_buf),
            signal_buffer_len(message_buf),
            global_context);
    if(result < 0) {
        goto complete;
    }

    result_message->base_message.serialized = signal_buffer_append(
            message_buf,
            signal_buffer_data(mac_buf),
            signal_buffer_len(mac_buf));
    if(result_message->base_message.serialized) {
        message_buf = 0;
    }
    else {
        result = SG_ERR_NOMEM;
    }

complete:
    if(message_buf) {
        signal_buffer_free(message_buf);
    }
    if(mac_buf) {
        signal_buffer_free(mac_buf);
    }
    if(result >= 0) {
        result = 0;
        *message = result_message;
    }
    else {
        if(result_message) {
            SIGNAL_UNREF(result_message);
        }
    }
    return result;
}

static int signal_message_serialize(signal_buffer **buffer, const signal_message *message)
{
    int result = 0;
    signal_buffer *result_buf = 0;
    upb_Arena *arena = 0;
    textsecure_SignalMessage *message_structure = 0;
    upb_StringView ratchet_key;

    uint8_t version = (message->message_version << 4) | CIPHERTEXT_CURRENT_VERSION;

    arena = upb_Arena_New();
    message_structure = arena ? textsecure_SignalMessage_new(arena) : 0;
    if(!message_structure) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    result = ec_public_key_serialize_protobuf(&ratchet_key, message->sender_ratchet_key, arena);
    if(result < 0) {
        goto complete;
    }
    textsecure_SignalMessage_set_ratchetKey(message_structure, ratchet_key);
    textsecure_SignalMessage_set_counter(message_structure, message->counter);
    textsecure_SignalMessage_set_previousCounter(message_structure, message->previous_counter);
    textsecure_SignalMessage_set_ciphertext(message_structure, signal_buffer_protobuf(message->ciphertext));

    result = signal_buffer_from_protobuf(&result_buf, message_structure, &textsecure__SignalMessage_msg_init, arena, 1, 0);
    if(result < 0) {
        goto complete;
    }
    signal_buffer_data(result_buf)[0] = version;

complete:
    if(arena) {
        upb_Arena_Free(arena);
    }
    if(result >= 0) {
        *buffer = result_buf;
    }
    return result;
}

int signal_message_deserialize(signal_message **message, const uint8_t *data, size_t len, signal_context *global_context)
{
    int result = 0;
    signal_message *result_message = 0;
    upb_Arena *arena = 0;
    textsecure_SignalMessage *message_structure = 0;
    upb_StringView field;
    uint8_t version = 0;
    uint8_t *serialized_data = 0;
    const uint8_t *message_data = 0;
    size_t message_len = 0;

    assert(global_context);

    if(!data || len <= 1 + SIGNAL_MESSAGE_MAC_LENGTH) {
        result = SG_ERR_INVAL;
        goto complete;
    }

    version = (data[0] & 0xF0) >> 4;

    /* Set some pointers and lengths for the sections of the raw data */
    message_data = data + 1;
    message_len = len - 1 - SIGNAL_MESSAGE_MAC_LENGTH;

    if(version <= CIPHERTEXT_UNSUPPORTED_VERSION) {
        signal_log(global_context, SG_LOG_WARNING, "Unsupported legacy version: %d", version);
        result = SG_ERR_LEGACY_MESSAGE;
        goto complete;
    }

    if(version > CIPHERTEXT_CURRENT_VERSION) {
        signal_log(global_context, SG_LOG_WARNING, "Unknown version: %d", version);
        result = SG_ERR_INVALID_MESSAGE;
        goto complete;
    }

    arena = upb_Arena_New();
    if(!arena) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    message_structure = textsecure_SignalMessage_parse((const char *)message_data, message_len, arena);
    if(!message_structure) {
        result = SG_ERR_INVALID_PROTO_BUF;
        goto complete;
    }

    if(!textsecure_SignalMessage_has_ciphertext(message_structure)
            || !textsecure_SignalMessage_has_counter(message_structure)
            || !textsecure_SignalMessage_has_ratchetKey(message_structure)) {
        signal_log(global_context, SG_LOG_WARNING, "Incomplete message");
        result = SG_ERR_INVALID_MESSAGE;
        goto complete;
    }

    result_message = malloc(sizeof(signal_message));
    if(!result_message) {
        result = SG_ERR_NOMEM;
        goto complete;
    }
    memset(result_message, 0, sizeof(signal_message));
    SIGNAL_INIT(result_message, signal_message_destroy);

    result_message->base_message.message_type = CIPHERTEXT_SIGNAL_TYPE;
    result_message->base_message.global_context = global_context;

    field = textsecure_SignalMessage_ratchetKey(message_structure);
    result = curve_decode_point(&result_message->sender_ratchet_key,
            (const uint8_t *)field.data, field.size, global_context);
    if(result < 0) {
        goto complete;
    }

    result_message->message_version = version;
    result_message->counter = textsecure_SignalMessage_counter(message_structure);
    result_message->previous_counter = textsecure_SignalMessage_previousCounter(message_structure);

    field = textsecure_SignalMessage_ciphertext(message_structure);
    result_message->ciphertext = signal_buffer_create((const uint8_t *)field.data, field.size);
    if(!result_message->ciphertext) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    result_message->base_message.serialized = signal_buffer_alloc(len);
    if(!result_message->base_message.serialized) {
        result = SG_ERR_NOMEM;
        goto complete;
    }
    serialized_data = signal_buffer_data(result_message->base_message.serialized);
    memcpy(serialized_data, data, len);

complete:
    if(arena) {
        upb_Arena_Free(arena);
    }
    if(result >= 0) {
        *message = result_message;
    }
    else {
        if(result_message) {
            SIGNAL_UNREF(result_message);
        }
    }
    return result;
}

int signal_message_copy(signal_message **message, signal_message *other_message, signal_context *global_context)
{
    int result = 0;
    signal_message *result_message = 0;

    assert(other_message);
    assert(global_context);

    result = signal_message_deserialize(
            &result_message,
            signal_buffer_data(other_message->base_message.serialized),
            signal_buffer_len(other_message->base_message.serialized),
            global_context);
    if(result >= 0) {
        *message = result_message;
    }

    return result;
}

ec_public_key *signal_message_get_sender_ratchet_key(const signal_message *message)
{
    assert(message);
    return message->sender_ratchet_key;
}

uint8_t signal_message_get_message_version(const signal_message *message)
{
    assert(message);
    return message->message_version;
}

uint32_t signal_message_get_counter(const signal_message *message)
{
    assert(message);
    return message->counter;
}

signal_buffer *signal_message_get_body(const signal_message *message)
{
    assert(message);
    return message->ciphertext;
}

int signal_message_verify_mac(signal_message *message,
        ec_public_key *sender_identity_key,
        ec_public_key *receiver_identity_key,
        const uint8_t *mac_key, size_t mac_key_len,
        signal_context *global_context)
{
    int result = 0;
    signal_buffer *our_mac_buffer = 0;
    uint8_t *serialized_data = 0;
    size_t serialized_len = 0;
    uint8_t *serialized_message_data = 0;
    size_t serialized_message_len = 0;
    uint8_t *their_mac_data = 0;
    const size_t their_mac_len = SIGNAL_MESSAGE_MAC_LENGTH;
    uint8_t *our_mac_data = 0;
    size_t our_mac_len = 0;

    assert(message);
    assert(message->base_message.serialized);

    /* Set some pointers and lengths for the sections of the raw data */
    serialized_data = signal_buffer_data(message->base_message.serialized);
    serialized_len = signal_buffer_len(message->base_message.serialized);
    serialized_message_data = serialized_data;
    serialized_message_len = serialized_len - SIGNAL_MESSAGE_MAC_LENGTH;
    their_mac_data = serialized_data + serialized_message_len;

    result = signal_message_get_mac(&our_mac_buffer,
            message->message_version,
            sender_identity_key, receiver_identity_key,
            mac_key, mac_key_len,
            serialized_message_data, serialized_message_len,
            message->base_message.global_context);
    if(result < 0) {
        goto complete;
    }

    our_mac_data = signal_buffer_data(our_mac_buffer);
    our_mac_len = signal_buffer_len(our_mac_buffer);
    if(our_mac_len != their_mac_len) {
        signal_log(global_context, SG_LOG_WARNING, "MAC length mismatch: %d != %d", our_mac_len, their_mac_len);
        result = SG_ERR_UNKNOWN;
        goto complete;
    }

    if(signal_constant_memcmp(our_mac_data, their_mac_data, our_mac_len) == 0) {
        result = 1;
    }
    else {
        signal_log(global_context, SG_LOG_NOTICE, "Bad MAC");
        result = 0;
    }

complete:
    if(our_mac_buffer) {
        signal_buffer_free(our_mac_buffer);
    }
    return result;
}

static int signal_message_get_mac(signal_buffer **buffer,
        uint8_t message_version,
        ec_public_key *sender_identity_key,
        ec_public_key *receiver_identity_key,
        const uint8_t *mac_key, size_t mac_key_len,
        const uint8_t *serialized, size_t serialized_len,
        signal_context *global_context)
{
    int result = 0;
    void *hmac_context;
    signal_buffer *sender_key_buffer = 0;
    signal_buffer *receiver_key_buffer = 0;
    signal_buffer *full_mac_buffer = 0;
    signal_buffer *result_buf = 0;
    uint8_t *result_data = 0;

    assert(global_context);

    result = signal_hmac_sha256_init(global_context,
            &hmac_context, mac_key, mac_key_len);
    if(result < 0) {
        goto complete;
    }

    if(message_version >= 3) {
        result = ec_public_key_serialize(&sender_key_buffer, sender_identity_key);
        if(result < 0) {
            goto complete;
        }

        result = signal_hmac_sha256_update(global_context, hmac_context,
                signal_buffer_data(sender_key_buffer),
                signal_buffer_len(sender_key_buffer));
        if(result < 0) {
            goto complete;
        }

        result = ec_public_key_serialize(&receiver_key_buffer, receiver_identity_key);
        if(result < 0) {
            goto complete;
        }

        result = signal_hmac_sha256_update(global_context, hmac_context,
                signal_buffer_data(receiver_key_buffer),
                signal_buffer_len(receiver_key_buffer));
        if(result < 0) {
            goto complete;
        }
    }

    result = signal_hmac_sha256_update(global_context, hmac_context,
        serialized, serialized_len);
    if(result < 0) {
        goto complete;
    }

    result = signal_hmac_sha256_final(global_context,
            hmac_context, &full_mac_buffer);
    if(result < 0 || signal_buffer_len(full_mac_buffer) < SIGNAL_MESSAGE_MAC_LENGTH) {
        if(result >= 0) { result = SG_ERR_UNKNOWN; }
        goto complete;
    }

    result_buf = signal_buffer_alloc(SIGNAL_MESSAGE_MAC_LENGTH);
    if(!result_buf) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    result_data = signal_buffer_data(result_buf);
    memcpy(result_data, signal_buffer_data(full_mac_buffer), SIGNAL_MESSAGE_MAC_LENGTH);

complete:
    signal_hmac_sha256_cleanup(global_context, hmac_context);
    signal_buffer_free(sender_key_buffer);
    signal_buffer_free(receiver_key_buffer);
    signal_buffer_free(full_mac_buffer);
    if(result >= 0) {
        *buffer = result_buf;
    }
    return result;
}

int signal_message_is_legacy(const uint8_t *data, size_t len)
{
    return data && len >= 1 && ((data[0] & 0xF0) >> 4) <= CIPHERTEXT_UNSUPPORTED_VERSION;
}

void signal_message_destroy(signal_type_base *type)
{
    signal_message *message = (signal_message *)type;

    if(message->base_message.serialized) {
        signal_buffer_free(message->base_message.serialized);
    }
    SIGNAL_UNREF(message->sender_ratchet_key);
    if(message->ciphertext) {
        signal_buffer_free(message->ciphertext);
    }
    free(message);
}

/*------------------------------------------------------------------------*/

int pre_key_signal_message_create(pre_key_signal_message **pre_key_message,
        uint8_t message_version, uint32_t registration_id, const uint32_t *pre_key_id,
        uint32_t signed_pre_key_id, ec_public_key *base_key, ec_public_key *identity_key,
        signal_message *message,
        signal_context *global_context)
{
    int result = 0;
    pre_key_signal_message *result_message = 0;

    assert(global_context);

    result_message = malloc(sizeof(pre_key_signal_message));

    if(!result_message) {
        return SG_ERR_NOMEM;
    }
    memset(result_message, 0, sizeof(pre_key_signal_message));
    SIGNAL_INIT(result_message, pre_key_signal_message_destroy);

    result_message->base_message.message_type = CIPHERTEXT_PREKEY_TYPE;
    result_message->base_message.global_context = global_context;

    result_message->version = message_version;
    result_message->registration_id = registration_id;
    if(pre_key_id) {
        result_message->has_pre_key_id = 1;
        result_message->pre_key_id = *pre_key_id;
    }
    result_message->signed_pre_key_id = signed_pre_key_id;

    SIGNAL_REF(base_key);
    result_message->base_key = base_key;

    SIGNAL_REF(identity_key);
    result_message->identity_key = identity_key;

    SIGNAL_REF(message);
    result_message->message = message;

    result = pre_key_signal_message_serialize(&result_message->base_message.serialized, result_message);

    if(result >= 0) {
        result = 0;
        *pre_key_message = result_message;
    }
    else {
        if(result_message) {
            SIGNAL_UNREF(result_message);
        }
    }
    return result;
}

static int pre_key_signal_message_serialize(signal_buffer **buffer, const pre_key_signal_message *message)
{
    int result = 0;
    signal_buffer *result_buf = 0;
    upb_Arena *arena = 0;
    textsecure_PreKeySignalMessage *message_structure = 0;
    upb_StringView key;

    uint8_t version = (message->version << 4) | CIPHERTEXT_CURRENT_VERSION;

    arena = upb_Arena_New();
    message_structure = arena ? textsecure_PreKeySignalMessage_new(arena) : 0;
    if(!message_structure) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    textsecure_PreKeySignalMessage_set_registrationId(message_structure, message->registration_id);

    if(message->has_pre_key_id) {
        textsecure_PreKeySignalMessage_set_preKeyId(message_structure, message->pre_key_id);
    }

    textsecure_PreKeySignalMessage_set_signedPreKeyId(message_structure, message->signed_pre_key_id);

    result = ec_public_key_serialize_protobuf(&key, message->base_key, arena);
    if(result < 0) {
        goto complete;
    }
    textsecure_PreKeySignalMessage_set_baseKey(message_structure, key);

    result = ec_public_key_serialize_protobuf(&key, message->identity_key, arena);
    if(result < 0) {
        goto complete;
    }
    textsecure_PreKeySignalMessage_set_identityKey(message_structure, key);

    textsecure_PreKeySignalMessage_set_message(message_structure,
            signal_buffer_protobuf(message->message->base_message.serialized));

    result = signal_buffer_from_protobuf(&result_buf, message_structure,
            &textsecure__PreKeySignalMessage_msg_init, arena, 1, 0);
    if(result < 0) {
        goto complete;
    }
    signal_buffer_data(result_buf)[0] = version;

complete:
    if(arena) {
        upb_Arena_Free(arena);
    }
    if(result >= 0) {
        *buffer = result_buf;
    }
    return result;
}

int pre_key_signal_message_deserialize(pre_key_signal_message **message,
        const uint8_t *data, size_t len,
        signal_context *global_context)
{
    int result = 0;
    pre_key_signal_message *result_message = 0;
    upb_Arena *arena = 0;
    textsecure_PreKeySignalMessage *message_structure = 0;
    upb_StringView field;
    uint8_t version = 0;
    const uint8_t *message_data = 0;
    size_t message_len = 0;
    uint8_t *serialized_data = 0;

    assert(global_context);

    if(!data || len <= 1) {
        result = SG_ERR_INVAL;
        goto complete;
    }

    version = (data[0] & 0xF0) >> 4;

    /* Set some pointers and lengths for the sections of the raw data */
    message_data = data + 1;
    message_len = len - 1;

    if(version < CIPHERTEXT_CURRENT_VERSION) {
        signal_log(global_context, SG_LOG_WARNING, "Unsupported legacy version: %d", version);
        result = SG_ERR_LEGACY_MESSAGE;
        goto complete;
    }

    if(version > CIPHERTEXT_CURRENT_VERSION) {
        signal_log(global_context, SG_LOG_WARNING, "Unknown version: %d", version);
        result = SG_ERR_INVALID_VERSION;
        goto complete;
    }

    arena = upb_Arena_New();
    if(!arena) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    message_structure = textsecure_PreKeySignalMessage_parse((const char *)message_data, message_len, arena);
    if(!message_structure) {
        result = SG_ERR_INVALID_PROTO_BUF;
        goto complete;
    }

    if(!textsecure_PreKeySignalMessage_has_signedPreKeyId(message_structure) ||
            !textsecure_PreKeySignalMessage_has_baseKey(message_structure) ||
            !textsecure_PreKeySignalMessage_has_identityKey(message_structure) ||
            !textsecure_PreKeySignalMessage_has_message(message_structure)) {
        signal_log(global_context, SG_LOG_WARNING, "Incomplete message");
        result = SG_ERR_INVALID_MESSAGE;
        goto complete;
    }

    result_message = malloc(sizeof(pre_key_signal_message));
    if(!result_message) {
        result = SG_ERR_NOMEM;
        goto complete;
    }
    memset(result_message, 0, sizeof(pre_key_signal_message));
    SIGNAL_INIT(result_message, pre_key_signal_message_destroy);

    result_message->base_message.message_type = CIPHERTEXT_PREKEY_TYPE;
    result_message->base_message.global_context = global_context;

    result_message->version = version;

    if(textsecure_PreKeySignalMessage_has_registrationId(message_structure)) {
        result_message->registration_id = textsecure_PreKeySignalMessage_registrationId(message_structure);
    }

    if(textsecure_PreKeySignalMessage_has_preKeyId(message_structure)) {
        result_message->pre_key_id = textsecure_PreKeySignalMessage_preKeyId(message_structure);
        result_message->has_pre_key_id = 1;
    }

    if(textsecure_PreKeySignalMessage_has_signedPreKeyId(message_structure)) {
        result_message->signed_pre_key_id = textsecure_PreKeySignalMessage_signedPreKeyId(message_structure);
    }

    if(textsecure_PreKeySignalMessage_has_baseKey(message_structure)) {
        field = textsecure_PreKeySignalMessage_baseKey(message_structure);
        result = curve_decode_point(&result_message->base_key,
                (const uint8_t *)field.data, field.size, global_context);
        if(result < 0) {
            goto complete;
        }
    }

    if(textsecure_PreKeySignalMessage_has_identityKey(message_structure)) {
        field = textsecure_PreKeySignalMessage_identityKey(message_structure);
        result = curve_decode_point(&result_message->identity_key,
                (const uint8_t *)field.data, field.size, global_context);
        if(result < 0) {
            goto complete;
        }
    }

    if(textsecure_PreKeySignalMessage_has_message(message_structure)) {
        field = textsecure_PreKeySignalMessage_message(message_structure);
        result = signal_message_deserialize(&result_message->message,
                (const uint8_t *)field.data,
                field.size,
                global_context);
        if(result < 0) {
            goto complete;
        }
        if(result_message->message->message_version != version) {
            signal_log(global_context, SG_LOG_WARNING, "Inner message version mismatch: %d != %d",
                    result_message->message->message_version, version);
            result = SG_ERR_INVALID_VERSION;
            goto complete;
        }
    }

    result_message->base_message.serialized = signal_buffer_alloc(len);
    if(!result_message->base_message.serialized) {
        result = SG_ERR_NOMEM;
        goto complete;
    }
    serialized_data = signal_buffer_data(result_message->base_message.serialized);
    memcpy(serialized_data, data, len);

complete:
    if(arena) {
        upb_Arena_Free(arena);
    }
    if(result >= 0) {
        *message = result_message;
    }
    else {
        if(result_message) {
            SIGNAL_UNREF(result_message);
        }
    }
    return result;
}

int pre_key_signal_message_copy(pre_key_signal_message **message, pre_key_signal_message *other_message, signal_context *global_context)
{
    int result = 0;
    pre_key_signal_message *result_message = 0;

    assert(other_message);
    assert(global_context);

    result = pre_key_signal_message_deserialize(
            &result_message,
            signal_buffer_data(other_message->base_message.serialized),
            signal_buffer_len(other_message->base_message.serialized),
            global_context);
    if(result >= 0) {
        *message = result_message;
    }

    return result;
}

uint8_t pre_key_signal_message_get_message_version(const pre_key_signal_message *message)
{
    assert(message);
    return message->version;
}

ec_public_key *pre_key_signal_message_get_identity_key(const pre_key_signal_message *message)
{
    assert(message);
    return message->identity_key;
}

uint32_t pre_key_signal_message_get_registration_id(const pre_key_signal_message *message)
{
    assert(message);
    return message->registration_id;
}

int pre_key_signal_message_has_pre_key_id(const pre_key_signal_message *message)
{
    assert(message);
    return message->has_pre_key_id;
}

uint32_t pre_key_signal_message_get_pre_key_id(const pre_key_signal_message *message)
{
    assert(message);
    assert(message->has_pre_key_id);
    return message->pre_key_id;
}

uint32_t pre_key_signal_message_get_signed_pre_key_id(const pre_key_signal_message *message)
{
    assert(message);
    return message->signed_pre_key_id;
}

ec_public_key *pre_key_signal_message_get_base_key(const pre_key_signal_message *message)
{
    assert(message);
    return message->base_key;
}

signal_message *pre_key_signal_message_get_signal_message(const pre_key_signal_message *message)
{
    assert(message);
    return message->message;
}

void pre_key_signal_message_destroy(signal_type_base *type)
{
    pre_key_signal_message *message = (pre_key_signal_message *)type;

    if(message->base_message.serialized) {
        signal_buffer_free(message->base_message.serialized);
    }
    SIGNAL_UNREF(message->base_key);
    SIGNAL_UNREF(message->identity_key);
    SIGNAL_UNREF(message->message);
    free(message);
}

int sender_key_message_create(sender_key_message **message,
        uint32_t key_id, uint32_t iteration,
        const uint8_t *ciphertext, size_t ciphertext_len,
        ec_private_key *signature_key,
        signal_context *global_context)
{
    int result = 0;
    sender_key_message *result_message = 0;
    signal_buffer *message_buf = 0;

    assert(global_context);

    result_message = malloc(sizeof(sender_key_message));

    if(!result_message) {
        return SG_ERR_NOMEM;
    }
    memset(result_message, 0, sizeof(sender_key_message));
    SIGNAL_INIT(result_message, sender_key_message_destroy);

    result_message->base_message.message_type = CIPHERTEXT_SENDERKEY_TYPE;
    result_message->base_message.global_context = global_context;

    result_message->message_version = CIPHERTEXT_CURRENT_VERSION;
    result_message->key_id = key_id;
    result_message->iteration = iteration;

    result_message->ciphertext = signal_buffer_create(ciphertext, ciphertext_len);
    if(!result_message->ciphertext) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    result = sender_key_message_serialize(&message_buf, result_message, signature_key, global_context);
    if(result < 0) {
        goto complete;
    }

    result_message->base_message.serialized = message_buf;

complete:
    if(result >= 0) {
        result = 0;
        *message = result_message;
    }
    else {
        if(result_message) {
            SIGNAL_UNREF(result_message);
        }
    }
    return result;
}

int sender_key_message_serialize(signal_buffer **buffer, const sender_key_message *message, ec_private_key *signature_key, signal_context *global_context)
{
    int result = 0;
    uint8_t version = (CIPHERTEXT_CURRENT_VERSION << 4) | CIPHERTEXT_CURRENT_VERSION;
    signal_buffer *result_buf = 0;
    signal_buffer *signature_buf = 0;
    upb_Arena *arena = 0;
    textsecure_SenderKeyMessage *message_structure = 0;
    size_t len = 0;
    uint8_t *data = 0;

    arena = upb_Arena_New();
    message_structure = arena ? textsecure_SenderKeyMessage_new(arena) : 0;
    if(!message_structure) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    textsecure_SenderKeyMessage_set_id(message_structure, message->key_id);
    textsecure_SenderKeyMessage_set_iteration(message_structure, message->iteration);
    textsecure_SenderKeyMessage_set_ciphertext(message_structure, signal_buffer_protobuf(message->ciphertext));

    result = signal_buffer_from_protobuf(&result_buf, message_structure,
            &textsecure__SenderKeyMessage_msg_init, arena, sizeof(version), SIGNATURE_LENGTH);
    if(result < 0) {
        goto complete;
    }

    data = signal_buffer_data(result_buf);
    data[0] = version;
    len = signal_buffer_len(result_buf) - sizeof(version) - SIGNATURE_LENGTH;

    result = curve_calculate_signature(global_context, &signature_buf, signature_key,
            data, len + sizeof(version));
    if(result < 0) {
        if(result == SG_ERR_INVALID_KEY) {
            result = SG_ERR_UNKNOWN;
        }
        goto complete;
    }
    else if(signal_buffer_len(signature_buf) != SIGNATURE_LENGTH) {
        result = SG_ERR_UNKNOWN;
        goto complete;
    }

    memcpy(data + sizeof(version) + len, signal_buffer_data(signature_buf), SIGNATURE_LENGTH);

complete:
    if(arena) {
        upb_Arena_Free(arena);
    }
    signal_buffer_free(signature_buf);
    if(result >= 0) {
        *buffer = result_buf;
    }
    else {
        signal_buffer_free(result_buf);
    }
    return result;
}

int sender_key_message_deserialize(sender_key_message **message,
        const uint8_t *data, size_t len,
        signal_context *global_context)
{
    int result = 0;
    sender_key_message *result_message = 0;
    uint8_t version = 0;
    const uint8_t *message_data = 0;
    size_t message_len = 0;
    upb_Arena *arena = 0;
    textsecure_SenderKeyMessage *message_structure = 0;
    upb_StringView field;

    assert(global_context);

    if(!data || len <= sizeof(uint8_t) + SIGNATURE_LENGTH) {
        result = SG_ERR_INVAL;
        goto complete;
    }

    version = (data[0] & 0xF0) >> 4;
    message_data = data + sizeof(uint8_t);
    message_len = len - sizeof(uint8_t) - SIGNATURE_LENGTH;

    if(version < CIPHERTEXT_CURRENT_VERSION) {
        signal_log(global_context, SG_LOG_WARNING, "Legacy message: %d", version);
        result = SG_ERR_LEGACY_MESSAGE;
        goto complete;
    }

    if(version > CIPHERTEXT_CURRENT_VERSION) {
        signal_log(global_context, SG_LOG_WARNING, "Unknown version: %d", version);
        result = SG_ERR_INVALID_VERSION;
        goto complete;
    }

    arena = upb_Arena_New();
    if(!arena) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    message_structure = textsecure_SenderKeyMessage_parse((const char *)message_data, message_len, arena);
    if(!message_structure) {
        result = SG_ERR_INVALID_PROTO_BUF;
        goto complete;
    }

    if(!textsecure_SenderKeyMessage_has_id(message_structure)
            || !textsecure_SenderKeyMessage_has_iteration(message_structure)
            || !textsecure_SenderKeyMessage_has_ciphertext(message_structure)) {
        signal_log(global_context, SG_LOG_WARNING, "Incomplete message");
        result = SG_ERR_INVALID_MESSAGE;
        goto complete;
    }

    result_message = malloc(sizeof(sender_key_message));
    if(!result_message) {
        result = SG_ERR_NOMEM;
        goto complete;
    }
    memset(result_message, 0, sizeof(sender_key_message));
    SIGNAL_INIT(result_message, sender_key_message_destroy);

    result_message->base_message.message_type = CIPHERTEXT_SENDERKEY_TYPE;
    result_message->base_message.global_context = global_context;

    result_message->key_id = textsecure_SenderKeyMessage_id(message_structure);
    result_message->iteration = textsecure_SenderKeyMessage_iteration(message_structure);
    result_message->message_version = version;

    field = textsecure_SenderKeyMessage_ciphertext(message_structure);
    result_message->ciphertext = signal_buffer_create((const uint8_t *)field.data, field.size);
    if(!result_message->ciphertext) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    result_message->base_message.serialized = signal_buffer_create(data, len);
    if(!result_message->base_message.serialized) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

complete:
    if(arena) {
        upb_Arena_Free(arena);
    }
    if(result >= 0) {
        *message = result_message;
    }
    else {
        if(result_message) {
            SIGNAL_UNREF(result_message);
        }
    }
    return result;
}

int sender_key_message_copy(sender_key_message **message, sender_key_message *other_message, signal_context *global_context)
{
    int result = 0;
    sender_key_message *result_message = 0;

    assert(other_message);
    assert(global_context);

    result = sender_key_message_deserialize(
            &result_message,
            signal_buffer_data(other_message->base_message.serialized),
            signal_buffer_len(other_message->base_message.serialized),
            global_context);
    if(result >= 0) {
        *message = result_message;
    }

    return result;
}

uint32_t sender_key_message_get_key_id(sender_key_message *message)
{
    assert(message);
    return message->key_id;
}

uint32_t sender_key_message_get_iteration(sender_key_message *message)
{
    assert(message);
    return message->iteration;
}

signal_buffer *sender_key_message_get_ciphertext(sender_key_message *message)
{
    assert(message);
    return message->ciphertext;
}

int sender_key_message_verify_signature(sender_key_message *message, ec_public_key *signature_key)
{
    int result = 0;
    uint8_t *data;
    size_t data_len;

    assert(message);

    data = signal_buffer_data(message->base_message.serialized);
    data_len = signal_buffer_len(message->base_message.serialized) - SIGNATURE_LENGTH;

    result = curve_verify_signature(signature_key, data, data_len, data + data_len, SIGNATURE_LENGTH);

    if(result == 0) {
        signal_log(message->base_message.global_context, SG_LOG_ERROR, "Invalid signature!");
        result = SG_ERR_INVALID_MESSAGE;
    }
    else if(result < 0) {
        result = SG_ERR_INVALID_MESSAGE;
    }
    else {
        result = 0;
    }

    return result;
}

void sender_key_message_destroy(signal_type_base *type)
{
    sender_key_message *message = (sender_key_message *)type;

    if(message->base_message.serialized) {
        signal_buffer_free(message->base_message.serialized);
    }
    if(message->ciphertext) {
        signal_buffer_free(message->ciphertext);
    }
    free(message);
}

int sender_key_distribution_message_create(sender_key_distribution_message **message,
        uint32_t id, uint32_t iteration,
        const uint8_t *chain_key, size_t chain_key_len,
        ec_public_key *signature_key,
        signal_context *global_context)
{
    int result = 0;

    sender_key_distribution_message *result_message = 0;
    signal_buffer *message_buf = 0;

    assert(global_context);

    result_message = malloc(sizeof(sender_key_distribution_message));

    if(!result_message) {
        return SG_ERR_NOMEM;
    }
    memset(result_message, 0, sizeof(sender_key_distribution_message));
    SIGNAL_INIT(result_message, sender_key_distribution_message_destroy);

    result_message->base_message.message_type = CIPHERTEXT_SENDERKEY_DISTRIBUTION_TYPE;
    result_message->base_message.global_context = global_context;

    result_message->id = id;
    result_message->iteration = iteration;

    result_message->chain_key = signal_buffer_create(chain_key, chain_key_len);
    if(!result_message->chain_key) {
        goto complete;
    }

    SIGNAL_REF(signature_key);
    result_message->signature_key = signature_key;

    result = sender_key_distribution_message_serialize(&message_buf, result_message);
    if(result < 0) {
        goto complete;
    }

    result_message->base_message.serialized = message_buf;

complete:
    if(result >= 0) {
        result = 0;
        *message = result_message;
    }
    else {
        if(result_message) {
            SIGNAL_UNREF(result_message);
        }
    }
    return result;
}

int sender_key_distribution_message_serialize(signal_buffer **buffer, const sender_key_distribution_message *message)
{
    int result = 0;
    uint8_t version = (CIPHERTEXT_CURRENT_VERSION << 4) | CIPHERTEXT_CURRENT_VERSION;
    signal_buffer *result_buf = 0;
    upb_Arena *arena = 0;
    textsecure_SenderKeyDistributionMessage *message_structure = 0;
    upb_StringView signing_key;

    arena = upb_Arena_New();
    message_structure = arena ? textsecure_SenderKeyDistributionMessage_new(arena) : 0;
    if(!message_structure) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    textsecure_SenderKeyDistributionMessage_set_id(message_structure, message->id);
    textsecure_SenderKeyDistributionMessage_set_iteration(message_structure, message->iteration);
    textsecure_SenderKeyDistributionMessage_set_chainKey(message_structure, signal_buffer_protobuf(message->chain_key));

    result = ec_public_key_serialize_protobuf(&signing_key, message->signature_key, arena);
    if(result < 0) {
        goto complete;
    }
    textsecure_SenderKeyDistributionMessage_set_signingKey(message_structure, signing_key);

    result = signal_buffer_from_protobuf(&result_buf, message_structure,
            &textsecure__SenderKeyDistributionMessage_msg_init, arena, sizeof(version), 0);
    if(result < 0) {
        goto complete;
    }
    signal_buffer_data(result_buf)[0] = version;

complete:
    if(arena) {
        upb_Arena_Free(arena);
    }
    if(result >= 0) {
        *buffer = result_buf;
    }
    else {
        signal_buffer_free(result_buf);
    }
    return result;
}

int sender_key_distribution_message_deserialize(sender_key_distribution_message **message,
        const uint8_t *data, size_t len,
        signal_context *global_context)
{
    int result = 0;
    sender_key_distribution_message *result_message = 0;
    uint8_t version = 0;
    const uint8_t *message_data = 0;
    size_t message_len = 0;
    upb_Arena *arena = 0;
    textsecure_SenderKeyDistributionMessage *message_structure = 0;
    upb_StringView field;

    assert(global_context);

    if(!data || len <= sizeof(uint8_t)) {
        result = SG_ERR_INVAL;
        goto complete;
    }

    version = (data[0] & 0xF0) >> 4;
    message_data = data + sizeof(uint8_t);
    message_len = len - sizeof(uint8_t);

    if(version < CIPHERTEXT_CURRENT_VERSION) {
        signal_log(global_context, SG_LOG_WARNING, "Legacy message: %d", version);
        result = SG_ERR_LEGACY_MESSAGE;
        goto complete;
    }

    if(version > CIPHERTEXT_CURRENT_VERSION) {
        signal_log(global_context, SG_LOG_WARNING, "Unknown version: %d", version);
        result = SG_ERR_INVALID_VERSION;
        goto complete;
    }

    arena = upb_Arena_New();
    if(!arena) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    message_structure = textsecure_SenderKeyDistributionMessage_parse((const char *)message_data, message_len, arena);
    if(!message_structure) {
        result = SG_ERR_INVALID_PROTO_BUF;
        goto complete;
    }

    if(!textsecure_SenderKeyDistributionMessage_has_id(message_structure)
            || !textsecure_SenderKeyDistributionMessage_has_iteration(message_structure)
            || !textsecure_SenderKeyDistributionMessage_has_chainKey(message_structure)
            || !textsecure_SenderKeyDistributionMessage_has_signingKey(message_structure)) {
        signal_log(global_context, SG_LOG_WARNING, "Incomplete message");
        result = SG_ERR_INVALID_MESSAGE;
        goto complete;
    }

    result_message = malloc(sizeof(sender_key_distribution_message));
    if(!result_message) {
        result = SG_ERR_NOMEM;
        goto complete;
    }
    memset(result_message, 0, sizeof(sender_key_distribution_message));
    SIGNAL_INIT(result_message, sender_key_distribution_message_destroy);

    result_message->base_message.message_type = CIPHERTEXT_SENDERKEY_DISTRIBUTION_TYPE;
    result_message->base_message.global_context = global_context;

    result_message->id = textsecure_SenderKeyDistributionMessage_id(message_structure);
    result_message->iteration = textsecure_SenderKeyDistributionMessage_iteration(message_structure);

    field = textsecure_SenderKeyDistributionMessage_chainKey(message_structure);
    result_message->chain_key = signal_buffer_create((const uint8_t *)field.data, field.size);
    if(!result_message->chain_key) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    field = textsecure_SenderKeyDistributionMessage_signingKey(message_structure);
    result = curve_decode_point(&result_message->signature_key,
            (const uint8_t *)field.data,
            field.size,
            global_context);
    if(result < 0) {
        goto complete;
    }

    result_message->base_message.serialized = signal_buffer_create(data, len);
    if(!result_message->base_message.serialized) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

complete:
    if(arena) {
        upb_Arena_Free(arena);
    }
    if(result >= 0) {
        *message = result_message;
    }
    else {
        if(result_message) {
            SIGNAL_UNREF(result_message);
        }
    }
    return result;
}

int sender_key_distribution_message_copy(sender_key_distribution_message **message, sender_key_distribution_message *other_message, signal_context *global_context)
{
    int result = 0;
    sender_key_distribution_message *result_message = 0;

    assert(other_message);
    assert(global_context);

    result = sender_key_distribution_message_deserialize(
            &result_message,
            signal_buffer_data(other_message->base_message.serialized),
            signal_buffer_len(other_message->base_message.serialized),
            global_context);
    if(result >= 0) {
        *message = result_message;
    }

    return result;
}

uint32_t sender_key_distribution_message_get_id(sender_key_distribution_message *message)
{
    assert(message);
    return message->id;
}

uint32_t sender_key_distribution_message_get_iteration(sender_key_distribution_message *message)
{
    assert(message);
    return message->iteration;
}

signal_buffer *sender_key_distribution_message_get_chain_key(sender_key_distribution_message *message)
{
    assert(message);
    return message->chain_key;
}

ec_public_key *sender_key_distribution_message_get_signature_key(sender_key_distribution_message *message)
{
    assert(message);
    return message->signature_key;
}

void sender_key_distribution_message_destroy(signal_type_base *type)
{
    sender_key_distribution_message *message = (sender_key_distribution_message *)type;

    if(message->base_message.serialized) {
        signal_buffer_free(message->base_message.serialized);
    }

    if(message->chain_key) {
        signal_buffer_free(message->chain_key);
    }
    SIGNAL_UNREF(message->signature_key);
    free(message);
}
