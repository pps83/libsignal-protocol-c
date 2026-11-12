#include "session_pre_key.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "curve.h"
#include "signal_protocol_internal.h"

struct session_pre_key {
    signal_type_base base;
    uint32_t id;
    ec_key_pair *key_pair;
};

struct session_signed_pre_key {
    signal_type_base base;
    uint32_t id;
    ec_key_pair *key_pair;
    uint64_t timestamp;
    size_t signature_len;
    uint8_t signature[];
};

struct session_pre_key_bundle {
    signal_type_base base;
    uint32_t registration_id;
    int device_id;
    uint32_t pre_key_id;
    ec_public_key *pre_key_public;
    uint32_t signed_pre_key_id;
    ec_public_key *signed_pre_key_public;
    signal_buffer *signed_pre_key_signature;
    ec_public_key *identity_key;
};

/*------------------------------------------------------------------------*/

int session_pre_key_create(session_pre_key **pre_key, uint32_t id, ec_key_pair *key_pair)
{
    session_pre_key *result = 0;

    assert(key_pair);

    result = malloc(sizeof(session_pre_key));
    if(!result) {
        return SG_ERR_NOMEM;
    }
    memset(result, 0, sizeof(session_pre_key));
    SIGNAL_INIT(result, session_pre_key_destroy);

    result->id = id;

    SIGNAL_REF(key_pair);
    result->key_pair = key_pair;

    *pre_key = result;
    return 0;
}

int session_pre_key_serialize(signal_buffer **buffer, const session_pre_key *pre_key)
{
    int result = 0;
    upb_Arena *arena = 0;
    textsecure_PreKeyRecordStructure *record = 0;
    signal_buffer *public_buf = 0;
    signal_buffer *private_buf = 0;
    signal_buffer *result_buf = 0;
    ec_public_key *public_key = 0;
    ec_private_key *private_key = 0;

    if(!pre_key) {
        result = SG_ERR_INVAL;
        goto complete;
    }

    public_key = ec_key_pair_get_public(pre_key->key_pair);
    result = ec_public_key_serialize(&public_buf, public_key);
    if(result < 0) {
        goto complete;
    }

    private_key = ec_key_pair_get_private(pre_key->key_pair);
    result = ec_private_key_serialize(&private_buf, private_key);
    if(result < 0) {
        goto complete;
    }

    arena = upb_Arena_New();
    record = arena ? textsecure_PreKeyRecordStructure_new(arena) : 0;
    if(!record) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    textsecure_PreKeyRecordStructure_set_id(record, pre_key->id);
    textsecure_PreKeyRecordStructure_set_publicKey(record, signal_buffer_protobuf(public_buf));
    textsecure_PreKeyRecordStructure_set_privateKey(record, signal_buffer_protobuf(private_buf));

    result = signal_buffer_from_protobuf(&result_buf, record, &textsecure__PreKeyRecordStructure_msg_init, arena, 0, 0);

complete:
    if(arena) {
        upb_Arena_Free(arena);
    }
    if(public_buf) {
        signal_buffer_free(public_buf);
    }
    if(private_buf) {
        signal_buffer_free(private_buf);
    }
    if(result >= 0) {
        *buffer = result_buf;
    }
    return result;
}

int session_pre_key_deserialize(session_pre_key **pre_key, const uint8_t *data, size_t len, signal_context *global_context)
{
    int result = 0;
    upb_Arena *arena = 0;
    textsecure_PreKeyRecordStructure *record = 0;
    upb_StringView field;
    ec_public_key *public_key = 0;
    ec_private_key *private_key = 0;
    ec_key_pair *key_pair = 0;
    session_pre_key *result_pre_key = 0;

    arena = upb_Arena_New();
    if(!arena) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    record = textsecure_PreKeyRecordStructure_parse((const char *)data, len, arena);
    if(!record) {
        result = SG_ERR_INVALID_PROTO_BUF;
        goto complete;
    }

    if(!textsecure_PreKeyRecordStructure_has_id(record)
            || !textsecure_PreKeyRecordStructure_has_publicKey(record)
            || !textsecure_PreKeyRecordStructure_has_privateKey(record)) {
        result = SG_ERR_INVALID_KEY;
        goto complete;
    }

    field = textsecure_PreKeyRecordStructure_publicKey(record);
    result = curve_decode_point(&public_key, (const uint8_t *)field.data, field.size, global_context);
    if(result < 0) {
        goto complete;
    }

    field = textsecure_PreKeyRecordStructure_privateKey(record);
    result = curve_decode_private_point(&private_key, (const uint8_t *)field.data, field.size, global_context);
    if(result < 0) {
        goto complete;
    }

    result = ec_key_pair_create(&key_pair, public_key, private_key);
    if(result < 0) {
        goto complete;
    }

    result = session_pre_key_create(&result_pre_key, textsecure_PreKeyRecordStructure_id(record), key_pair);
    if(result < 0) {
        goto complete;
    }

complete:
    if(arena) {
        upb_Arena_Free(arena);
    }
    if(public_key) {
        SIGNAL_UNREF(public_key);
    }
    if(private_key) {
        SIGNAL_UNREF(private_key);
    }
    if(key_pair) {
        SIGNAL_UNREF(key_pair);
    }
    if(result >= 0) {
        *pre_key = result_pre_key;
    }
    return result;
}

uint32_t session_pre_key_get_id(const session_pre_key *pre_key)
{
    return pre_key->id;
}

ec_key_pair *session_pre_key_get_key_pair(const session_pre_key *pre_key)
{
    return pre_key->key_pair;
}

void session_pre_key_destroy(signal_type_base *type)
{
    session_pre_key *pre_key = (session_pre_key *)type;

    if(pre_key->key_pair) {
        SIGNAL_UNREF(pre_key->key_pair);
    }

    free(pre_key);
}

/*------------------------------------------------------------------------*/

int session_signed_pre_key_create(session_signed_pre_key **pre_key,
        uint32_t id, uint64_t timestamp, ec_key_pair *key_pair,
        const uint8_t *signature, size_t signature_len)
{
    session_signed_pre_key *result = 0;

    assert(key_pair);
    assert(signature);
    assert(signature_len > 0);

    if(signature_len > (SIZE_MAX - sizeof(session_signed_pre_key)) / sizeof(uint8_t)) {
        return SG_ERR_NOMEM;
    }

    result = malloc(sizeof(session_signed_pre_key) + (sizeof(uint8_t) * signature_len));
    if(!result) {
        return SG_ERR_NOMEM;
    }
    memset(result, 0, sizeof(session_signed_pre_key));
    SIGNAL_INIT(result, session_signed_pre_key_destroy);

    result->id = id;
    result->timestamp = timestamp;

    SIGNAL_REF(key_pair);
    result->key_pair = key_pair;

    result->signature_len = signature_len;

    memcpy(result->signature, signature, signature_len);

    *pre_key = result;
    return 0;
}

int session_signed_pre_key_serialize(signal_buffer **buffer, const session_signed_pre_key *pre_key)
{
    int result = 0;
    upb_Arena *arena = 0;
    textsecure_SignedPreKeyRecordStructure *record = 0;
    signal_buffer *public_buf = 0;
    signal_buffer *private_buf = 0;
    signal_buffer *signature_buf = 0;
    signal_buffer *result_buf = 0;
    ec_public_key *public_key = 0;
    ec_private_key *private_key = 0;

    public_key = ec_key_pair_get_public(pre_key->key_pair);
    result = ec_public_key_serialize(&public_buf, public_key);
    if(result < 0) {
        goto complete;
    }

    private_key = ec_key_pair_get_private(pre_key->key_pair);
    result = ec_private_key_serialize(&private_buf, private_key);
    if(result < 0) {
        goto complete;
    }

    signature_buf = signal_buffer_create(pre_key->signature, pre_key->signature_len);
    if(!signature_buf) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    arena = upb_Arena_New();
    record = arena ? textsecure_SignedPreKeyRecordStructure_new(arena) : 0;
    if(!record) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    textsecure_SignedPreKeyRecordStructure_set_id(record, pre_key->id);
    textsecure_SignedPreKeyRecordStructure_set_timestamp(record, pre_key->timestamp);
    textsecure_SignedPreKeyRecordStructure_set_publicKey(record, signal_buffer_protobuf(public_buf));
    textsecure_SignedPreKeyRecordStructure_set_privateKey(record, signal_buffer_protobuf(private_buf));
    textsecure_SignedPreKeyRecordStructure_set_signature(record, signal_buffer_protobuf(signature_buf));

    result = signal_buffer_from_protobuf(&result_buf, record,
            &textsecure__SignedPreKeyRecordStructure_msg_init, arena, 0, 0);

complete:
    if(arena) {
        upb_Arena_Free(arena);
    }
    if(public_buf) {
        signal_buffer_free(public_buf);
    }
    if(private_buf) {
        signal_buffer_free(private_buf);
    }
    if(signature_buf) {
        signal_buffer_free(signature_buf);
    }
    if(result >= 0) {
        *buffer = result_buf;
    }
    return result;
}

int session_signed_pre_key_deserialize(session_signed_pre_key **pre_key, const uint8_t *data, size_t len, signal_context *global_context)
{
    int result = 0;
    upb_Arena *arena = 0;
    textsecure_SignedPreKeyRecordStructure *record = 0;
    upb_StringView field;
    ec_public_key *public_key = 0;
    ec_private_key *private_key = 0;
    ec_key_pair *key_pair = 0;
    session_signed_pre_key *result_pre_key = 0;

    arena = upb_Arena_New();
    if(!arena) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    record = textsecure_SignedPreKeyRecordStructure_parse((const char *)data, len, arena);
    if(!record) {
        result = SG_ERR_INVALID_PROTO_BUF;
        goto complete;
    }

    if(!textsecure_SignedPreKeyRecordStructure_has_id(record)
            || !textsecure_SignedPreKeyRecordStructure_has_timestamp(record)
            || !textsecure_SignedPreKeyRecordStructure_has_publicKey(record)
            || !textsecure_SignedPreKeyRecordStructure_has_privateKey(record)
            || !textsecure_SignedPreKeyRecordStructure_has_signature(record)) {
        result = SG_ERR_INVALID_KEY;
        goto complete;
    }

    field = textsecure_SignedPreKeyRecordStructure_publicKey(record);
    result = curve_decode_point(&public_key, (const uint8_t *)field.data, field.size, global_context);
    if(result < 0) {
        goto complete;
    }

    field = textsecure_SignedPreKeyRecordStructure_privateKey(record);
    result = curve_decode_private_point(&private_key, (const uint8_t *)field.data, field.size, global_context);
    if(result < 0) {
        goto complete;
    }

    result = ec_key_pair_create(&key_pair, public_key, private_key);
    if(result < 0) {
        goto complete;
    }

    field = textsecure_SignedPreKeyRecordStructure_signature(record);
    result = session_signed_pre_key_create(&result_pre_key,
            textsecure_SignedPreKeyRecordStructure_id(record),
            textsecure_SignedPreKeyRecordStructure_timestamp(record), key_pair,
            (const uint8_t *)field.data, field.size);
    if(result < 0) {
        goto complete;
    }

complete:
    if(arena) {
        upb_Arena_Free(arena);
    }
    if(public_key) {
        SIGNAL_UNREF(public_key);
    }
    if(private_key) {
        SIGNAL_UNREF(private_key);
    }
    if(key_pair) {
        SIGNAL_UNREF(key_pair);
    }
    if(result >= 0) {
        *pre_key = result_pre_key;
    }
    return result;
}

uint32_t session_signed_pre_key_get_id(const session_signed_pre_key *pre_key)
{
    return pre_key->id;
}

uint64_t session_signed_pre_key_get_timestamp(const session_signed_pre_key *pre_key)
{
    return pre_key->timestamp;
}

ec_key_pair *session_signed_pre_key_get_key_pair(const session_signed_pre_key *pre_key)
{
    return pre_key->key_pair;
}

const uint8_t *session_signed_pre_key_get_signature(const session_signed_pre_key *pre_key)
{
    return pre_key->signature;
}

size_t session_signed_pre_key_get_signature_len(const session_signed_pre_key *pre_key)
{
    return pre_key->signature_len;
}

void session_signed_pre_key_destroy(signal_type_base *type)
{
    session_signed_pre_key *pre_key = (session_signed_pre_key *)type;

    if(pre_key->key_pair) {
        SIGNAL_UNREF(pre_key->key_pair);
    }

    free(pre_key);
}

/*------------------------------------------------------------------------*/

int session_pre_key_bundle_create(session_pre_key_bundle **bundle,
        uint32_t registration_id, int device_id, uint32_t pre_key_id,
        ec_public_key *pre_key_public,
        uint32_t signed_pre_key_id, ec_public_key *signed_pre_key_public,
        const uint8_t *signed_pre_key_signature_data, size_t signed_pre_key_signature_len,
        ec_public_key *identity_key)
{
    int result = 0;
    session_pre_key_bundle *result_bundle = 0;

    result_bundle = malloc(sizeof(session_pre_key_bundle));
    if(!result_bundle) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    memset(result_bundle, 0, sizeof(session_pre_key_bundle));
    SIGNAL_INIT(result_bundle, session_pre_key_bundle_destroy);

    result_bundle->registration_id = registration_id;
    result_bundle->device_id = device_id;
    result_bundle->pre_key_id = pre_key_id;

    if(pre_key_public) {
        SIGNAL_REF(pre_key_public);
        result_bundle->pre_key_public = pre_key_public;
    }

    result_bundle->signed_pre_key_id = signed_pre_key_id;

    if(signed_pre_key_public) {
        SIGNAL_REF(signed_pre_key_public);
        result_bundle->signed_pre_key_public = signed_pre_key_public;
    }

    if(signed_pre_key_signature_data && signed_pre_key_signature_len > 0) {
        result_bundle->signed_pre_key_signature = signal_buffer_create(
                signed_pre_key_signature_data, signed_pre_key_signature_len);
    }

    if(identity_key) {
        SIGNAL_REF(identity_key);
        result_bundle->identity_key = identity_key;
    }

complete:
    if(result >= 0) {
        *bundle = result_bundle;
    }
    else {
        if(result_bundle) {
            SIGNAL_UNREF(result_bundle);
        }
    }
    return result;
}

uint32_t session_pre_key_bundle_get_registration_id(const session_pre_key_bundle *bundle)
{
    assert(bundle);
    return bundle->registration_id;
}

int session_pre_key_bundle_get_device_id(const session_pre_key_bundle *bundle)
{
    assert(bundle);
    return bundle->device_id;
}

uint32_t session_pre_key_bundle_get_pre_key_id(const session_pre_key_bundle *bundle)
{
    assert(bundle);
    return bundle->pre_key_id;
}

ec_public_key *session_pre_key_bundle_get_pre_key(const session_pre_key_bundle *bundle)
{
    assert(bundle);
    return bundle->pre_key_public;
}

uint32_t session_pre_key_bundle_get_signed_pre_key_id(const session_pre_key_bundle *bundle)
{
    assert(bundle);
    return bundle->signed_pre_key_id;
}

ec_public_key *session_pre_key_bundle_get_signed_pre_key(const session_pre_key_bundle *bundle)
{
    assert(bundle);
    return bundle->signed_pre_key_public;
}

signal_buffer *session_pre_key_bundle_get_signed_pre_key_signature(const session_pre_key_bundle *bundle)
{
    assert(bundle);
    return bundle->signed_pre_key_signature;
}

ec_public_key *session_pre_key_bundle_get_identity_key(const session_pre_key_bundle *bundle)
{
    assert(bundle);
    return bundle->identity_key;
}

void session_pre_key_bundle_destroy(signal_type_base *type)
{
    session_pre_key_bundle *bundle = (session_pre_key_bundle *)type;

    if(bundle->pre_key_public) {
        SIGNAL_UNREF(bundle->pre_key_public);
    }
    if(bundle->signed_pre_key_public) {
        SIGNAL_UNREF(bundle->signed_pre_key_public);
    }
    if(bundle->signed_pre_key_signature) {
        signal_buffer_free(bundle->signed_pre_key_signature);
    }
    if(bundle->identity_key) {
        SIGNAL_UNREF(bundle->identity_key);
    }

    free(bundle);
}
