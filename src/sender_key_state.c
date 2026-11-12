#include "sender_key_state.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "sender_key.h"
#include "utlist.h"
#include "signal_protocol_internal.h"

#define MAX_MESSAGE_KEYS 2000

typedef struct sender_message_key_node {
    sender_message_key *key;
    struct sender_message_key_node *prev, *next;
} sender_message_key_node;

struct sender_key_state
{
    signal_type_base base;

    uint32_t key_id;
    sender_chain_key *chain_key;
    ec_public_key *signature_public_key;
    ec_private_key *signature_private_key;
    sender_message_key_node *message_keys_head;

    signal_context *global_context;
};

int sender_key_state_create(sender_key_state **state,
        uint32_t id, sender_chain_key *chain_key,
        ec_public_key *signature_public_key, ec_private_key *signature_private_key,
        signal_context *global_context)
{
    sender_key_state *result = 0;

    if(!chain_key || !signature_public_key) {
        return SG_ERR_INVAL;
    }

    result = malloc(sizeof(sender_key_state));
    if(!result) {
        return SG_ERR_NOMEM;
    }
    memset(result, 0, sizeof(sender_key_state));
    SIGNAL_INIT(result, sender_key_state_destroy);

    result->key_id = id;

    SIGNAL_REF(chain_key);
    result->chain_key = chain_key;

    SIGNAL_REF(signature_public_key);
    result->signature_public_key = signature_public_key;

    if(signature_private_key) {
        SIGNAL_REF(signature_private_key);
        result->signature_private_key = signature_private_key;
    }

    result->global_context = global_context;

    *state = result;
    return 0;
}

int sender_key_state_serialize(signal_buffer **buffer, sender_key_state *state)
{
    int result = 0;
    upb_Arena *arena = 0;
    textsecure_SenderKeyStateStructure *state_structure = 0;
    signal_buffer *result_buf = 0;

    arena = upb_Arena_New();
    state_structure = arena ? textsecure_SenderKeyStateStructure_new(arena) : 0;
    if(!state_structure) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    result = sender_key_state_serialize_prepare(state, state_structure, arena);
    if(result < 0) {
        goto complete;
    }

    result = signal_buffer_from_protobuf(&result_buf, state_structure,
            &textsecure__SenderKeyStateStructure_msg_init, arena, 0, 0);

complete:
    if(arena) {
        upb_Arena_Free(arena);
    }
    if(result >= 0) {
        *buffer = result_buf;
    }
    return result;
}

int sender_key_state_deserialize(sender_key_state **state, const uint8_t *data, size_t len, signal_context *global_context)
{
    int result = 0;
    upb_Arena *arena = 0;
    textsecure_SenderKeyStateStructure *state_structure = 0;
    sender_key_state *result_state = 0;

    arena = upb_Arena_New();
    if(!arena) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    state_structure = textsecure_SenderKeyStateStructure_parse((const char *)data, len, arena);
    if(!state_structure) {
        result = SG_ERR_INVALID_PROTO_BUF;
        goto complete;
    }

    result = sender_key_state_deserialize_protobuf(&result_state, state_structure, global_context);
    if(result < 0) {
        goto complete;
    }

complete:
    if(arena) {
        upb_Arena_Free(arena);
    }
    if(result_state) {
        if(result < 0) {
            SIGNAL_UNREF(result_state);
        }
        else {
            *state = result_state;
        }
    }

    return result;
}

int sender_key_state_serialize_prepare(sender_key_state *state, textsecure_SenderKeyStateStructure *state_structure, upb_Arena *arena)
{
    int result = 0;
    textsecure_SenderKeyStateStructure_SenderChainKey *chain_key_structure = 0;
    textsecure_SenderKeyStateStructure_SenderSigningKey *signing_key_structure = 0;
    sender_message_key_node *cur_node = 0;
    upb_StringView key;

    assert(state);
    assert(state_structure);

    /* Sender key ID */
    textsecure_SenderKeyStateStructure_set_senderKeyId(state_structure, state->key_id);

    /* Sender chain key */
    chain_key_structure = textsecure_SenderKeyStateStructure_mutable_senderChainKey(state_structure, arena);
    if(!chain_key_structure) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    textsecure_SenderKeyStateStructure_SenderChainKey_set_iteration(chain_key_structure,
            sender_chain_key_get_iteration(state->chain_key));
    textsecure_SenderKeyStateStructure_SenderChainKey_set_seed(chain_key_structure,
            signal_buffer_protobuf(sender_chain_key_get_seed(state->chain_key)));

    /* Sender signing key */
    signing_key_structure = textsecure_SenderKeyStateStructure_mutable_senderSigningKey(state_structure, arena);
    if(!signing_key_structure) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    if(state->signature_public_key) {
        result = ec_public_key_serialize_protobuf(&key, state->signature_public_key, arena);
        if(result < 0) {
            goto complete;
        }
        textsecure_SenderKeyStateStructure_SenderSigningKey_set_public(signing_key_structure, key);
    }

    if(state->signature_private_key) {
        result = ec_private_key_serialize_protobuf(&key, state->signature_private_key, arena);
        if(result < 0) {
            goto complete;
        }
        textsecure_SenderKeyStateStructure_SenderSigningKey_set_private(signing_key_structure, key);
    }

    /* Sender message keys */
    DL_FOREACH(state->message_keys_head, cur_node) {
        textsecure_SenderKeyStateStructure_SenderMessageKey *message_key_structure =
                textsecure_SenderKeyStateStructure_add_senderMessageKeys(state_structure, arena);
        if(!message_key_structure) {
            result = SG_ERR_NOMEM;
            goto complete;
        }

        textsecure_SenderKeyStateStructure_SenderMessageKey_set_iteration(message_key_structure,
                sender_message_key_get_iteration(cur_node->key));
        textsecure_SenderKeyStateStructure_SenderMessageKey_set_seed(message_key_structure,
                signal_buffer_protobuf(sender_message_key_get_seed(cur_node->key)));
    }

complete:
    return result;
}

int sender_key_state_deserialize_protobuf(sender_key_state **state, const textsecure_SenderKeyStateStructure *state_structure, signal_context *global_context)
{
    int result = 0;
    sender_key_state *result_state = 0;
    sender_chain_key *chain_key = 0;
    ec_public_key *signature_public_key = 0;
    ec_private_key *signature_private_key = 0;
    const textsecure_SenderKeyStateStructure_SenderChainKey *chain_key_structure =
            textsecure_SenderKeyStateStructure_senderChainKey(state_structure);
    const textsecure_SenderKeyStateStructure_SenderSigningKey *signing_key_structure =
            textsecure_SenderKeyStateStructure_senderSigningKey(state_structure);
    upb_StringView field;

    if(chain_key_structure
            && textsecure_SenderKeyStateStructure_SenderChainKey_has_iteration(chain_key_structure)
            && textsecure_SenderKeyStateStructure_SenderChainKey_has_seed(chain_key_structure)) {
        signal_buffer *seed_buffer = 0;
        field = textsecure_SenderKeyStateStructure_SenderChainKey_seed(chain_key_structure);
        seed_buffer = signal_buffer_create((const uint8_t *)field.data, field.size);
        if(!seed_buffer) {
            result = SG_ERR_NOMEM;
            goto complete;
        }

        result = sender_chain_key_create(&chain_key,
                textsecure_SenderKeyStateStructure_SenderChainKey_iteration(chain_key_structure),
                seed_buffer,
                global_context);
        signal_buffer_free(seed_buffer);
        if(result < 0) {
            goto complete;
        }
    }

    if(signing_key_structure) {
        if(textsecure_SenderKeyStateStructure_SenderSigningKey_has_public(signing_key_structure)) {
            field = textsecure_SenderKeyStateStructure_SenderSigningKey_public(signing_key_structure);
            result = curve_decode_point(&signature_public_key,
                    (const uint8_t *)field.data, field.size,
                    global_context);
            if(result < 0) {
                goto complete;
            }
        }
        if(textsecure_SenderKeyStateStructure_SenderSigningKey_has_private(signing_key_structure)) {
            field = textsecure_SenderKeyStateStructure_SenderSigningKey_private(signing_key_structure);
            result = curve_decode_private_point(&signature_private_key,
                    (const uint8_t *)field.data, field.size,
                    global_context);
            if(result < 0) {
                goto complete;
            }
        }
    }

    if(textsecure_SenderKeyStateStructure_has_senderKeyId(state_structure) && chain_key && signature_public_key) {
        size_t i;
        size_t message_key_count = 0;
        const textsecure_SenderKeyStateStructure_SenderMessageKey *const *message_keys =
                textsecure_SenderKeyStateStructure_senderMessageKeys(state_structure, &message_key_count);

        result = sender_key_state_create(&result_state,
                textsecure_SenderKeyStateStructure_senderKeyId(state_structure), chain_key,
                signature_public_key, signature_private_key,
                global_context);
        if(result < 0) {
            goto complete;
        }

        if(message_key_count > 0) {
            for(i = 0; i < message_key_count; i++) {
                signal_buffer *seed_buffer;
                sender_message_key *message_key;
                const textsecure_SenderKeyStateStructure_SenderMessageKey *message_key_structure = message_keys[i];

                if(!textsecure_SenderKeyStateStructure_SenderMessageKey_has_iteration(message_key_structure)
                        || !textsecure_SenderKeyStateStructure_SenderMessageKey_has_seed(message_key_structure)) {
                    continue;
                }

                field = textsecure_SenderKeyStateStructure_SenderMessageKey_seed(message_key_structure);
                seed_buffer = signal_buffer_create((const uint8_t *)field.data, field.size);
                if(!seed_buffer) {
                    result = SG_ERR_NOMEM;
                    goto complete;
                }

                result = sender_message_key_create(&message_key,
                        textsecure_SenderKeyStateStructure_SenderMessageKey_iteration(message_key_structure),
                        seed_buffer,
                        global_context);
                signal_buffer_free(seed_buffer);
                if(result < 0) {
                    goto complete;
                }

                result = sender_key_state_add_sender_message_key(result_state, message_key);
                if(result < 0) {
                    goto complete;
                }
                SIGNAL_UNREF(message_key);
            }
        }
    }
    else {
        result = SG_ERR_INVALID_PROTO_BUF;
    }

complete:
    if(chain_key) {
        SIGNAL_UNREF(chain_key);
    }
    if(signature_public_key) {
        SIGNAL_UNREF(signature_public_key);
    }
    if(signature_private_key) {
        SIGNAL_UNREF(signature_private_key);
    }
    if(result >= 0) {
        *state = result_state;
    }
    else {
        if(result_state) {
            SIGNAL_UNREF(result_state);
        }
    }
    return result;
}

int sender_key_state_copy(sender_key_state **state, sender_key_state *other_state, signal_context *global_context)
{
    int result = 0;
    signal_buffer *buffer = 0;
    uint8_t *data;
    size_t len;

    assert(other_state);
    assert(global_context);

    result = sender_key_state_serialize(&buffer, other_state);
    if(result < 0) {
        goto complete;
    }

    data = signal_buffer_data(buffer);
    len = signal_buffer_len(buffer);

    result = sender_key_state_deserialize(state, data, len, global_context);
    if(result < 0) {
        goto complete;
    }

complete:
    if(buffer) {
        signal_buffer_free(buffer);
    }
    return result;
}

uint32_t sender_key_state_get_key_id(sender_key_state *state)
{
    assert(state);
    return state->key_id;
}

sender_chain_key *sender_key_state_get_chain_key(sender_key_state *state)
{
    assert(state);
    return state->chain_key;
}

void sender_key_state_set_chain_key(sender_key_state *state, sender_chain_key *chain_key)
{
    assert(state);
    assert(chain_key);

    if(state->chain_key) {
        SIGNAL_UNREF(state->chain_key);
    }
    SIGNAL_REF(chain_key);
    state->chain_key = chain_key;
}

ec_public_key *sender_key_state_get_signing_key_public(sender_key_state *state)
{
    assert(state);
    return state->signature_public_key;
}

ec_private_key *sender_key_state_get_signing_key_private(sender_key_state *state)
{
    assert(state);
    return state->signature_private_key;
}

int sender_key_state_has_sender_message_key(sender_key_state *state, uint32_t iteration)
{
    sender_message_key_node *cur_node = 0;
    assert(state);

    DL_FOREACH(state->message_keys_head, cur_node) {
        if(sender_message_key_get_iteration(cur_node->key) == iteration) {
            return 1;
        }
    }

    return 0;
}

int sender_key_state_add_sender_message_key(sender_key_state *state, sender_message_key *message_key)
{
    int result = 0;
    sender_message_key_node *node = 0;
    int count;
    assert(state);
    assert(message_key);

    node = malloc(sizeof(sender_message_key_node));
    if(!node) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    SIGNAL_REF(message_key);
    node->key = message_key;
    DL_APPEND(state->message_keys_head, node);

    DL_COUNT(state->message_keys_head, node, count);
    while(count > MAX_MESSAGE_KEYS) {
        node = state->message_keys_head;
        DL_DELETE(state->message_keys_head, node);
        if(node->key) {
            SIGNAL_UNREF(node->key);
        }
        free(node);
        --count;
    }

complete:
    return result;
}

sender_message_key *sender_key_state_remove_sender_message_key(sender_key_state *state, uint32_t iteration)
{
    sender_message_key *result = 0;
    sender_message_key_node *cur_node = 0;
    sender_message_key_node *tmp_node = 0;
    assert(state);

    DL_FOREACH_SAFE(state->message_keys_head, cur_node, tmp_node) {
        if(sender_message_key_get_iteration(cur_node->key) == iteration) {
            DL_DELETE(state->message_keys_head, cur_node);
            result = cur_node->key;
            free(cur_node);
            break;
        }
    }

    return result;
}

void sender_key_state_destroy(signal_type_base *type)
{
    sender_key_state *state = (sender_key_state *)type;
    sender_message_key_node *cur_node;
    sender_message_key_node *tmp_node;

    SIGNAL_UNREF(state->chain_key);
    SIGNAL_UNREF(state->signature_public_key);
    SIGNAL_UNREF(state->signature_private_key);

    DL_FOREACH_SAFE(state->message_keys_head, cur_node, tmp_node) {
        DL_DELETE(state->message_keys_head, cur_node);
        if(cur_node->key) {
            SIGNAL_UNREF(cur_node->key);
        }
        free(cur_node);
    }
    state->message_keys_head = 0;

    free(state);
}
