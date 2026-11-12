#include "sender_key_record.h"

#include <string.h>

#include "sender_key_state.h"
#include "sender_key.h"
#include "utlist.h"
#include "signal_protocol_internal.h"

#define MAX_STATES 5

typedef struct sender_key_state_node {
    sender_key_state *state;
    struct sender_key_state_node *prev, *next;
} sender_key_state_node;

struct sender_key_record
{
    signal_type_base base;
    sender_key_state_node *sender_key_states_head;
    signal_buffer *user_record;
    signal_context *global_context;
};

int sender_key_record_create(sender_key_record **record,
        signal_context *global_context)
{
    sender_key_record *result = malloc(sizeof(sender_key_record));
    if(!result) {
        return SG_ERR_NOMEM;
    }
    memset(result, 0, sizeof(sender_key_record));
    SIGNAL_INIT(result, sender_key_record_destroy);

    result->global_context = global_context;

    *record = result;
    return 0;
}

int sender_key_record_serialize(signal_buffer **buffer, sender_key_record *record)
{
    int result = 0;
    upb_Arena *arena = 0;
    textsecure_SenderKeyRecordStructure *record_structure = 0;
    sender_key_state_node *cur_node = 0;
    signal_buffer *result_buf = 0;

    arena = upb_Arena_New();
    record_structure = arena ? textsecure_SenderKeyRecordStructure_new(arena) : 0;
    if(!record_structure) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    DL_FOREACH(record->sender_key_states_head, cur_node) {
        textsecure_SenderKeyStateStructure *state_structure =
                textsecure_SenderKeyRecordStructure_add_senderKeyStates(record_structure, arena);
        if(!state_structure) {
            result = SG_ERR_NOMEM;
            goto complete;
        }

        result = sender_key_state_serialize_prepare(cur_node->state, state_structure, arena);
        if(result < 0) {
            goto complete;
        }
    }

    result = signal_buffer_from_protobuf(&result_buf, record_structure,
            &textsecure__SenderKeyRecordStructure_msg_init, arena, 0, 0);

complete:
    if(arena) {
        upb_Arena_Free(arena);
    }

    if(result >= 0) {
        *buffer = result_buf;
    }
    return result;
}

int sender_key_record_deserialize(sender_key_record **record, const uint8_t *data, size_t len, signal_context *global_context)
{
    int result = 0;
    sender_key_record *result_record = 0;
    upb_Arena *arena = 0;
    textsecure_SenderKeyRecordStructure *record_structure = 0;
    const textsecure_SenderKeyStateStructure *const *states = 0;
    size_t state_count = 0;

    arena = upb_Arena_New();
    if(!arena) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    record_structure = textsecure_SenderKeyRecordStructure_parse((const char *)data, len, arena);
    if(!record_structure) {
        result = SG_ERR_INVALID_PROTO_BUF;
        goto complete;
    }

    result = sender_key_record_create(&result_record, global_context);
    if(result < 0) {
        goto complete;
    }

    states = textsecure_SenderKeyRecordStructure_senderKeyStates(record_structure, &state_count);
    if(state_count > 0) {
        size_t i;
        sender_key_state_node *state_node = 0;
        sender_key_state *state_element = 0;
        for(i = 0; i < state_count; i++) {
            result = sender_key_state_deserialize_protobuf(&state_element, states[i], global_context);
            if(result < 0) {
                goto complete;
            }

            state_node = malloc(sizeof(sender_key_state_node));
            if(!state_node) {
                result = SG_ERR_NOMEM;
                goto complete;
            }

            state_node->state = state_element;
            DL_APPEND(result_record->sender_key_states_head, state_node);
        }
    }

complete:
    if(arena) {
        upb_Arena_Free(arena);
    }
    if(result_record) {
        if(result < 0) {
            SIGNAL_UNREF(result_record);
        }
        else {
            *record = result_record;
        }
    }
    return result;
}

int sender_key_record_copy(sender_key_record **record, sender_key_record *other_record, signal_context *global_context)
{
    int result = 0;
    sender_key_record *result_record = 0;
    signal_buffer *buffer = 0;
    uint8_t *data;
    size_t len;

    assert(other_record);
    assert(global_context);

    result = sender_key_record_serialize(&buffer, other_record);
    if(result < 0) {
        goto complete;
    }

    data = signal_buffer_data(buffer);
    len = signal_buffer_len(buffer);

    result = sender_key_record_deserialize(&result_record, data, len, global_context);
    if(result < 0) {
        goto complete;
    }
    if(other_record->user_record) {
        result_record->user_record = signal_buffer_copy(other_record->user_record);
        if(!result_record->user_record) {
            result = SG_ERR_NOMEM;
            goto complete;
        }
    }

complete:
    if(buffer) {
        signal_buffer_free(buffer);
    }
    if(result >= 0) {
        *record = result_record;
    }
    else {
        SIGNAL_UNREF(result_record);
    }
    return result;
}

int sender_key_record_is_empty(sender_key_record *record)
{
    assert(record);
    if(record->sender_key_states_head) {
        return 0;
    }
    else {
        return 1;
    }
}

int sender_key_record_get_sender_key_state(sender_key_record *record, sender_key_state **state)
{
    assert(record);
    if(record->sender_key_states_head) {
        *state = record->sender_key_states_head->state;
        return 0;
    }
    else {
        signal_log(record->global_context, SG_LOG_ERROR, "No key state in record!");
        return SG_ERR_INVALID_KEY_ID;
    }
}

int sender_key_record_get_sender_key_state_by_id(sender_key_record *record, sender_key_state **state, uint32_t key_id)
{
    sender_key_state_node *cur_node;
    assert(record);

    DL_FOREACH(record->sender_key_states_head, cur_node) {
        if(sender_key_state_get_key_id(cur_node->state) == key_id) {
            *state = cur_node->state;
            return 0;
        }
    }

    signal_log(record->global_context, SG_LOG_ERROR, "No keys for: %d", key_id);
    return SG_ERR_INVALID_KEY_ID;
}

static int sender_key_record_add_sender_key_state_impl(sender_key_record *record,
        uint32_t id, uint32_t iteration, signal_buffer *chain_key,
        ec_public_key *signature_public_key, ec_private_key *signature_private_key)
{
    int result = 0;
    sender_chain_key *chain_key_element = 0;
    sender_key_state *state = 0;
    sender_key_state_node *state_node = 0;
    int count;
    assert(record);

    result = sender_chain_key_create(&chain_key_element, iteration, chain_key, record->global_context);
    if(result < 0) {
        goto complete;
    }

    result = sender_key_state_create(&state, id, chain_key_element,
            signature_public_key, signature_private_key,
            record->global_context);
    if(result < 0) {
        goto complete;
    }

    state_node = malloc(sizeof(sender_key_state_node));
    if(!state_node) {
        result = SG_ERR_NOMEM;
        goto complete;
    }

    state_node->state = state;
    DL_PREPEND(record->sender_key_states_head, state_node);

    DL_COUNT(record->sender_key_states_head, state_node, count);
    while(count > MAX_STATES) {
        state_node = record->sender_key_states_head->prev;
        DL_DELETE(record->sender_key_states_head, state_node);
        if(state_node->state) {
            SIGNAL_UNREF(state_node->state);
        }
        free(state_node);
        --count;
    }

complete:
    SIGNAL_UNREF(chain_key_element);
    if(result < 0) {
        SIGNAL_UNREF(state);
    }
    return result;
}

int sender_key_record_add_sender_key_state(sender_key_record *record,
        uint32_t id, uint32_t iteration, signal_buffer *chain_key, ec_public_key *signature_key)
{
    int result = sender_key_record_add_sender_key_state_impl(
            record, id, iteration, chain_key, signature_key, 0);
    return result;
}

int sender_key_record_set_sender_key_state(sender_key_record *record,
        uint32_t id, uint32_t iteration, signal_buffer *chain_key, ec_key_pair *signature_key_pair)
{
    int result = 0;
    sender_key_state_node *cur_node;
    sender_key_state_node *tmp_node;
    assert(record);

    DL_FOREACH_SAFE(record->sender_key_states_head, cur_node, tmp_node) {
        DL_DELETE(record->sender_key_states_head, cur_node);
        if(cur_node->state) {
            SIGNAL_UNREF(cur_node->state);
        }
        free(cur_node);
    }
    record->sender_key_states_head = 0;

    result = sender_key_record_add_sender_key_state_impl(
            record, id, iteration, chain_key,
            ec_key_pair_get_public(signature_key_pair),
            ec_key_pair_get_private(signature_key_pair));
    return result;
}

signal_buffer *sender_key_record_get_user_record(const sender_key_record *record)
{
    assert(record);
    return record->user_record;
}

void sender_key_record_set_user_record(sender_key_record *record, signal_buffer *user_record)
{
    assert(record);
    if(record->user_record) {
        signal_buffer_free(record->user_record);
    }
    record->user_record = user_record;
}

void sender_key_record_destroy(signal_type_base *type)
{
    sender_key_record *record = (sender_key_record *)type;
    sender_key_state_node *cur_node;
    sender_key_state_node *tmp_node;

    DL_FOREACH_SAFE(record->sender_key_states_head, cur_node, tmp_node) {
        DL_DELETE(record->sender_key_states_head, cur_node);
        if(cur_node->state) {
            SIGNAL_UNREF(cur_node->state);
        }
        free(cur_node);
    }
    record->sender_key_states_head = 0;

    if(record->user_record) {
        signal_buffer_free(record->user_record);
    }

    free(record);
}
