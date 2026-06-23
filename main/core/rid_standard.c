#include "rid_standard.h"
#include "rid_messages.h"

// GB42590 构建器
static const msg_builder_t gb42590_builders[] = {
    rid_encode_basic_id,
    rid_encode_location,
    rid_encode_system
};

// ASTM 构建器（含 Self-ID 和 Operator ID）
static const msg_builder_t astm_builders[] = {
    rid_encode_basic_id,
    rid_encode_location,
    rid_encode_system,
    rid_encode_self_id,
    rid_encode_operator_id
};

// GB46750 不使用构建器
const rid_standard_meta_t g_standard_meta[] = {
    {
        .standard = RID_STANDARD_GB42590,
        .pack_version = 1,          // 0xF1
        .msg_count = 3,
        .builders = gb42590_builders
    },
    {
        .standard = RID_STANDARD_GB46750,
        .pack_version = 0,          // 未使用
        .msg_count = 0,
        .builders = NULL
    },
    {
        .standard = RID_STANDARD_ASTM,
        .pack_version = 1,          // 0xF1（实际与 GB42590 相同）
        .msg_count = 5,
        .builders = astm_builders
    }
};

const rid_standard_meta_t* rid_get_standard_meta(rid_standard_t std) {
    for (size_t i = 0; i < sizeof(g_standard_meta) / sizeof(g_standard_meta[0]); i++) {
        if (g_standard_meta[i].standard == std) {
            return &g_standard_meta[i];
        }
    }
    return NULL;
}