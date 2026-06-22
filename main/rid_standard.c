#include "rid_standard.h"
#include "rid_messages.h"

// GB42590 构建器列表
static const msg_builder_t gb42590_builders[] = {
    rid_encode_basic_id,
    rid_encode_location,
    rid_encode_system
};

// ASTM 构建器列表
static const msg_builder_t astm_builders[] = {
    rid_encode_basic_id,
    rid_encode_location,
    rid_encode_system,
    rid_encode_self_id,
    rid_encode_operator_id
};

// GB46750 不使用构建器数组，msg_count = 0, builders = NULL
const rid_standard_meta_t g_standard_meta[] = {
    {
        .standard = RID_STANDARD_GB42590,
        .pack_format = PACK_FORMAT_GB42590,
        .msg_count = 3,
        .builders = gb42590_builders,
        .use_gb46750_encoder = false
    },
    {
        .standard = RID_STANDARD_GB46750,
        .pack_format = PACK_FORMAT_GB46750,
        .msg_count = 0,
        .builders = NULL,
        .use_gb46750_encoder = true
    },
    {
        .standard = RID_STANDARD_ASTM,
        .pack_format = PACK_FORMAT_ASTM,
        .msg_count = 5,
        .builders = astm_builders,
        .use_gb46750_encoder = false
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