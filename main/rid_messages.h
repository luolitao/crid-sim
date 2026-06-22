#ifndef RID_MESSAGES_H
#define RID_MESSAGES_H

#include "rid_config.h"
#include "rid_standard.h"      // 添加这行，获取 pack_format_t 等定义
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RID_SINGLE_MSG_SIZE     25
#define RID_MAX_PACK_MESSAGES   9
#define RID_PROTOCOL_VERSION    1

// 消息类型
enum {
    RID_MSG_BASIC_ID = 0x0,
    RID_MSG_LOCATION = 0x1,
    RID_MSG_AUTH = 0x2,
    RID_MSG_SELF_ID = 0x3,
    RID_MSG_SYSTEM = 0x4,
    RID_MSG_OPERATOR_ID = 0x5,
    RID_MSG_PACK = 0xF
};

// 精度等级（与 ASTM 一致）
enum RIDAccuracy {
    RID_ACC_UNKNOWN = 0,
    RID_ACC_10NM = 1,
    RID_ACC_4NM = 2,
    RID_ACC_2NM = 3,
    RID_ACC_1NM = 4,
    RID_ACC_0_5NM = 5,
    RID_ACC_0_3M = 6,      // 0.3 m/s 速度精度
    RID_ACC_0_1NM = 7,
    RID_ACC_0_05NM = 8,
    RID_ACC_30M = 9,
    RID_ACC_10M = 10,
    RID_ACC_3M = 11,
    RID_ACC_1M = 12
};

// 时间戳精度（ASTM 定义）
enum RIDTSAccuracy {
    RID_ACC_TS_UNKNOWN = 0,
    RID_ACC_TS_0_5S = 1,
    RID_ACC_TS_0_4S = 2,
    RID_ACC_TS_0_3S = 3,
    RID_ACC_TS_0_2S = 4,   // 我们需要的
    RID_ACC_TS_0_1S = 5,
    RID_ACC_TS_0_05S = 6,
    RID_ACC_TS_0_02S = 7,
    RID_ACC_TS_0_01S = 8
};

// 描述类型（Self-ID 使用）
#define DESC_TYPE_TEXT  0
#define DESC_TYPE_EMERGENCY 1
#define DESC_TYPE_EXTENDED_STATUS 2

// 消息构建函数类型（已在 rid_standard.h 中定义，但为了防止循环依赖，在此也声明）
// 由于已经包含 rid_standard.h，可以使用 msg_builder_t 类型
// 但为了避免重复定义，我们直接使用 rid_standard.h 中的类型

// 编码单条消息（这些函数在 rid_messages.c 中实现）
void rid_encode_basic_id(const rid_config_t *config, uint8_t *out);
void rid_encode_location(const rid_config_t *config, uint8_t *out);
void rid_encode_system(const rid_config_t *config, uint8_t *out);
void rid_encode_self_id(const rid_config_t *config, uint8_t *out);
void rid_encode_operator_id(const rid_config_t *config, uint8_t *out);
void rid_encode_auth(const rid_config_t *config, uint8_t *out);

// 打包函数（支持不同头部格式）
int rid_pack_messages(uint8_t *out, pack_format_t format,
                      const msg_builder_t builders[], uint8_t count,
                      const rid_config_t *config);

// GB46750 专用函数
int rid_build_gb46750_payload(const rid_config_t *config, uint8_t *out, size_t max_len);

#ifdef __cplusplus
}
#endif

#endif // RID_MESSAGES_H