#ifndef RID_MESSAGES_H
#define RID_MESSAGES_H

#include "rid_config.h"
#include "rid_standard.h"      // 提供 rid_standard_meta_t, msg_builder_t
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RID_SINGLE_MSG_SIZE     25
#define RID_MAX_PACK_MESSAGES   9

// 消息类型（ASTM/GB42590 定义）
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
    RID_ACC_TS_0_2S = 4,
    RID_ACC_TS_0_1S = 5,
    RID_ACC_TS_0_05S = 6,
    RID_ACC_TS_0_02S = 7,
    RID_ACC_TS_0_01S = 8
};

// 描述类型（Self-ID 使用）
#define DESC_TYPE_TEXT          0
#define DESC_TYPE_EMERGENCY     1
#define DESC_TYPE_EXTENDED_STATUS 2

// 单消息编码函数
void rid_encode_basic_id(const rid_config_t *config, uint8_t *out);
void rid_encode_location(const rid_config_t *config, uint8_t *out);
void rid_encode_system(const rid_config_t *config, uint8_t *out);
void rid_encode_self_id(const rid_config_t *config, uint8_t *out);
void rid_encode_operator_id(const rid_config_t *config, uint8_t *out);
void rid_encode_auth(const rid_config_t *config, uint8_t *out);

/**
 * @brief 根据标准元数据打包消息
 * @param out 输出缓冲区
 * @param meta 标准元数据（包含 protocol_version、msg_count、builders）
 * @param config 配置
 * @return 打包后的长度（>0 表示成功），-1 表示失败
 */
int rid_pack_messages(uint8_t *out, const rid_standard_meta_t *meta, const rid_config_t *config);

/**
 * @brief 构建 GB46750 数据包 (直接输出 Vendor Specific 载荷)
 * @param config 配置结构体
 * @param out 输出缓冲区
 * @param max_len 缓冲区最大长度
 * @return 实际长度, 失败返回 -1
 */
int rid_build_gb46750_payload(const rid_config_t *config, uint8_t *out, size_t max_len);

#ifdef __cplusplus
}
#endif

#endif // RID_MESSAGES_H