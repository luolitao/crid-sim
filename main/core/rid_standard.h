#ifndef RID_STANDARD_H
#define RID_STANDARD_H

#include "rid_config.h"
#include <stdint.h>
#include <stdbool.h>

// 标准类型枚举
typedef enum {
    RID_STANDARD_GB46750 = 0,
    RID_STANDARD_GB42590 = 1,
    RID_STANDARD_ASTM    = 2
} rid_standard_t;

// 消息构建器函数指针
typedef void (*msg_builder_t)(const rid_config_t*, uint8_t*);

// 标准元数据结构（所有打包标准共用 3 字节头部：Version + 0x19 + Count）
typedef struct {
    rid_standard_t standard;
    uint8_t protocol_version;          // 低 4 位，例如 1 -> 0xF1，2 -> 0xF2
    uint8_t msg_count;             // 消息数量（GB46750 为 0）
    const msg_builder_t *builders; // 构建器列表（GB46750 为 NULL）
} rid_standard_meta_t;

// 全局元数据表
extern const rid_standard_meta_t g_standard_meta[];

// 辅助函数
const rid_standard_meta_t* rid_get_standard_meta(rid_standard_t std);

#endif