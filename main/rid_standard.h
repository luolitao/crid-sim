// rid_standard.h
#ifndef RID_STANDARD_H
#define RID_STANDARD_H

#include "rid_config.h"
#include <stdint.h>
#include <stdbool.h>


// ==================== 标准类型枚举 ====================
typedef enum {
    RID_STANDARD_GB42590 = 0,
    RID_STANDARD_GB46750 = 1,
    RID_STANDARD_ASTM    = 2
} rid_standard_t;

// ==================== 打包格式类型 ====================
typedef enum {
    PACK_FORMAT_ASTM,      // 2字节头部: [0xF1][MsgCount]
    PACK_FORMAT_GB42590,   // 3字节头部: [0xF1][25][MsgCount]
    PACK_FORMAT_GB46750    // 独立编码, 不使用打包格式
} pack_format_t;

// ==================== 消息构建器函数指针 ====================
typedef void (*msg_builder_t)(const rid_config_t*, uint8_t*);

// ==================== 标准元数据 ====================
typedef struct {
    rid_standard_t standard;
    pack_format_t pack_format;
    uint8_t msg_count;                  // ASTM/GB42590 使用
    const msg_builder_t *builders;      // ASTM/GB42590 使用
    bool use_gb46750_encoder;           // GB46750 专用标志
} rid_standard_meta_t;

// ==================== 全局标准元数据表 ====================
extern const rid_standard_meta_t g_standard_meta[];

// ==================== 辅助函数 ====================
const rid_standard_meta_t* rid_get_standard_meta(rid_standard_t std);

#endif // RID_STANDARD_H