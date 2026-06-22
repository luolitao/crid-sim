#ifndef RID_BEACON_H
#define RID_BEACON_H

#include "rid_config.h"
#include "rid_messages.h"
#include "rid_standard.h"
#include <stdint.h>
#include <stdbool.h>


// 原有函数声明
bool rid_build_beacon_frame(const rid_config_t *config,
                            uint8_t message_counter,
                            const rid_standard_meta_t *meta,
                            uint8_t *frame, uint16_t max_len,
                            uint16_t *out_len) ;

/**
 * @brief 启动 RID Beacon 发送任务（1Hz 循环）
 * @param config 指向完整的配置结构体（必须保持有效，通常为静态全局变量）
 */
void rid_beacon_start(rid_config_t *config);


#endif // RID_BEACON_H