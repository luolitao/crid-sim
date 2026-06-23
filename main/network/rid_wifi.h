#ifndef rid_WIFI_H
#define rid_WIFI_H

#include "rid_config.h"
#include "esp_err.h"
#include <stdint.h>

/**
 * @brief 初始化 Wi-Fi 用于 raw 802.11 帧发送
 * @param channel Wi-Fi 信道
 * @return ESP_OK 成功
 */
esp_err_t rid_wifi_init(uint8_t channel, const char *ssid);


/**
 * @brief 设置 Vendor IE 的 Payload (RID 数据 + Counter)
 * @param payload 指向 RID 编码后的数据（不含 OUI 和 Type）
 * @param payload_len 数据长度（不含 Counter）
 * @param counter 消息计数器（1 字节）
 */
esp_err_t rid_wifi_set_rid_data(const uint8_t *payload, size_t payload_len, uint8_t counter);

#endif // rid_WIFI_H
