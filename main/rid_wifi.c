#include "sdkconfig.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_mac.h"          // 新增，用于 esp_base_mac_addr_set
#include "esp_log.h"
#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "rid_wifi.h"

static const char *TAG = "RID_WIFI";
static bool s_wifi_driver_inited = false;

#define RID_OUI_0  0xFA
#define RID_OUI_1  0x0B
#define RID_OUI_2  0xBC
#define RID_OUI_TYPE 0x0D
#define AP_DEFAULT_PASSWORD "12345678"

esp_err_t rid_wifi_init(uint8_t channel, const char *ssid) {
    // ... 已有代码（esp_netif_init, esp_event_loop_create_default）...
    // 注意：这些在 wifi_tx.cpp 的 init() 中也被调用
    // 生成或使用自定义 MAC
    uint8_t mac[6] = {0x24, 0x0A, 0xC4, 0x12, 0x34, 0x56};
    // 注意：wifi_tx.cpp 使用随机 MAC，但为了固定，我们使用自定义

    // 初始化 Wi-Fi 驱动（与 wifi_tx.cpp 相同）
    if (!s_wifi_driver_inited) {
        wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
        esp_err_t ret = esp_wifi_init(&cfg);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "esp_wifi_init failed: %s", esp_err_to_name(ret));
            return ret;
        }
        s_wifi_driver_inited = true;
    }

    // 设置 AP 接口的 MAC（在 esp_wifi_init 之后，esp_wifi_start 之前）
    esp_err_t mac_ret = esp_wifi_set_mac(WIFI_IF_AP, mac);
    if (mac_ret != ESP_OK) {
        ESP_LOGW(TAG, "esp_wifi_set_mac failed: %s", esp_err_to_name(mac_ret));
    } else {
        ESP_LOGI(TAG, "AP MAC set to: %02X:%02X:%02X:%02X:%02X:%02X",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }

    // 配置 AP（与 wifi_tx.cpp 类似）
    wifi_config_t wifi_config = {};
    strncpy((char*)wifi_config.ap.ssid, ssid, sizeof(wifi_config.ap.ssid) - 1);
    wifi_config.ap.ssid_len = strlen(ssid);
    strncpy((char*)wifi_config.ap.password, AP_DEFAULT_PASSWORD, sizeof(wifi_config.ap.password) - 1);
    wifi_config.ap.authmode = WIFI_AUTH_WPA2_PSK;
    wifi_config.ap.channel = channel;
    wifi_config.ap.max_connection = 4;
    wifi_config.ap.ssid_hidden = 0;

    esp_wifi_set_mode(WIFI_MODE_AP);
    esp_wifi_set_config(WIFI_IF_AP, &wifi_config);

    // 启动 Wi-Fi
    esp_wifi_start();

    ESP_LOGI(TAG, "Wi-Fi initialized: AP mode, channel=%d, SSID=%s", channel, ssid);
    return ESP_OK;
}


esp_err_t rid_wifi_set_rid_data(const uint8_t *payload, size_t payload_len, uint8_t counter) {
    if (!payload || payload_len == 0) return ESP_ERR_INVALID_ARG;

    // 清除旧 IE
    esp_wifi_set_vendor_ie(false, WIFI_VND_IE_TYPE_BEACON, WIFI_VND_IE_ID_0, NULL);
    esp_wifi_set_vendor_ie(false, WIFI_VND_IE_TYPE_PROBE_RESP, WIFI_VND_IE_ID_0, NULL);

    // 使用静态缓冲区
    static uint8_t ie_buffer[256];
    size_t total_len = 2 + 3 + 1 + 1 + payload_len; // id + len + OUI + type + counter + data
    if (total_len > sizeof(ie_buffer)) {
        ESP_LOGE(TAG, "IE buffer too small");
        return ESP_ERR_INVALID_SIZE;
    }

    uint8_t *ptr = ie_buffer;
    *ptr++ = WIFI_VENDOR_IE_ELEMENT_ID;
    *ptr++ = (uint8_t)(3 + 1 + 1 + payload_len);
    *ptr++ = RID_OUI_0;
    *ptr++ = RID_OUI_1;
    *ptr++ = RID_OUI_2;
    *ptr++ = RID_OUI_TYPE;
    *ptr++ = counter;
    memcpy(ptr, payload, payload_len);

    esp_err_t ret = esp_wifi_set_vendor_ie(true, WIFI_VND_IE_TYPE_BEACON, WIFI_VND_IE_ID_0, (vendor_ie_data_t *)ie_buffer);
    if (ret == ESP_OK) {
        ESP_LOGD(TAG, "esp_wifi_set_vendor_ie WIFI_VND_IE_TYPE_BEACON OK!");
        // ESP_LOG_BUFFER_HEX(TAG, ie_buffer, payload_len > 64 ? 64 : payload_len);
        ret = esp_wifi_set_vendor_ie(true, WIFI_VND_IE_TYPE_PROBE_RESP, WIFI_VND_IE_ID_0, (vendor_ie_data_t *)ie_buffer);
        if (ret == ESP_OK) ESP_LOGD(TAG, "WIFI_VND_IE_TYPE_PROBE_RESP OK!");
    }
    return ret;
}