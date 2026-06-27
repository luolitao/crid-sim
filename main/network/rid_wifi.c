#include "sdkconfig.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_mac.h"
#include "esp_log.h"
#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/ip4_addr.h"      // 新增，提供 IP4_ADDR 宏

#include "rid_wifi.h"

#define RID_OUI_0  0xFA
#define RID_OUI_1  0x0B
#define RID_OUI_2  0xBC
#define RID_OUI_TYPE 0x0D
#define AP_DEFAULT_PASSWORD "12345678"

static const char *TAG = "RID_WIFI";
static bool s_wifi_driver_inited = false;

// 设置 MAC 地址（自动适配）
static void init_mac_address(void) {
    uint8_t mac[6];
    esp_err_t ret = esp_efuse_mac_get_default(mac);
    if (ret == ESP_OK) {
        // EFUSE MAC 有效，使用板载 MAC
        esp_base_mac_addr_set(mac);
        ESP_LOGI(TAG, "Using onboard MAC: %02X:%02X:%02X:%02X:%02X:%02X",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    } else {
        // EFUSE MAC 无效（CRC 错误），使用自定义 MAC
        uint8_t custom_mac[6] = {0x24, 0x0A, 0xC4, 0x00, 0x00, 0x01};
        esp_base_mac_addr_set(custom_mac);
        ESP_LOGW(TAG, "EFUSE MAC CRC error, using custom MAC: %02X:%02X:%02X:%02X:%02X:%02X",
                 custom_mac[0], custom_mac[1], custom_mac[2],
                 custom_mac[3], custom_mac[4], custom_mac[5]);
    }
}

esp_err_t rid_wifi_init(uint8_t channel, const char *ssid) {
    init_mac_address();

    if (!s_wifi_driver_inited) {
        wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
        esp_err_t ret = esp_wifi_init(&cfg);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "esp_wifi_init failed: %s", esp_err_to_name(ret));
            return ret;
        }
        s_wifi_driver_inited = true;
    }

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

    esp_netif_t *ap_netif = esp_netif_create_default_wifi_ap();
    esp_netif_ip_info_t ip_info;
    IP4_ADDR(&ip_info.ip, 192, 168, 4, 1);
    IP4_ADDR(&ip_info.gw, 192, 168, 4, 1);
    IP4_ADDR(&ip_info.netmask, 255, 255, 255, 0);
    esp_netif_dhcps_stop(ap_netif);
    esp_netif_set_ip_info(ap_netif, &ip_info);
    esp_netif_dhcps_start(ap_netif);

    esp_wifi_start();

    ESP_LOGI(TAG, "Wi-Fi initialized: AP mode, channel=%d, SSID=%s", channel, ssid);
    return ESP_OK;
}


esp_err_t rid_wifi_set_rid_data(const uint8_t *payload, size_t payload_len, uint8_t counter) {
    if (!payload || payload_len == 0) return ESP_ERR_INVALID_ARG;
    
    static uint8_t ie_buffer[256];
    size_t total_len = 2 + 3 + 1 + 1 + payload_len;
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
        

    // 每16帧打印一次前64字节（调试）
    if (counter % 0x10 == 0){
        // 在 rid_wifi_set_rid_data 中，设置完 Vendor IE 后
        ESP_LOGI(TAG, "Vendor IE Message Counter: %d, total_len: (%d bytes):", counter, total_len);
        ESP_LOG_BUFFER_HEX(TAG, ie_buffer, 64);
    } 

    // 构造 Vendor IE 并设置
    // so first remove old element, add new afterwards
    esp_err_t ret = esp_wifi_set_vendor_ie(false, WIFI_VND_IE_TYPE_BEACON, WIFI_VND_IE_ID_0, ie_buffer);
    if (ret != ESP_OK) return ret;
    ret = esp_wifi_set_vendor_ie(true, WIFI_VND_IE_TYPE_BEACON, WIFI_VND_IE_ID_0, ie_buffer);
    if (ret != ESP_OK) return ret;    

    //set the payload also to probe requests, to increase update rate on mobile phones
    // so first remove old element, add new afterwards
    // ret = esp_wifi_set_vendor_ie(false, WIFI_VND_IE_TYPE_PROBE_RESP, WIFI_VND_IE_ID_0, ie_buffer);
    // if (ret != ESP_OK) return ret;
    // ret = esp_wifi_set_vendor_ie(true, WIFI_VND_IE_TYPE_PROBE_RESP, WIFI_VND_IE_ID_0, ie_buffer);
    // if (ret != ESP_OK) return ret;

    return ESP_OK;
}