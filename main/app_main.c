#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "nvs_flash.h"
#include "esp_log.h"
#include "esp_mac.h"          // 新增，提供 esp_base_mac_addr_set

#include "rid_config.h"
#include "rid_wifi.h"
#include "rid_web_ota.h"
#include "rid_ota.h"
#include "rid_manager.h"

static const char *TAG = "RID_MAIN";

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

void app_main(void) {
    ESP_LOGI(TAG, "=== ESP32 Multi-Standard Remote ID Simulator ===");

    esp_err_t ret = rid_nvs_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "NVS Init Failed: %s", esp_err_to_name(ret));
        return;
    }

    // 预打开实例 NVS 命名空间（确保可用）
    nvs_handle_t handle;
    ret = nvs_open("rid_inst", NVS_READWRITE, &handle);
    if (ret == ESP_OK) {
        nvs_close(handle);
        ESP_LOGI(TAG, "NVS namespace rid_inst ready");
    } else {
        ESP_LOGW(TAG, "nvs_open rid_inst: %s, will retry later", esp_err_to_name(ret));
    }

    ret = rid_nvs_load_config(&g_rid_config);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "Failed to load config, using defaults");
    }

    rid_manager_init();

    ret = rid_manager_load_all();
    if (ret != ESP_OK) {
        // 没有存储的实例，创建默认
        ESP_LOGW(TAG, "No instances stored, creating default");
        rid_config_t default_config;
        rid_config_init_default(&default_config);
        default_config.latitude = (float)g_rid_config.init_lat;
        default_config.longitude = (float)g_rid_config.init_lon;
        default_config.speed_horizontal = g_rid_config.speed;
        default_config.patrol_speed = g_rid_config.speed;

        uint32_t id;
        ret = rid_manager_create(RID_STANDARD_GB42590, &default_config, &id);
        if (ret == ESP_OK) {
            rid_manager_start(id);
            ret = rid_manager_save_all();
            if (ret != ESP_OK) {
                ESP_LOGE(TAG, "Save failed: %s", esp_err_to_name(ret));
            } else {
                ESP_LOGI(TAG, "Default instance saved");
            }
        } else {
            ESP_LOGE(TAG, "Create instance failed: %s", esp_err_to_name(ret));
        }
    } else {
        ESP_LOGI(TAG, "Instances loaded successfully");
        // 查找第一个 active 实例并启动（实际上启动函数会停止其他）
        drone_instance_t *inst = rid_manager_get_first();
        while (inst) {
            if (inst->active) {
                rid_manager_start(inst->id);
                break;
            }
            inst = inst->next;
        }
        if (!inst) {
            // 如果没有 active 实例，启动第一个
            inst = rid_manager_get_first();
            if (inst) {
                rid_manager_start(inst->id);
            }
        }
    }

    // 初始化网络和 Wi-Fi
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    ret = rid_wifi_init(g_rid_config.channel, "ESP32-RID-Simulator");
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Wi-Fi init failed: %s", esp_err_to_name(ret));
        return;
    }

    rid_web_ota_init();
    rid_ota_auto_confirm();
    rid_manager_start_dispatcher();

    ESP_LOGI(TAG, "System ready. Web: http://192.168.4.1/");
}