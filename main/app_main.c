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

void app_main(void) {
    ESP_LOGI(TAG, "=== ESP32 Multi-Standard Remote ID Simulator ===");

    // 1. 设置自定义 MAC（如果 EFUSE 损坏）
    uint8_t custom_mac[6] = {0x24, 0x0A, 0xC4, 0x12, 0x34, 0x56};
    esp_base_mac_addr_set(custom_mac);
    ESP_LOGI(TAG, "Custom MAC set to: %02X:%02X:%02X:%02X:%02X:%02X",
             custom_mac[0], custom_mac[1], custom_mac[2],
             custom_mac[3], custom_mac[4], custom_mac[5]);

    // 2. 初始化 NVS
    esp_err_t ret = rid_nvs_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "NVS Init Failed: %s", esp_err_to_name(ret));
        return;
    }

    // 2.1 预先创建实例 NVS 命名空间（确保可用）
    nvs_handle_t handle;
    ret = nvs_open("rid_inst", NVS_READWRITE, &handle);
    if (ret == ESP_OK) {
        nvs_close(handle);
        ESP_LOGI(TAG, "NVS namespace rid_inst ready");
    } else {
        ESP_LOGW(TAG, "nvs_open rid_inst: %s, will retry later", esp_err_to_name(ret));
    }

    // 3. 加载动态配置
    ret = rid_nvs_load_config(&g_rid_config);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "Failed to load config, using defaults");
    }

    // 4. 初始化实例管理器
    rid_manager_init();

    // 5. 尝试加载实例
    ret = rid_manager_load_all();
    if (ret == ESP_ERR_NOT_FOUND || ret != ESP_OK) {
        ESP_LOGW(TAG, "No instances stored, creating default");

        rid_config_t default_config;
        rid_config_init_default(&default_config);
        default_config.latitude = (float)g_rid_config.init_lat;
        default_config.longitude = (float)g_rid_config.init_lon;
        default_config.speed_horizontal = g_rid_config.speed;
        default_config.patrol_speed = g_rid_config.speed;

        uint32_t id;
        rid_manager_create(RID_STANDARD_GB42590, &default_config, &id);
        rid_manager_start(id);
        ret = rid_manager_save_all();
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to save initial instance: %s", esp_err_to_name(ret));
        } else {
            ESP_LOGI(TAG, "Initial instance created and saved");
        }
    } else if (ret == ESP_OK) {
        ESP_LOGI(TAG, "Instances loaded successfully");
        // 启动 active 实例
        drone_instance_t *inst = rid_manager_get_first();
        while (inst) {
            if (inst->active) {
                rid_manager_start(inst->id);  // 内部会设置 s_current_instance
                break;
            }
            inst = inst->next;
        }
        if (!inst) {
            // 没有 active 实例，默认启动第一个
            inst = rid_manager_get_first();
            if (inst) {
                rid_manager_start(inst->id);
            }
        }
    } else {
        ESP_LOGE(TAG, "rid_manager_load_all returned error: %s", esp_err_to_name(ret));
    }

    // 6. 初始化网络和 Wi-Fi
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    ret = rid_wifi_init(g_rid_config.channel, "ESP32-RID-Simulator");
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Wi-Fi init failed: %s", esp_err_to_name(ret));
        return;
    }

    // 7. 启动 Web OTA 和调度器
    rid_web_ota_init();
    rid_ota_auto_confirm();
    rid_manager_start_dispatcher();

    ESP_LOGI(TAG, "System ready. Web: http://192.168.4.1/");
}