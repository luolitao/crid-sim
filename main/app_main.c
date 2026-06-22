#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "nvs_flash.h"
#include "esp_log.h"
#include "rid_config.h"
#include "rid_wifi.h"
#include "rid_web_ota.h"
#include "rid_ota.h"
#include "rid_manager.h"

static const char *TAG = "RID_MAIN";

void app_main(void) {
    ESP_LOGI(TAG, "=== ESP32 Multi-Standard Remote ID Simulator ===");
    // 1. 初始化 NVS
    esp_err_t ret = rid_nvs_init();
    if (ret != ESP_OK) { ESP_LOGE(TAG, "NVS Init Failed"); return; }

    // 2. 加载动态配置（g_rid_config）-- 原有代码
    ESP_ERROR_CHECK(rid_nvs_load_config(&g_rid_config));

    // 3. 初始化实例管理器
    rid_manager_init();

    // 4. 尝试加载实例
    ret = rid_manager_load_all();
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "No instances stored, creating default");

        // 创建默认配置
        rid_config_t default_config;
        rid_config_init_default(&default_config);
        // 同步动态参数
        default_config.latitude = (float)g_rid_config.init_lat;
        default_config.longitude = (float)g_rid_config.init_lon;
        default_config.speed_horizontal = g_rid_config.speed;
        default_config.patrol_speed = g_rid_config.speed;

        uint32_t id;
        rid_manager_create(RID_STANDARD_GB42590, &default_config, &id);
        // 启动该实例
        rid_manager_start(id);
        // 保存到 NVS
        rid_manager_save_all();
    } else {
        // 加载后，启动所有 active 实例        
        drone_instance_t *inst = rid_manager_get_first();
        while (inst) {
            if (inst->active) {
                rid_manager_start(inst->id);
            }
            inst = inst->next; // 注意：需要遍历链表，需提供访问函数
        }
    }

    // 5. 初始化 Wi-Fi 等
    
    // 初始化网络
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    
    // 初始化 Wi-Fi
    ret = rid_wifi_init(g_rid_config.channel, "ESP32-RID-Simulator");
    if (ret != ESP_OK) return;    
    
    
    // 启动 Web OTA
    rid_web_ota_init();
    rid_ota_auto_confirm();
    
    // 启动调度器
    rid_manager_start_dispatcher();
    
    ESP_LOGI(TAG, "System ready. Web: http://192.168.4.1/");
}