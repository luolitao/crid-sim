#include "rid_config.h"
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include "esp_system.h"
#include "esp_mac.h"
#include "esp_log.h"
#include "esp_chip_info.h"
#include "esp_ota_ops.h"
#include "esp_timer.h"
#include "esp_sntp.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

static const char *TAG = "RID_CFG";

// 全局动态配置
rid_dynamic_config_t g_rid_config;
SemaphoreHandle_t g_rid_config_mutex = NULL;

// ==================== 系统与配置管理实现 ====================

void rid_get_sys_info(rid_sys_info_t *info) {
    if (!info) return;
    
    snprintf(info->chip_model, sizeof(info->chip_model), "%s", CONFIG_IDF_TARGET);
    snprintf(info->flash_size, sizeof(info->flash_size), "%s", CONFIG_ESPTOOLPY_FLASHSIZE);
    
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    snprintf(info->mac_addr, sizeof(info->mac_addr), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
             
    info->uptime_sec = (uint32_t)(esp_timer_get_time() / 1000000);
    
    time_t now;
    struct tm timeinfo;
    time(&now);
    localtime_r(&now, &timeinfo);
    if (timeinfo.tm_year < (2020 - 1900)) {
        snprintf(info->sys_time, sizeof(info->sys_time), "Not Synced (Offline)");
    } else {
        strftime(info->sys_time, sizeof(info->sys_time), "%Y-%m-%d %H:%M:%S", &timeinfo);
    }
    
    info->free_heap = esp_get_free_heap_size();
    
    const esp_partition_t *part = esp_ota_get_running_partition();
    snprintf(info->partition_name, sizeof(info->partition_name), "%.15s", part ? part->label : "Unknown");
}

void rid_get_config_snapshot(rid_dynamic_config_t *cfg) {
    if (!cfg) return;
    if (g_rid_config_mutex != NULL) {
        xSemaphoreTake(g_rid_config_mutex, portMAX_DELAY);
    }
    *cfg = g_rid_config;
    if (g_rid_config_mutex != NULL) {
        xSemaphoreGive(g_rid_config_mutex);
    }
}

static void time_sync_notification_cb(struct timeval *tv) {
    ESP_LOGI(TAG, "SNTP Time synchronized!");
}

void rid_time_sync_init(void) {
    ESP_LOGI(TAG, "Initializing SNTP");
    esp_sntp_setoperatingmode(ESP_SNTP_OPMODE_POLL);
    esp_sntp_setservername(0, "pool.ntp.org");
    sntp_set_time_sync_notification_cb(time_sync_notification_cb);
    esp_sntp_init();
}

// ==================== NVS 与配置逻辑 ====================

esp_err_t rid_nvs_init(void) {
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    if (ret == ESP_OK && g_rid_config_mutex == NULL) {
        g_rid_config_mutex = xSemaphoreCreateMutex();
        if (g_rid_config_mutex == NULL) {
            ESP_LOGE(TAG, "Failed to create config mutex");
            return ESP_FAIL;
        }
    }
    return ret;
}

esp_err_t rid_nvs_load_config(rid_dynamic_config_t *cfg) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open(rid_NVS_NAMESPACE, NVS_READONLY, &handle);
    if (err != ESP_OK) {
        cfg->init_lat = 23.14287;
        cfg->init_lon = 113.26026;
        cfg->speed = 0.2f;
        cfg->flight_mode = FLIGHT_MODE_CIRCLE;
        cfg->channel = DEFAULT_WIFI_CHANNEL;
        ESP_LOGW(TAG, "NVS space empty. Loaded default factory config.");
        return ESP_OK;
    }
    size_t size = sizeof(rid_dynamic_config_t);
    err = nvs_get_blob(handle, "config_blob", cfg, &size);
    nvs_close(handle);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "Config successfully loaded from NVS.");
    } else {
        cfg->init_lat = 23.14287;
        cfg->init_lon = 113.26026;
        cfg->speed = 0.2f;
        cfg->flight_mode = FLIGHT_MODE_CIRCLE;
        cfg->channel = DEFAULT_WIFI_CHANNEL;
        ESP_LOGW(TAG, "Config load failed, using defaults.");
    }
    return err;
}

esp_err_t rid_nvs_save_config(const rid_dynamic_config_t *cfg) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open(rid_NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) return err;
    err = nvs_set_blob(handle, "config_blob", cfg, sizeof(rid_dynamic_config_t));
    if (err == ESP_OK) {
        err = nvs_commit(handle);
        ESP_LOGI(TAG, "Config saved and committed to NVS.");
    }
    nvs_close(handle);
    return err;
}

// ==================== 实例配置初始化 ====================

void rid_config_init_default(rid_config_t *config) {
    if (config == NULL) return;
    memset(config, 0, sizeof(rid_config_t));
    
    // MAC 地址（使用默认）
    config->mac_address[0] = 0x24;
    config->mac_address[1] = 0x0A;
    config->mac_address[2] = 0xC4;
    config->mac_address[3] = 0x12;
    config->mac_address[4] = 0x34;
    config->mac_address[5] = 0x56;
    
    // UAS ID（带 MAC 后缀）
    char mac_suffix[5];
    snprintf(mac_suffix, sizeof(mac_suffix), "%02X%02X", config->mac_address[4], config->mac_address[5]);
    snprintf(config->uas_id, sizeof(config->uas_id), "ESP32-rid-%s", mac_suffix);
    
    // 通用字段默认值
    config->id_type = 1;           // Serial Number
    config->ua_type = 2;           // Helicopter
    config->latitude = 23.14287f;
    config->longitude = 113.26026f;
    config->altitude_msl = 50.0f;
    config->altitude_agl = 50.0f;
    config->speed_horizontal = 1.0f;
    config->speed_vertical = 0.0f;
    config->heading = 45.0f;
    config->status = 2;            // Airborne
    config->operator_lat = 23.143017f;
    config->operator_lon = 113.260734f;
    config->operator_alt = 10.0f;
    snprintf(config->operator_id, sizeof(config->operator_id), "OP-%s", mac_suffix);
    snprintf(config->drone_name, sizeof(config->drone_name), "ESP32-DRONE");
    config->operator_location_type = 1;  // Dynamic (GNSS)
    config->category_eu = 1;       // Open category
    config->class_eu = 0;          // Undefined class
    config->height_type = 0;       // Over takeoff
    snprintf(config->ssid, sizeof(config->ssid), "ESP32-RID-%s", mac_suffix);
    config->channel = DEFAULT_WIFI_CHANNEL;
    config->message_counter = 0;
    config->base_latitude = config->latitude;
    config->base_longitude = config->longitude;
    config->base_altitude_msl = config->altitude_msl;
    config->patrol_radius_lat = 0.00005f;
    config->patrol_radius_lon = 0.00004f;
    config->patrol_speed = 0.2f;
    config->time_counter = 0.0f;
    config->flight_mode = FLIGHT_MODE_CIRCLE;

    // GB46750 特有字段默认值
    config->reg_mark[0] = '\0';    // 空字符串
    config->op_category = 1;       // 开放类
    config->ua_class = 1;          // 轻型
    config->gcs_pos_type = 0;      // 起飞点
    config->coord_type = 0;        // WGS-84
    config->h_acc = 11;            // <3m
    config->v_acc = 5;             // <3m
    config->spd_acc = 4;           // <0.3m/s
    config->ts_acc = 4;            // ≤0.2s
}

void rid_config_update_position(rid_config_t *config, float lat, float lon,
                                float alt_msl, float alt_agl, float speed_h,
                                float speed_v, float heading) {
    if (config == NULL) return;
    static uint32_t s_update_count = 0;
    s_update_count++;
    
    config->latitude = lat;
    config->longitude = lon;
    config->altitude_msl = alt_msl;
    config->altitude_agl = alt_agl;
    config->speed_horizontal = speed_h;
    config->speed_vertical = speed_v;
    config->heading = heading;
    
    if ((s_update_count % 10U) == 1U) {
        ESP_LOGI(TAG, "Position updated: %.6f, %.6f, Alt: %.2fm, Hdg: %.1f",
                 config->latitude, config->longitude, config->altitude_msl, config->heading);
    }
}