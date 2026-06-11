#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/uart.h"
#include "esp_log.h"
#include "crid_config.h"
#include "crid_ota.h"

static const char *TAG = "CRID_CLI";
#define BUF_SIZE (256)

static void cli_task(void *pvParameters) {
    uint8_t *data = (uint8_t *) malloc(BUF_SIZE);
    if (data == NULL) {
        ESP_LOGE(TAG, "Failed to allocate CLI buffer");
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "CLI Engine started. Usage: SET <lat> <lon> <mode> | OTA <url>");
    ESP_LOGI(TAG, "Modes: 0=Circle, 1=PingPong, 2=S-Search. Example: SET 22.54 114.05 1");

    while (1) {
        // 从默认控制台 UART0 获取一行命令
        int len = uart_read_bytes(UART_NUM_0, data, BUF_SIZE - 1, pdMS_TO_TICKS(100));
        if (len > 0) {
            data[len] = '\0';
            // 去除换行符
            char *pos;
            if ((pos = strchr((char*)data, '\n')) != NULL) *pos = '\0';
            if ((pos = strchr((char*)data, '\r')) != NULL) *pos = '\0';

            char cmd[16];
            double t_lat = 0;
            double t_lon = 0;
            int t_mode = 0;
            char ota_url[192];

            // 解析指令 格式: SET 23.123 113.123 1
            if (sscanf((char*)data, "%15s %191s", cmd, ota_url) == 2 && strcmp(cmd, "OTA") == 0) {
                esp_err_t ota_ret = crid_ota_perform(ota_url);
                if (ota_ret != ESP_OK) {
                    printf("\r\n[OTA ERROR] Update failed: %s\n", esp_err_to_name(ota_ret));
                }
            } else if (sscanf((char*)data, "%15s %lf %lf %d", cmd, &t_lat, &t_lon, &t_mode) == 4) {
                if (strcmp(cmd, "SET") == 0 && t_mode >= 0 && t_mode < FLIGHT_MODE_MAX) {
                    // 动态更新内存全局变量
                    crid_dynamic_config_t config_snapshot;
                    if (g_crid_config_mutex != NULL) {
                        xSemaphoreTake(g_crid_config_mutex, portMAX_DELAY);
                    }
                    g_crid_config.init_lat = t_lat;
                    g_crid_config.init_lon = t_lon;
                    g_crid_config.flight_mode = (uint8_t)t_mode;
                    config_snapshot = g_crid_config;
                    if (g_crid_config_mutex != NULL) {
                        xSemaphoreGive(g_crid_config_mutex);
                    }
                    
                    printf("\r\n[CLI SUCCESS] Target updated to Lat:%lf, Lon:%lf, Mode:%d\n", t_lat, t_lon, t_mode);
                    
                    // 持久化存储，下次掉电不丢失
                    crid_nvs_save_config(&config_snapshot);
                } else {
                    printf("\r\n[CLI ERROR] Unknown command or invalid mode.\n");
                }
            }
        }
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    free(data);
}

void crid_cli_init(void) {
    // 确保开发板串口驱动在核心层已初始化完毕
    xTaskCreate(cli_task, "crid_cli_task", 4096, NULL, 5, NULL);
}