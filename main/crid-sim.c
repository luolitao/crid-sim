/**
 * @file crid-sim.c
 * @brief ESP32 中国民用无人机远程识别 (C-RID) 模拟发射器 - 主入口 (重构优化版)
 *
 * 符合 GB42590-2023 和《民用微轻小型无人驾驶航空器运行识别最低性能要求（试行）》
 */

#include <stdio.h>
#include <stdint.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "nvs_flash.h"
#include "esp_log.h"

// 引入你项目的各组件头文件
#include "crid_config.h"
#include "crid_messages.h"
#include "crid_wifi.h"
#include "crid_patrol.h"

static const char *TAG = "CRID_MAIN";

// --- 全局 Beacon 帧缓冲区（仅在发送任务中使用） ---
#define BEACON_FRAME_BUF_SIZE 512
static uint8_t g_beacon_frame[BEACON_FRAME_BUF_SIZE];
static uint16_t g_beacon_frame_len = 0;
static cn_crid_config_t g_beacon_config;

/**
 * @brief C-RID Beacon 发送任务
 * 每秒(1Hz)动态更新坐标，并构筑标准的 C-RID 帧向空中广播
 */
static void crid_send_beacon_task(void *pvParameter) {
    ESP_LOGI(TAG, "Starting China C-RID beacon transmission loop (1Hz)...");

    TickType_t xLastWakeTime = xTaskGetTickCount();
    // 严格 1Hz 广播周期（通常国内规定为 1000ms 间隔）
    const TickType_t xInterval = pdMS_TO_TICKS(1000); 

    for (;;) {
        // --- 严格 1 秒定时锁定 ---
        vTaskDelayUntil(&xLastWakeTime, xInterval);

        // 1. 核心改进：在每次发射前，调用多模式轨迹状态机，计算下一步的动态位置
        // 算法会直接读取由 CLI/NVS 动态改写的全局变量 g_crid_config 中的 init_lat/lon 和 flight_mode
        double current_lat = 0;
        double current_lon = 0;
        float current_heading = 0;
        crid_patrol_calculate_next(&current_lat, &current_lon, &current_heading);

        // 2. 将计算出来的动态经纬度、航向同步更新到实际要打包的报文数据结构中
        crid_config_update_position(&g_beacon_config,
                        (float)current_lat,
                        (float)current_lon,
                        g_beacon_config.altitude_msl,
                        g_beacon_config.altitude_agl,
                        g_beacon_config.speed_horizontal,
                        g_beacon_config.speed_vertical,
                        current_heading);

        ESP_LOGI(TAG, "[📡 TX POOL] Mode:%d | Lat: %.6f, Lon: %.6f | Heading: %.1f°", 
                 g_crid_config.flight_mode, current_lat, current_lon, current_heading);

        // 3. 实时重新构建 5 条国标消息组合成的完整 Beacon 原始数据帧
        uint8_t message_counter = g_beacon_config.message_counter;
        if (crid_build_beacon_frame(&g_beacon_config, message_counter,
                                    g_beacon_frame, BEACON_FRAME_BUF_SIZE, &g_beacon_frame_len)) {
            // 4. 底层射频注入空中
            esp_err_t ret = crid_wifi_send_raw_frame(g_beacon_frame, g_beacon_frame_len);
            if (ret != ESP_OK) {
                ESP_LOGE(TAG, "Raw frame injection failed: %s", esp_err_to_name(ret));
            } else {
                g_beacon_config.message_counter++;
            }
        } else {
            ESP_LOGE(TAG, "Failed to build dynamically updated beacon frame!");
        }
    }
}

/**
 * @brief 应用主入口
 */
void app_main(void) {
    ESP_LOGI(TAG, "=== ESP32 China C-RID Transmitter ===");
    ESP_LOGI(TAG, "Standard: GB42590-2023 Deploying...");

    // 1. 初始化持久化 Flash (NVS)
    esp_err_t ret = crid_nvs_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "NVS Flash Init Failed!");
        return;
    }

    // 2. 运行时加载用户历史保存的动态配置 (若第一次启动则加载越秀山初始默认值)
    // 配置将直接注入到全局变量 g_crid_config 中
    ESP_ERROR_CHECK(crid_nvs_load_config(&g_crid_config));

    // 2.1 初始化用于报文构建的完整配置，并从动态配置同步巡航参数
    crid_config_init_default(&g_beacon_config);
    g_beacon_config.base_latitude = (float)g_crid_config.init_lat;
    g_beacon_config.base_longitude = (float)g_crid_config.init_lon;
    g_beacon_config.latitude = (float)g_crid_config.init_lat;
    g_beacon_config.longitude = (float)g_crid_config.init_lon;
    g_beacon_config.speed_horizontal = g_crid_config.speed;
    g_beacon_config.patrol_speed = g_crid_config.speed;

    // 3. 初始化 TCP/IP 网络接口与事件循环（乐鑫 Wi-Fi 驱动必需的前置条件）
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    // 4. 初始化 Wi-Fi 硬件射频驱动，并锁定在配置的目标信道（如 Channel 6）
    ret = crid_wifi_init(g_crid_config.channel);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Wi-Fi RF initialization failed: %s", esp_err_to_name(ret));
        return;
    }

    // 5. 启动串口交互式命令行（CLI）接收任务，允许用户通过串口随时动态 SET 参数
    crid_cli_init();
    ESP_LOGI(TAG, "Interactive CLI Engine online.");

    // 6. 创建 1Hz 的核心无人机 Remote ID 动态模拟发射任务
    BaseType_t task_ret = xTaskCreate(crid_send_beacon_task, "cn_crid_tx_task", 4096, NULL, 5, NULL);
    if (task_ret != pdPASS) {
        ESP_LOGE(TAG, "Critical Error: Failed to create TX task!");
        return;
    }

    // 7. 打印启动成功状态横幅
    ESP_LOGI(TAG, "--------------------------------------------------------");
    ESP_LOGI(TAG, "Transmitter dynamic framework deployed successfully!");
    ESP_LOGI(TAG, "Default Target Channel: %u", g_crid_config.channel);
    ESP_LOGI(TAG, "OUI: FA:0B:BC, Vendor Type: 0x0D (GB42590-2023)");
    ESP_LOGI(TAG, "--------------------------------------------------------");

    // 提示：app_main 此时可以结束执行，FreeRTOS 会自动回收该主线程，
    // 后台的 CLI 任务和 TX 发射任务将在其各自的优先级下持久并发运行。
}