// rid_web_ota.c 完整修正版（纯 C，移除 lambda，修正 API 路由参数解析）
#include "sdkconfig.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "esp_http_server.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "cJSON.h"

#include "rid_web_ota.h"
#include "rid_config.h"
#include "rid_ota.h"
#include "rid_manager.h"
#include "rid_patrol.h"
#include "rid_api.h"
#include "rid_auth.h"
#include "rid_static.h"

#define FIRMWARE_VERSION "v1.0.0-" __DATE__ " " __TIME__

static const char *TAG = "RID_WEB_OTA";
static httpd_handle_t s_server = NULL;
static volatile bool s_ota_in_progress = false;

// ================= 原有其他处理函数 ====================
static void reboot_delay_task(void *arg) {
    vTaskDelay(pdMS_TO_TICKS(1500));
    esp_restart();
}

// -------------------- 全局配置（兼容旧接口） --------------------
static esp_err_t config_post_handler(httpd_req_t *req) {
    if (!validate_auth(req)) {
        httpd_resp_set_status(req, "401 Unauthorized");
        httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"RID OTA\"");
        return httpd_resp_sendstr(req, "Unauthorized");
    }
    char buf[64];
    int received = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (received <= 0) {
        httpd_resp_set_status(req, "400 Bad Request");
        return httpd_resp_sendstr(req, "Empty body");
    }
    buf[received] = '\0';
    double lat = 0, lon = 0;
    int mode = 0;
    if (sscanf(buf, "%lf,%lf,%d", &lat, &lon, &mode) != 3) {
        httpd_resp_set_status(req, "400 Bad Request");
        return httpd_resp_sendstr(req, "Invalid format");
    }
    if (mode < 0 || mode >= FLIGHT_MODE_MAX) {
        httpd_resp_set_status(req, "400 Bad Request");
        return httpd_resp_sendstr(req, "Invalid mode");
    }
    // 更新全局配置（仅示例，实际应更新实例）
    // 这里我们更新第一个实例（如果有）
    drone_instance_t *inst = rid_manager_get_first();
    if (inst) {
        inst->config.latitude = (float)lat;
        inst->config.longitude = (float)lon;
        rid_manager_save_all();
    }
    char resp[64];
    snprintf(resp, sizeof(resp), "Saved: Lat:%.6f, Lon:%.6f, Mode:%d", lat, lon, mode);
    return httpd_resp_sendstr(req, resp);
}

// -------------------- 确认 OTA --------------------
static esp_err_t confirm_ota_handler(httpd_req_t *req) {
    if (!validate_auth(req)) {
        httpd_resp_set_status(req, "401 Unauthorized");
        httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"RID OTA\"");
        return httpd_resp_sendstr(req, "Unauthorized");
    }
    if (rid_ota_confirm() == ESP_OK) {
        httpd_resp_set_type(req, "text/plain");
        return httpd_resp_sendstr(req, "OK: Firmware confirmed valid.");
    }
    httpd_resp_set_status(req, "400 Bad Request");
    return httpd_resp_sendstr(req, "No pending OTA to confirm.");
}

// -------------------- OTA 处理 --------------------
static esp_err_t ota_post_handler(httpd_req_t *req) {
    if (!validate_auth(req)) {
        httpd_resp_set_status(req, "401 Unauthorized");
        httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"RID OTA\"");
        return httpd_resp_sendstr(req, "Unauthorized");
    }
    if (s_ota_in_progress) {
        httpd_resp_set_status(req, "409 Conflict");
        return httpd_resp_sendstr(req, "OTA already in progress");
    }
    s_ota_in_progress = true;
    rid_ota_handle_t ota_handle = NULL;
    esp_err_t ret = rid_ota_begin(&ota_handle);
    if (ret != ESP_OK) {
        s_ota_in_progress = false;
        httpd_resp_set_status(req, "500 Internal Server Error");
        char err_msg[64];
        snprintf(err_msg, sizeof(err_msg), "OTA begin failed: %s", esp_err_to_name(ret));
        return httpd_resp_sendstr(req, err_msg);
    }
    char ota_buf[1024];
    int received = 0;
    while ((received = httpd_req_recv(req, ota_buf, sizeof(ota_buf))) > 0) {
        ret = rid_ota_write(ota_handle, (const uint8_t *)ota_buf, received);
        if (ret != ESP_OK) {
            s_ota_in_progress = false;
            httpd_resp_set_status(req, "500 Internal Server Error");
            char err_msg[64];
            snprintf(err_msg, sizeof(err_msg), "Write failed: %s", esp_err_to_name(ret));
            return httpd_resp_sendstr(req, err_msg);
        }
    }
    if (received < 0) {
        rid_ota_end(ota_handle);
        s_ota_in_progress = false;
        httpd_resp_set_status(req, "500 Internal Server Error");
        return httpd_resp_sendstr(req, "HTTP receive error");
    }
    ret = rid_ota_end(ota_handle);
    s_ota_in_progress = false;
    if (ret != ESP_OK) {
        httpd_resp_set_status(req, "500 Internal Server Error");
        char err_msg[64];
        snprintf(err_msg, sizeof(err_msg), "OTA finalize failed: %s", esp_err_to_name(ret));
        return httpd_resp_sendstr(req, err_msg);
    }
    httpd_resp_set_status(req, "200 OK");
    httpd_resp_sendstr(req, "OTA succeeded. Device is rebooting...");
    xTaskCreate(reboot_delay_task, "reboot_task", 2048, NULL, 5, NULL);
    return ESP_OK;
}

// -------------------- 系统信息 API --------------------
static esp_err_t sysinfo_get_handler(httpd_req_t *req) {
    rid_sys_info_t info;
    rid_get_sys_info(&info);
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "Chip", info.chip_model);
    cJSON_AddStringToObject(root, "Flash", info.flash_size);
    cJSON_AddStringToObject(root, "MAC", info.mac_addr);
    cJSON_AddNumberToObject(root, "Uptime (s)", info.uptime_sec);
    cJSON_AddStringToObject(root, "System Time", info.sys_time);
    cJSON_AddNumberToObject(root, "Free Heap", info.free_heap);
    cJSON_AddStringToObject(root, "Partition", info.partition_name);
    char version[32];
    snprintf(version, sizeof(version), "v1.0.0-%s %s", __DATE__, __TIME__);
    cJSON_AddStringToObject(root, "Firmware", version);
    char *json = cJSON_Print(root);
    cJSON_Delete(root);
    httpd_resp_set_type(req, "application/json");
    esp_err_t ret = httpd_resp_sendstr(req, json);
    free(json);
    return ret;
}


// ==================== 初始化 ====================
// -------------------- 路由注册 --------------------
void rid_web_ota_init(void) {
    if (s_server != NULL) return;
    
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.max_uri_handlers = 20;
    esp_err_t ret = httpd_start(&s_server, &config);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start HTTP server: %s", esp_err_to_name(ret));
        return;
    } else {
        ESP_LOGI(TAG, "HTTP server started successfully");
    }

    // 静态页面（首页、配置页、OTA页）
    httpd_uri_t root = { .uri = "/", .method = HTTP_GET, .handler = serve_index_html };
    httpd_uri_t config_page = { .uri = "/config.html", .method = HTTP_GET, .handler = serve_config_html };
    httpd_uri_t ota_page = { .uri = "/ota.html", .method = HTTP_GET, .handler = serve_ota_html };
    httpd_register_uri_handler(s_server, &root);
    httpd_register_uri_handler(s_server, &config_page);
    httpd_register_uri_handler(s_server, &ota_page);

    // ---------- API 路由（实例管理） ----------
    httpd_uri_t api_instances = { .uri = "/api/instances", .method = HTTP_GET, .handler = instances_get_handler };
    httpd_uri_t api_instance_post = { .uri = "/api/instance", .method = HTTP_POST, .handler = instance_post_handler };
    httpd_uri_t api_instance_put = { .uri = "/api/instance", .method = HTTP_PUT, .handler = instance_put_handler };
    httpd_uri_t api_instance_delete = { .uri = "/api/instance", .method = HTTP_DELETE, .handler = instance_delete_handler };
    httpd_uri_t api_instance_start = { .uri = "/api/instance/start", .method = HTTP_POST, .handler = instance_start_handler };
    httpd_uri_t api_instance_stop = { .uri = "/api/instance/stop", .method = HTTP_POST, .handler = instance_stop_handler };
    httpd_uri_t api_sysinfo = { .uri = "/api/sysinfo", .method = HTTP_GET, .handler = sysinfo_get_handler };

    httpd_register_uri_handler(s_server, &api_instances);
    httpd_register_uri_handler(s_server, &api_instance_post);
    httpd_register_uri_handler(s_server, &api_instance_put);
    httpd_register_uri_handler(s_server, &api_instance_delete);
    httpd_register_uri_handler(s_server, &api_instance_start);
    httpd_register_uri_handler(s_server, &api_instance_stop);
    httpd_register_uri_handler(s_server, &api_sysinfo);

    // ---------- OTA 与配置路由 ----------
    httpd_uri_t ota = { .uri = "/ota", .method = HTTP_POST, .handler = ota_post_handler };
    httpd_uri_t confirm = { .uri = "/confirm_ota", .method = HTTP_GET, .handler = confirm_ota_handler };
    httpd_uri_t ota_config = { .uri = "/config", .method = HTTP_POST, .handler = config_post_handler };

    httpd_register_uri_handler(s_server, &ota);
    httpd_register_uri_handler(s_server, &confirm);
    httpd_register_uri_handler(s_server, &ota_config);

    ESP_LOGI(TAG, "Web server started. Open http://192.168.4.1/ in your browser");
}

