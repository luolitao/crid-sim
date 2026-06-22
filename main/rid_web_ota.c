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
#include "rid_web_html.h"

static const char *TAG = "RID_WEB_OTA";
static httpd_handle_t s_server = NULL;
static volatile bool s_ota_in_progress = false;

static void reboot_delay_task(void *arg) {
    vTaskDelay(pdMS_TO_TICKS(1500));
    esp_restart();
}


// ================= 原有其他处理函数 ====================
static esp_err_t config_post_handler(httpd_req_t *req) {
    if (!validate_auth(req)) {
        httpd_resp_set_status(req, "401 Unauthorized");
        httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"C-RID OTA\"");
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

static esp_err_t confirm_ota_handler(httpd_req_t *req) {
    if (!validate_auth(req)) {
        httpd_resp_set_status(req, "401 Unauthorized");
        httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"C-RID OTA\"");
        return httpd_resp_sendstr(req, "Unauthorized");
    }
    if (rid_ota_confirm() == ESP_OK) {
        httpd_resp_set_type(req, "text/plain");
        return httpd_resp_sendstr(req, "OK: Firmware confirmed valid.");
    }
    httpd_resp_set_status(req, "400 Bad Request");
    return httpd_resp_sendstr(req, "No pending OTA to confirm.");
}

static esp_err_t ota_post_handler(httpd_req_t *req) {
    if (!validate_auth(req)) {
        httpd_resp_set_status(req, "401 Unauthorized");
        httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"C-RID OTA\"");
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

// ==================== 初始化 ====================
void rid_web_ota_init(void) {
    rid_ota_auto_confirm();
    if (s_server != NULL) return;
    rid_time_sync_init();

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.stack_size = 4096;
    config.server_port = 80;
    config.max_uri_handlers = 10;
    config.recv_wait_timeout = 60;
    config.send_wait_timeout = 60;

    if (httpd_start(&s_server, &config) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start HTTP server");
        return;
    }

    httpd_uri_t root_uri = { .uri = "/", .method = HTTP_GET, .handler = send_root_html };
    httpd_uri_t confirm_uri = { .uri = "/confirm_ota", .method = HTTP_GET, .handler = confirm_ota_handler };
    httpd_uri_t config_uri = { .uri = "/config", .method = HTTP_POST, .handler = config_post_handler };
    httpd_uri_t ota_uri = { .uri = "/ota", .method = HTTP_POST, .handler = ota_post_handler };
    httpd_uri_t instances_get = { .uri = "/api/instances", .method = HTTP_GET, .handler = instances_get_handler };
    httpd_uri_t instance_post = { .uri = "/api/instance", .method = HTTP_POST, .handler = instance_post_handler };
    httpd_uri_t instance_put = { .uri = "/api/instance", .method = HTTP_PUT, .handler = instance_put_handler };
    httpd_uri_t instance_delete = { .uri = "/api/instance", .method = HTTP_DELETE, .handler = instance_delete_handler };
    httpd_uri_t instance_start = { .uri = "/api/instance/start", .method = HTTP_POST, .handler = instance_start_handler };
    httpd_uri_t instance_stop = { .uri = "/api/instance/stop", .method = HTTP_POST, .handler = instance_stop_handler };

    httpd_register_uri_handler(s_server, &root_uri);
    httpd_register_uri_handler(s_server, &confirm_uri);
    httpd_register_uri_handler(s_server, &config_uri);
    httpd_register_uri_handler(s_server, &ota_uri);
    httpd_register_uri_handler(s_server, &instances_get);
    httpd_register_uri_handler(s_server, &instance_post);
    httpd_register_uri_handler(s_server, &instance_put);
    httpd_register_uri_handler(s_server, &instance_delete);
    httpd_register_uri_handler(s_server, &instance_start);
    httpd_register_uri_handler(s_server, &instance_stop);

    ESP_LOGI(TAG, "Web server started. Open http://192.168.4.1/ in your browser");
}