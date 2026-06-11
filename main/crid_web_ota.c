#include "sdkconfig.h"
#include "crid_web_ota.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#ifndef CONFIG_HTTPD_MAX_REQ_HDR_LEN
#define CONFIG_HTTPD_MAX_REQ_HDR_LEN 1024
#endif

#include "crid_ota.h"
#include "sdkconfig.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "CRID_WEB_OTA";
static httpd_handle_t s_server = NULL;
static volatile bool s_ota_in_progress = false;

static bool url_decode(const char *input, char *output, size_t output_size) {
    size_t in_pos = 0;
    size_t out_pos = 0;

    while (input[in_pos] != '\0') {
        if (out_pos + 1 >= output_size) {
            return false;
        }

        if (input[in_pos] == '%' && input[in_pos + 1] != '\0' && input[in_pos + 2] != '\0') {
            char hex[3] = {input[in_pos + 1], input[in_pos + 2], '\0'};
            char *end = NULL;
            long value = strtol(hex, &end, 16);
            if (end == NULL || *end != '\0') {
                return false;
            }
            output[out_pos++] = (char)value;
            in_pos += 3;
            continue;
        }

        if (input[in_pos] == '+') {
            output[out_pos++] = ' ';
            in_pos++;
            continue;
        }

        output[out_pos++] = input[in_pos++];
    }

    output[out_pos] = '\0';
    return true;
}

static void ota_worker_task(void *arg) {
    char *ota_url = (char *)arg;

    esp_err_t ret = crid_ota_perform(ota_url);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "OTA request failed: %s", esp_err_to_name(ret));
        s_ota_in_progress = false;
    }

    free(ota_url);
    vTaskDelete(NULL);
}

static esp_err_t start_ota_async(const char *ota_url) {
    if (s_ota_in_progress) {
        return ESP_ERR_INVALID_STATE;
    }

    char *url_copy = strdup(ota_url);
    if (url_copy == NULL) {
        return ESP_ERR_NO_MEM;
    }

    s_ota_in_progress = true;
    BaseType_t ok = xTaskCreate(ota_worker_task, "web_ota_task", 6144, url_copy, 5, NULL);
    if (ok != pdPASS) {
        s_ota_in_progress = false;
        free(url_copy);
        return ESP_FAIL;
    }

    return ESP_OK;
}

static esp_err_t root_get_handler(httpd_req_t *req) {
    const char *html =
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>CRID OTA</title>"
        "<style>body{font-family:sans-serif;max-width:720px;margin:40px auto;padding:0 16px;line-height:1.5}"
        "input{width:100%;padding:12px;font-size:16px}button{padding:12px 18px;font-size:16px;margin-top:12px}"
        ".box{background:#f5f5f5;padding:16px;border-radius:12px}</style></head><body>"
        "<h1>C-RID OTA</h1><div class=\"box\">"
        "<form action=\"/ota\" method=\"get\">"
        "<label>Firmware URL</label><br><input name=\"url\" placeholder=\"http://192.168.4.2:8000/crid_sim.bin\" required>"
        "<button type=\"submit\">Start OTA</button></form>"
        "<p>Device AP default IP: <b>192.168.4.1</b></p>"
        "</div></body></html>";

    httpd_resp_set_type(req, "text/html; charset=utf-8");
    return httpd_resp_send(req, html, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t ota_get_handler(httpd_req_t *req) {
    char query[256];
    char ota_url[192];
    char decoded_url[192];

    if (httpd_req_get_url_query_str(req, query, sizeof(query)) != ESP_OK ||
        httpd_query_key_value(query, "url", ota_url, sizeof(ota_url)) != ESP_OK) {
        httpd_resp_set_status(req, "400 Bad Request");
        return httpd_resp_sendstr(req, "Missing url parameter");
    }

    if (!url_decode(ota_url, decoded_url, sizeof(decoded_url))) {
        httpd_resp_set_status(req, "400 Bad Request");
        return httpd_resp_sendstr(req, "Invalid url encoding");
    }

    esp_err_t ret = start_ota_async(decoded_url);
    if (ret == ESP_OK) {
        httpd_resp_set_status(req, "202 Accepted");
        httpd_resp_set_type(req, "text/plain; charset=utf-8");
        return httpd_resp_sendstr(req, "OTA started. Device will reboot after update.");
    }

    if (ret == ESP_ERR_INVALID_STATE) {
        httpd_resp_set_status(req, "409 Conflict");
        return httpd_resp_sendstr(req, "OTA already in progress");
    }

    httpd_resp_set_status(req, "500 Internal Server Error");
    return httpd_resp_sendstr(req, "Failed to start OTA");
}

void crid_web_ota_init(void) {
    if (s_server != NULL) {
        return;
    }

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.stack_size = 8192;
    config.server_port = 80;
    config.max_uri_handlers = 4;

    if (httpd_start(&s_server, &config) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start HTTP server");
        s_server = NULL;
        return;
    }

    httpd_uri_t root_uri = {
        .uri = "/",
        .method = HTTP_GET,
        .handler = root_get_handler,
        .user_ctx = NULL,
    };
    httpd_uri_t ota_uri = {
        .uri = "/ota",
        .method = HTTP_GET,
        .handler = ota_get_handler,
        .user_ctx = NULL,
    };

    httpd_register_uri_handler(s_server, &root_uri);
    httpd_register_uri_handler(s_server, &ota_uri);

    ESP_LOGI(TAG, "Web OTA server started. Open http://192.168.4.1/ in a browser");
}
