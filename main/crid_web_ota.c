#include "sdkconfig.h"
#include "crid_web_ota.h"
#include "crid_config.h"
#include "crid_ota.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "esp_http_server.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "CRID_WEB_OTA";
static httpd_handle_t s_server = NULL;
static volatile bool s_ota_in_progress = false;

static void reboot_delay_task(void *arg) {
    vTaskDelay(pdMS_TO_TICKS(1500));
    esp_restart();
}

#define SEND_CHUNK(str) httpd_resp_send_chunk(req, str, HTTPD_RESP_USE_STRLEN)

// ================= 确认 OTA 接口 (GET /confirm_ota) =================
static esp_err_t confirm_ota_handler(httpd_req_t *req) {
    if (crid_ota_confirm() == ESP_OK) {
        httpd_resp_set_type(req, "text/plain");
        return httpd_resp_sendstr(req, "OK: Firmware confirmed valid.");
    }
    httpd_resp_set_status(req, "400 Bad Request");
    return httpd_resp_sendstr(req, "No pending OTA to confirm.");
}

// ================= Web 主页处理 (GET /) =================
static esp_err_t root_get_handler(httpd_req_t *req) {
    // 1. 调用底层 API 获取系统与配置信息 (完全解耦)
    crid_sys_info_t sys_info;
    crid_get_sys_info(&sys_info);
    
    crid_dynamic_config_t cfg;
    crid_get_config_snapshot(&cfg);

     
    // --- 开始发送 HTML (Chunked 方式，零堆内存分配) ---
    SEND_CHUNK("<!doctype html><html><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>C-RID Control</title>"
        "<style>body{font-family:sans-serif;max-width:720px;margin:40px auto;padding:0 16px;line-height:1.5}"
        "input,select{width:100%;padding:8px;font-size:14px;box-sizing:border-box;margin-bottom:10px}"
        "button{padding:10px 15px;font-size:14px;background:#007bff;color:#fff;border:none;border-radius:4px;cursor:pointer}"
        "button:disabled{background:#ccc}"
        ".box{background:#f5f5f5;padding:15px;border-radius:8px;margin-bottom:15px}"
        ".warning{background:#fff3cd;color:#856404;padding:15px;border-radius:8px;margin-bottom:15px;border:1px solid #ffeeba}"
        ".warning button{background:#dc3545;margin-left:10px}"
        "table{width:100%;border-collapse:collapse}"
        "th,td{padding:6px;border-bottom:1px solid #ddd;text-align:left;font-size:13px}"
        "th{width:40%;color:#555}"
        ".status{margin-top:10px;font-weight:bold;font-size:14px}</style></head><body>"
        "<h1>C-RID Simulator Control</h1>");

    // 系统信息区块
    SEND_CHUNK("<div class=\"box\"><h3>System Information</h3><table>");
    char buf[128]; 
    
    int days = sys_info.uptime_sec / 86400;
    int hours = (sys_info.uptime_sec % 86400) / 3600;
    int mins = (sys_info.uptime_sec % 3600) / 60;
    int secs = sys_info.uptime_sec % 60;

    snprintf(buf, sizeof(buf), "<tr><th>Chip / Flash</th><td>%s / %sMB</td></tr>", sys_info.chip_model, sys_info.flash_size);
    SEND_CHUNK(buf);
    
    snprintf(buf, sizeof(buf), "<tr><th>MAC Address</th><td>%s</td></tr>", sys_info.mac_addr);
    SEND_CHUNK(buf);

    snprintf(buf, sizeof(buf), "<tr><th>Uptime</th><td>%dd %dh %dm %ds</td></tr>", days, hours, mins, secs);
    SEND_CHUNK(buf);

    SEND_CHUNK("<tr><th>System Time</th><td>");
    SEND_CHUNK(sys_info.sys_time);
    SEND_CHUNK("</td></tr>");

    snprintf(buf, sizeof(buf), "<tr><th>Free Heap</th><td>%lu bytes</td></tr>", sys_info.free_heap);
    SEND_CHUNK(buf);

    snprintf(buf, sizeof(buf), "<tr><th>Partition</th><td>%s</td></tr>", sys_info.partition_name);
    SEND_CHUNK(buf);
    SEND_CHUNK("</table></div>");

    // 参数配置区块
    SEND_CHUNK("<div class=\"box\"><h3>Flight Configuration</h3>"
        "<form id=\"configForm\">"
        "<label>Latitude</label><input type=\"number\" step=\"0.000001\" id=\"lat\" required>"
        "<label>Longitude</label><input type=\"number\" step=\"0.000001\" id=\"lon\" required>"
        "<label>Flight Mode</label>"
        "<select id=\"mode\">"
        "<option value=\"0\">Circle</option>"
        "<option value=\"1\">PingPong</option>"
        "<option value=\"2\">S-Search</option>"
        "</select>"
        "<button type=\"submit\">Save & Apply</button>"
        "</form>"
        "<p id=\"cfgStatus\" class=\"status\"></p></div>");

    // JS: 初始化表单数据
    SEND_CHUNK("<script>"
        "document.getElementById('lat').value = '");
    snprintf(buf, sizeof(buf), "%.6f", cfg.init_lat);
    SEND_CHUNK(buf);
    SEND_CHUNK("'; document.getElementById('lon').value = '");
    snprintf(buf, sizeof(buf), "%.6f", cfg.init_lon);
    SEND_CHUNK(buf);
    SEND_CHUNK("'; document.getElementById('mode').value = '");
    snprintf(buf, sizeof(buf), "%d", cfg.flight_mode);
    SEND_CHUNK(buf);
    SEND_CHUNK("';"
        "document.getElementById('configForm').addEventListener('submit', async function(e) {"
        "  e.preventDefault();"
        "  const lat = document.getElementById('lat').value;"
        "  const lon = document.getElementById('lon').value;"
        "  const mode = document.getElementById('mode').value;"
        "  const st = document.getElementById('cfgStatus');"
        "  st.innerText = 'Saving...'; st.style.color='blue';"
        "  try {"
        "    const res = await fetch('/config', {"
        "      method: 'POST',"
        "      headers: {'Content-Type': 'text/plain'},"
        "      body: `${lat},${lon},${mode}`"
        "    });"
        "    st.innerText = await res.text();"
        "    st.style.color = res.ok ? 'green' : 'red';"
        "  } catch(err) { st.innerText = 'Error: ' + err; st.style.color='red'; }"
        "});"
        "</script>");

    // OTA 区块
    SEND_CHUNK("<div class=\"box\"><h3>Firmware Update</h3>"
        "<form id=\"otaForm\">"
        "<input type=\"file\" id=\"firmwareFile\" accept=\".bin\" required>"
        "<button type=\"submit\" id=\"otaBtn\">Upload & OTA</button>"
        "</form>"
        "<p id=\"otaStatus\" class=\"status\"></p></div>");

    SEND_CHUNK("<script>"
        "document.getElementById('otaForm').addEventListener('submit', async function(e) {"
        "  e.preventDefault();"
        "  const file = document.getElementById('firmwareFile').files[0];"
        "  if (!file) return;"
        "  const st = document.getElementById('otaStatus');"
        "  const btn = document.getElementById('otaBtn');"
        "  st.innerText = 'Uploading ' + file.name + '...'; st.style.color='blue'; btn.disabled=true;"
        "  try {"
        "    const res = await fetch('/ota', {"
        "      method: 'POST',"
        "      headers: {'Content-Type': 'application/octet-stream'},"
        "      body: file"
        "    });"
        "    st.innerText = await res.text();"
        "    st.style.color = res.ok ? 'green' : 'red';"
        "    if(!res.ok) btn.disabled=false;"
        "  } catch(err) { st.innerText = 'Error: ' + err; st.style.color='red'; btn.disabled=false; }"
        "});"
        "</script></body></html>");

    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

// ================= 处理配置修改 (POST /config) =================
static esp_err_t config_post_handler(httpd_req_t *req) {
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

    // 调用底层 API 保存配置
    if (g_crid_config_mutex != NULL) xSemaphoreTake(g_crid_config_mutex, portMAX_DELAY);
    g_crid_config.init_lat = lat;
    g_crid_config.init_lon = lon;
    g_crid_config.flight_mode = (uint8_t)mode;
    crid_dynamic_config_t snapshot = g_crid_config;
    if (g_crid_config_mutex != NULL) xSemaphoreGive(g_crid_config_mutex);

    crid_nvs_save_config(&snapshot);
    
    char resp[64];
    snprintf(resp, sizeof(resp), "Saved: Lat:%.6f, Lon:%.6f, Mode:%d", lat, lon, mode);
    return httpd_resp_sendstr(req, resp);
}

// ================= OTA 处理：流式接收文件 (POST /ota) =================
static esp_err_t ota_post_handler(httpd_req_t *req) {
    if (s_ota_in_progress) {
        httpd_resp_set_status(req, "409 Conflict");
        return httpd_resp_sendstr(req, "OTA already in progress");
    }

    s_ota_in_progress = true;
    crid_ota_handle_t ota_handle = NULL;
    
    esp_err_t ret = crid_ota_begin(&ota_handle);
    if (ret != ESP_OK) {
        s_ota_in_progress = false;
        httpd_resp_set_status(req, "500 Internal Server Error");
        return httpd_resp_sendstr(req, "Failed to begin OTA session");
    }

    char ota_buf[1024];
    int received = 0;
    while ((received = httpd_req_recv(req, ota_buf, sizeof(ota_buf))) > 0) {
        ret = crid_ota_write(ota_handle, (const uint8_t *)ota_buf, received);
        if (ret != ESP_OK) {
            crid_ota_end(ota_handle);
            s_ota_in_progress = false;
            httpd_resp_set_status(req, "500 Internal Server Error");
            return httpd_resp_sendstr(req, "Failed to write OTA data");
        }
    }

    if (received < 0) {
        crid_ota_end(ota_handle);
        s_ota_in_progress = false;
        httpd_resp_set_status(req, "500 Internal Server Error");
        return httpd_resp_sendstr(req, "HTTP receive error");
    }

    ret = crid_ota_end(ota_handle);
    s_ota_in_progress = false;
    
    if (ret != ESP_OK) {
        httpd_resp_set_status(req, "500 Internal Server Error");
        return httpd_resp_sendstr(req, "OTA finalize failed (invalid firmware?)");
    }

    httpd_resp_set_status(req, "200 OK");
    httpd_resp_sendstr(req, "OTA succeeded. Device is rebooting...");
    xTaskCreate(reboot_delay_task, "reboot_task", 2048, NULL, 5, NULL);
    
    return ESP_OK;
}

// ================= 初始化 =================
void crid_web_ota_init(void) {
    if (s_server != NULL) return;
    
    crid_time_sync_init(); // 调用底层 API 初始化时间同步

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.stack_size = 4096;
    config.server_port = 80;
    config.max_uri_handlers = 5;
    config.recv_wait_timeout = 30;
    config.send_wait_timeout = 30;

    if (httpd_start(&s_server, &config) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start HTTP server");
        return;
    }

    httpd_uri_t root_uri    = { .uri = "/", .method = HTTP_GET, .handler = root_get_handler };
    httpd_uri_t confirm_uri = { .uri = "/confirm_ota", .method = HTTP_GET, .handler = confirm_ota_handler };
    httpd_uri_t config_uri  = { .uri = "/config", .method = HTTP_POST, .handler = config_post_handler };
    httpd_uri_t ota_uri     = { .uri = "/ota", .method = HTTP_POST, .handler = ota_post_handler };

    httpd_register_uri_handler(s_server, &root_uri);
    httpd_register_uri_handler(s_server, &confirm_uri);
    httpd_register_uri_handler(s_server, &config_uri);
    httpd_register_uri_handler(s_server, &ota_uri);
    
    ESP_LOGI(TAG, "Web server started. Open http://192.168.4.1/ in your browser");
}