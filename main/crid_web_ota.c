#include "sdkconfig.h"
#include "crid_web_ota.h"
#include "crid_ota.h"
#include "crid_config.h" // 确保包含您的配置头文件
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_chip_info.h"
#include "esp_mac.h"
#include "esp_ota_ops.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

// 【提示】: 如果您不需要网络时间同步，可以将下面这行注释掉，
// 并将 crid_web_ota_init() 中的 initialize_sntp() 也注释掉。
// 如果保留，请确保在 main/CMakeLists.txt 的 REQUIRES 中添加了 "esp_sntp"
#include "esp_sntp.h"

static const char *TAG = "CRID_WEB_OTA";
static httpd_handle_t s_server = NULL;
static volatile bool s_ota_in_progress = false;

// ================= SNTP 时间同步 (可选) =================
static void time_sync_notification_cb(struct timeval *tv) {
    ESP_LOGI(TAG, "SNTP Time synchronized!");
}

static void initialize_sntp(void) {
    ESP_LOGI(TAG, "Initializing SNTP");
    esp_sntp_setoperatingmode(ESP_SNTP_OPMODE_POLL);
    esp_sntp_setservername(0, "pool.ntp.org");
    sntp_set_time_sync_notification_cb(time_sync_notification_cb);
    esp_sntp_init();
}

// ================= 辅助函数 =================
static void reboot_delay_task(void *arg) {
    vTaskDelay(pdMS_TO_TICKS(1500));
    esp_restart();
}

#define SEND_CHUNK(str) httpd_resp_send_chunk(req, str, HTTPD_RESP_USE_STRLEN)

// ================= Web 主页处理 =================
static esp_err_t root_get_handler(httpd_req_t *req) {
    // 1. 获取基础硬件信息
    esp_chip_info_t chip_info;
    esp_chip_info(&chip_info);
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    const esp_partition_t *running_part = esp_ota_get_running_partition();
    const char *part_name = running_part ? running_part->label : "Unknown";

    // 2. 计算运行时间 (Uptime)
    int64_t uptime_us = esp_timer_get_time();
    uint32_t uptime_s = uptime_us / 1000000;
    int days = uptime_s / 86400;
    int hours = (uptime_s % 86400) / 3600;
    int mins = (uptime_s % 3600) / 60;
    int secs = uptime_s % 60;

    // 3. 获取 SNTP 同步时间
    time_t now;
    struct tm timeinfo;
    time(&now);
    localtime_r(&now, &timeinfo);
    char time_str[32];
    if (timeinfo.tm_year < (2020 - 1900)) {
        snprintf(time_str, sizeof(time_str), "Not Synchronized (Offline)");
    } else {
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &timeinfo);
    }

    // 4. 获取当前无人机配置 (用于在表单中回显)
    double cur_lat = 0, cur_lon = 0;
    int cur_mode = 0;
    if (g_crid_config_mutex != NULL) {
        xSemaphoreTake(g_crid_config_mutex, portMAX_DELAY);
    }
    cur_lat = g_crid_config.init_lat;
    cur_lon = g_crid_config.init_lon;
    cur_mode = g_crid_config.flight_mode;
    if (g_crid_config_mutex != NULL) {
        xSemaphoreGive(g_crid_config_mutex);
    }

    // --- 开始发送 HTML (Chunked 方式，零堆内存分配，适配 S0WD) ---
    SEND_CHUNK("<!doctype html><html><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>ESP32 Remote ID Control</title>"
        "<style>body{font-family:sans-serif;max-width:720px;margin:40px auto;padding:0 16px;line-height:1.5}"
        "input,select{width:100%;padding:8px;font-size:14px;box-sizing:border-box;margin-bottom:10px}"
        "button{padding:10px 15px;font-size:14px;background:#007bff;color:#fff;border:none;border-radius:4px;cursor:pointer}"
        "button:disabled{background:#ccc}"
        ".box{background:#f5f5f5;padding:15px;border-radius:8px;margin-bottom:15px}"
        "table{width:100%;border-collapse:collapse}"
        "th,td{padding:6px;border-bottom:1px solid #ddd;text-align:left;font-size:13px}"
        "th{width:40%;color:#555}"
        ".status{margin-top:10px;font-weight:bold;font-size:14px}</style></head><body>"
        "<h1>C-RID Simulator Control</h1>");

    // 系统信息区块
    SEND_CHUNK("<div class=\"box\"><h3>System Information</h3><table>");
    char buf[96]; // 适度放大到 96，确保所有 snprintf 绝对安全，且在 4096 栈中微不足道
    
    snprintf(buf, sizeof(buf), "<tr><th>Chip / Flash</th><td>%s / %sMB</td></tr>", CONFIG_IDF_TARGET, CONFIG_ESPTOOLPY_FLASHSIZE);
    SEND_CHUNK(buf);
    
    snprintf(buf, sizeof(buf), "<tr><th>MAC Address</th><td>%02X:%02X:%02X:%02X:%02X:%02X</td></tr>", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    SEND_CHUNK(buf);

    snprintf(buf, sizeof(buf), "<tr><th>Uptime</th><td>%dd %dh %dm %ds</td></tr>", days, hours, mins, secs);
    SEND_CHUNK(buf);

    // 【修复】直接分块发送，避免 snprintf 拼接长字符串导致截断警告
    SEND_CHUNK("<tr><th>System Time</th><td>");
    SEND_CHUNK(time_str);
    SEND_CHUNK("</td></tr>");

    snprintf(buf, sizeof(buf), "<tr><th>Free Heap</th><td>%d bytes</td></tr>", (int)esp_get_free_heap_size());
    SEND_CHUNK(buf);

    snprintf(buf, sizeof(buf), "<tr><th>Partition</th><td>%s</td></tr>", part_name);
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

    // JS: 初始化表单数据并处理提交 (拆分发送以避免 snprintf 截断警告)
    SEND_CHUNK("<script>"
        "document.getElementById('lat').value = '");
    snprintf(buf, sizeof(buf), "%.6f", cur_lat);
    SEND_CHUNK(buf);
    
    SEND_CHUNK("';document.getElementById('lon').value = '");
    snprintf(buf, sizeof(buf), "%.6f", cur_lon);
    SEND_CHUNK(buf);
    
    SEND_CHUNK("';document.getElementById('mode').value = '");
    snprintf(buf, sizeof(buf), "%d", cur_mode);
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

    httpd_resp_send_chunk(req, NULL, 0); // 结束 Chunked 响应
    return ESP_OK;
}

// ================= 处理配置修改 =================
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

    if (g_crid_config_mutex != NULL) {
        xSemaphoreTake(g_crid_config_mutex, portMAX_DELAY);
    }
    g_crid_config.init_lat = lat;
    g_crid_config.init_lon = lon;
    g_crid_config.flight_mode = (uint8_t)mode;
    crid_dynamic_config_t snapshot = g_crid_config;
    if (g_crid_config_mutex != NULL) {
        xSemaphoreGive(g_crid_config_mutex);
    }

    crid_nvs_save_config(&snapshot);
    
    char resp[64];
    snprintf(resp, sizeof(resp), "Saved: Lat:%.6f, Lon:%.6f, Mode:%d", lat, lon, mode);
    return httpd_resp_sendstr(req, resp);
}

// ================= OTA 处理 (流式接收) =================
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
        return httpd_resp_sendstr(req, "Failed to begin OTA");
    }

    char ota_buf[1024];
    int received = 0;
    while ((received = httpd_req_recv(req, ota_buf, sizeof(ota_buf))) > 0) {
        ret = crid_ota_write(ota_handle, (const uint8_t *)ota_buf, received);
        if (ret != ESP_OK) {
            crid_ota_end(ota_handle);
            s_ota_in_progress = false;
            httpd_resp_set_status(req, "500 Internal Server Error");
            return httpd_resp_sendstr(req, "Write failed");
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
        return httpd_resp_sendstr(req, "OTA finalize failed");
    }

    httpd_resp_set_status(req, "200 OK");
    httpd_resp_sendstr(req, "OTA succeeded. Rebooting...");
    xTaskCreate(reboot_delay_task, "reboot_task", 2048, NULL, 5, NULL);
    return ESP_OK;
}

// ================= 初始化 =================
void crid_web_ota_init(void) {
    if (s_server != NULL) return;
    
    // 如果不需要网络时间同步，请注释掉下面这行
    initialize_sntp(); 

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.stack_size = 4096; // S0WD 优化：限制栈大小
    config.server_port = 80;
    config.max_uri_handlers = 4;

    if (httpd_start(&s_server, &config) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start HTTP server");
        return;
    }

    httpd_uri_t root_uri   = { .uri = "/", .method = HTTP_GET, .handler = root_get_handler };
    httpd_uri_t config_uri = { .uri = "/config", .method = HTTP_POST, .handler = config_post_handler };
    httpd_uri_t ota_uri    = { .uri = "/ota", .method = HTTP_POST, .handler = ota_post_handler };

    httpd_register_uri_handler(s_server, &root_uri);
    httpd_register_uri_handler(s_server, &config_uri);
    httpd_register_uri_handler(s_server, &ota_uri);
    
    ESP_LOGI(TAG, "Web server started. Open http://192.168.4.1/");
}