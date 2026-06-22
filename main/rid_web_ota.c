#include "rid_web_ota.h"
#include "rid_config.h"
#include "rid_ota.h"
#include "rid_manager.h"
#include "sdkconfig.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "esp_http_server.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "RID_WEB_OTA";
static httpd_handle_t s_server = NULL;
static volatile bool s_ota_in_progress = false;
#define FIRMWARE_VERSION "v1.0.0-" __DATE__ " " __TIME__

static void reboot_delay_task(void *arg) {
    vTaskDelay(pdMS_TO_TICKS(1500));
    esp_restart();
}

// ================= Base64 解码（轻量级实现） =================
//static const char base64_table[] =     "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int base64_decode_char(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static size_t base64_decode(const char *in, size_t in_len, uint8_t *out, size_t out_size) {
    size_t out_pos = 0;
    int bits = 0, buffer = 0;
    for (size_t i = 0; i < in_len && out_pos < out_size; i++) {
        char c = in[i];
        if (c == '=') break; // padding
        int val = base64_decode_char(c);
        if (val < 0) continue; // skip invalid chars
        buffer = (buffer << 6) | val;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[out_pos++] = (buffer >> bits) & 0xFF;
        }
    }
    return out_pos;
}

// ================= HTTP 基本认证 =================
#define WEB_USERNAME "admin"
#define WEB_PASSWORD "password"  // 建议从 NVS 读取

static bool validate_auth(httpd_req_t *req) {
    char auth_buf[256];
    size_t auth_len = sizeof(auth_buf);  // 缓冲区总大小
    if (httpd_req_get_hdr_value_str(req, "Authorization", auth_buf, auth_len) != ESP_OK) {
        return false;
    }
    // 解析 "Basic base64" 格式
    const char *auth_header = auth_buf;
    if (strncasecmp(auth_header, "Basic ", 6) != 0) return false;
    auth_header += 6;
    
    // Base64 解码
    uint8_t decoded[64];
    size_t decoded_len = base64_decode(auth_header, strlen(auth_header), decoded, sizeof(decoded));
    if (decoded_len == 0) return false;
    decoded[decoded_len] = '\0';
    // 格式为 "user:password"
    char *sep = strchr((char *)decoded, ':');
    if (sep == NULL) return false;
    *sep = '\0';
    char *user = (char *)decoded;
    char *pass = (char *)(sep + 1);
    return (strcmp(user, WEB_USERNAME) == 0 && strcmp(pass, WEB_PASSWORD) == 0);
}

#define SEND_CHUNK(str) httpd_resp_send_chunk(req, str, HTTPD_RESP_USE_STRLEN)

// ================= 确认 OTA 接口 (GET /confirm_ota) =================
static esp_err_t confirm_ota_handler(httpd_req_t *req) {
    // 验证身份
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

// ================= Web 主页处理 (GET /) =================
static esp_err_t root_get_handler(httpd_req_t *req) {
    rid_sys_info_t sys_info;
    rid_get_sys_info(&sys_info);
    rid_dynamic_config_t cfg;
    rid_get_config_snapshot(&cfg);

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
    snprintf(buf, sizeof(buf), "<tr><th>Free Heap</th><td>%u bytes</td></tr>", (unsigned int)sys_info.free_heap);
    SEND_CHUNK(buf);
    snprintf(buf, sizeof(buf), "<tr><th>Partition</th><td>%s</td></tr>", sys_info.partition_name);
    SEND_CHUNK(buf);
    snprintf(buf, sizeof(buf), "<tr><th>Firmware</th><td>%s</td></tr>", FIRMWARE_VERSION);
    SEND_CHUNK(buf);

    // 从 sys_info 中已有 partition_name 字段，直接显示
    snprintf(buf, sizeof(buf), "<tr><th>Running Partition</th><td>%s</td></tr>", sys_info.partition_name);
    SEND_CHUNK(buf);
    SEND_CHUNK("</table></div>");

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
    // 验证身份
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

    // 在 config_post_handler 中，更新配置后
    if (g_rid_config_mutex != NULL) xSemaphoreTake(g_rid_config_mutex, portMAX_DELAY);
    // 假设修改的是全局动态配置（用于位置更新），但实例配置应单独修改。
    // 若实例配置通过此 API 修改，则需更新对应实例并保存。
    // 此处示例：获取第一个实例并更新其配置
    drone_instance_t *inst = rid_manager_get_first(); // 需要实现
    if (inst) {
        inst->config.latitude = (float)lat;
        inst->config.longitude = (float)lon;
        // 保存实例列表
        rid_manager_save_all();
    }
    
    char resp[64];
    snprintf(resp, sizeof(resp), "Saved: Lat:%.6f, Lon:%.6f, Mode:%d", lat, lon, mode);
    return httpd_resp_sendstr(req, resp);
}

// ================= OTA 处理：流式接收文件 (POST /ota) =================
static esp_err_t ota_post_handler(httpd_req_t *req) {
    // 验证身份
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

// ================= 初始化 =================
void rid_web_ota_init(void) {
    rid_ota_auto_confirm();   // 自动确认
    if (s_server != NULL) return;
    
    rid_time_sync_init();

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