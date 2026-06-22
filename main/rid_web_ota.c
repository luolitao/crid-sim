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

static const char *TAG = "RID_WEB_OTA";
static httpd_handle_t s_server = NULL;
static volatile bool s_ota_in_progress = false;

#define FIRMWARE_VERSION "v1.0.0-" __DATE__ " " __TIME__

static void reboot_delay_task(void *arg) {
    vTaskDelay(pdMS_TO_TICKS(1500));
    esp_restart();
}

// ================= Base64 解码（轻量级） =================
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
        if (c == '=') break;
        int val = base64_decode_char(c);
        if (val < 0) continue;
        buffer = (buffer << 6) | val;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[out_pos++] = (buffer >> bits) & 0xFF;
        }
    }
    return out_pos;
}

#define SEND_CHUNK(str) httpd_resp_send_chunk(req, str, HTTPD_RESP_USE_STRLEN)

// ==================== HTTP 基本认证 ====================
#define WEB_USERNAME "admin"
#define WEB_PASSWORD "password"

static bool validate_auth(httpd_req_t *req) {
    char auth_buf[256];
    size_t auth_len = sizeof(auth_buf);
    if (httpd_req_get_hdr_value_str(req, "Authorization", auth_buf, auth_len) != ESP_OK) {
        return false;
    }
    const char *auth_header = auth_buf;
    if (strncasecmp(auth_header, "Basic ", 6) != 0) return false;
    auth_header += 6;
    uint8_t decoded[64];
    size_t decoded_len = base64_decode(auth_header, strlen(auth_header), decoded, sizeof(decoded));
    if (decoded_len == 0) return false;
    decoded[decoded_len] = '\0';
    char *sep = strchr((char*)decoded, ':');
    if (!sep) return false;
    *sep = '\0';
    char *user = (char*)decoded;
    char *pass = (char*)(sep + 1);
    return (strcmp(user, WEB_USERNAME) == 0 && strcmp(pass, WEB_PASSWORD) == 0);
}

// ==================== 辅助：从 URL 查询字符串提取 id ====================
static bool get_id_from_query(httpd_req_t *req, uint32_t *id) {
    char query[64];
    size_t qlen = sizeof(query);
    if (httpd_req_get_url_query_str(req, query, qlen) != ESP_OK) {  // 修正：传递 qlen 而非 &qlen
        return false;
    }
    char id_str[16];
    if (httpd_query_key_value(query, "id", id_str, sizeof(id_str)) != ESP_OK) {
        return false;
    }
    *id = (uint32_t)atoi(id_str);
    return true;
}

// ==================== API 回调函数（纯 C） ====================
static void instance_to_json_cb(drone_instance_t *inst, void *ctx) {
    cJSON *array = (cJSON*)ctx;
    cJSON *obj = cJSON_CreateObject();
    if (!obj) return;
    cJSON_AddNumberToObject(obj, "id", (double)inst->id);
    cJSON_AddNumberToObject(obj, "standard", inst->standard);
    cJSON_AddStringToObject(obj, "uas_id", inst->config.uas_id);
    cJSON_AddNumberToObject(obj, "latitude", inst->config.latitude);
    cJSON_AddNumberToObject(obj, "longitude", inst->config.longitude);
    cJSON_AddNumberToObject(obj, "altitude_msl", inst->config.altitude_msl);
    cJSON_AddNumberToObject(obj, "altitude_agl", inst->config.altitude_agl);
    cJSON_AddNumberToObject(obj, "speed_horizontal", inst->config.speed_horizontal);
    cJSON_AddNumberToObject(obj, "heading", inst->config.heading);
    cJSON_AddBoolToObject(obj, "active", inst->active);
    cJSON_AddNumberToObject(obj, "flight_mode", inst->config.flight_mode);
    cJSON_AddItemToArray(array, obj);
}

// GET /api/instances
static esp_err_t instances_get_handler(httpd_req_t *req) {
    if (!validate_auth(req)) {
        httpd_resp_set_status(req, "401 Unauthorized");
        httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"C-RID OTA\"");
        return httpd_resp_sendstr(req, "Unauthorized");
    }
    cJSON *root = cJSON_CreateArray();
    rid_manager_for_each(instance_to_json_cb, root);
    char *json_str = cJSON_Print(root);
    cJSON_Delete(root);
    httpd_resp_set_type(req, "application/json");
    esp_err_t ret = httpd_resp_sendstr(req, json_str);
    free(json_str);
    return ret;
}

// POST /api/instance
static esp_err_t instance_post_handler(httpd_req_t *req) {
    if (!validate_auth(req)) {
        httpd_resp_set_status(req, "401 Unauthorized");
        httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"C-RID OTA\"");
        return httpd_resp_sendstr(req, "Unauthorized");
    }
    char buf[512];
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (len <= 0) {
        httpd_resp_set_status(req, "400 Bad Request");
        return httpd_resp_sendstr(req, "Empty body");
    }
    buf[len] = '\0';
    cJSON *json = cJSON_Parse(buf);
    if (!json) {
        httpd_resp_set_status(req, "400 Bad Request");
        return httpd_resp_sendstr(req, "Invalid JSON");
    }
    cJSON *standard = cJSON_GetObjectItem(json, "standard");
    cJSON *uas_id = cJSON_GetObjectItem(json, "uas_id");
    cJSON *lat = cJSON_GetObjectItem(json, "latitude");
    cJSON *lon = cJSON_GetObjectItem(json, "longitude");
    cJSON *alt = cJSON_GetObjectItem(json, "altitude_msl");
    cJSON *mode = cJSON_GetObjectItem(json, "flight_mode");
    if (!standard || !uas_id || !lat || !lon || !alt || !mode) {
        cJSON_Delete(json);
        httpd_resp_set_status(req, "400 Bad Request");
        return httpd_resp_sendstr(req, "Missing fields");
    }
    rid_config_t cfg;
    rid_config_init_default(&cfg);
    strncpy(cfg.uas_id, uas_id->valuestring, sizeof(cfg.uas_id) - 1);
    cfg.latitude = (float)lat->valuedouble;
    cfg.longitude = (float)lon->valuedouble;
    cfg.altitude_msl = (float)alt->valuedouble;
    cfg.altitude_agl = (float)alt->valuedouble;
    cfg.flight_mode = (uint8_t)mode->valueint;
    uint32_t id;
    esp_err_t ret = rid_manager_create((rid_standard_t)standard->valueint, &cfg, &id);
    cJSON_Delete(json);
    if (ret != ESP_OK) {
        httpd_resp_set_status(req, "500 Internal Server Error");
        return httpd_resp_sendstr(req, "Create failed");
    }
    rid_manager_save_all();
    httpd_resp_set_status(req, "201 Created");
    char resp[32];
    snprintf(resp, sizeof(resp), "{\"id\":%u}", (unsigned)id);
    return httpd_resp_sendstr(req, resp);
}

// PUT /api/instance?id=xxx
static esp_err_t instance_put_handler(httpd_req_t *req) {
    if (!validate_auth(req)) return httpd_resp_sendstr(req, "Unauthorized");
    uint32_t id;
    if (!get_id_from_query(req, &id)) {
        httpd_resp_set_status(req, "400 Bad Request");
        return httpd_resp_sendstr(req, "Missing or invalid id");
    }
    char buf[512];
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (len <= 0) {
        httpd_resp_set_status(req, "400 Bad Request");
        return httpd_resp_sendstr(req, "Empty body");
    }
    buf[len] = '\0';
    cJSON *json = cJSON_Parse(buf);
    if (!json) {
        httpd_resp_set_status(req, "400 Bad Request");
        return httpd_resp_sendstr(req, "Invalid JSON");
    }
    rid_config_t cfg;
    if (rid_manager_get_config(id, &cfg) != ESP_OK) {
        cJSON_Delete(json);
        httpd_resp_set_status(req, "404 Not Found");
        return httpd_resp_sendstr(req, "Instance not found");
    }
    cJSON *item;
    if ((item = cJSON_GetObjectItem(json, "uas_id"))) {
        strncpy(cfg.uas_id, item->valuestring, sizeof(cfg.uas_id) - 1);
    }
    if ((item = cJSON_GetObjectItem(json, "latitude"))) cfg.latitude = (float)item->valuedouble;
    if ((item = cJSON_GetObjectItem(json, "longitude"))) cfg.longitude = (float)item->valuedouble;
    if ((item = cJSON_GetObjectItem(json, "altitude_msl"))) cfg.altitude_msl = (float)item->valuedouble;
    if ((item = cJSON_GetObjectItem(json, "altitude_agl"))) cfg.altitude_agl = (float)item->valuedouble;
    if ((item = cJSON_GetObjectItem(json, "flight_mode"))) cfg.flight_mode = (uint8_t)item->valueint;
    esp_err_t ret = rid_manager_update_config(id, &cfg);
    cJSON_Delete(json);
    if (ret != ESP_OK) {
        httpd_resp_set_status(req, "500 Internal Server Error");
        return httpd_resp_sendstr(req, "Update failed");
    }
    rid_manager_save_all();
    return httpd_resp_sendstr(req, "OK");
}

// DELETE /api/instance?id=xxx
static esp_err_t instance_delete_handler(httpd_req_t *req) {
    if (!validate_auth(req)) return httpd_resp_sendstr(req, "Unauthorized");
    uint32_t id;
    if (!get_id_from_query(req, &id)) {
        httpd_resp_set_status(req, "400 Bad Request");
        return httpd_resp_sendstr(req, "Missing or invalid id");
    }
    esp_err_t ret = rid_manager_delete(id);
    if (ret != ESP_OK) {
        httpd_resp_set_status(req, "404 Not Found");
        return httpd_resp_sendstr(req, "Not found");
    }
    rid_manager_save_all();
    return httpd_resp_sendstr(req, "OK");
}

// POST /api/instance/start?id=xxx
static esp_err_t instance_start_handler(httpd_req_t *req) {
    if (!validate_auth(req)) return httpd_resp_sendstr(req, "Unauthorized");
    uint32_t id;
    if (!get_id_from_query(req, &id)) {
        httpd_resp_set_status(req, "400 Bad Request");
        return httpd_resp_sendstr(req, "Missing or invalid id");
    }
    esp_err_t ret = rid_manager_start(id);
    if (ret != ESP_OK) {
        httpd_resp_set_status(req, "404 Not Found");
        return httpd_resp_sendstr(req, "Not found");
    }
    rid_manager_save_all();
    return httpd_resp_sendstr(req, "OK");
}

// POST /api/instance/stop?id=xxx
static esp_err_t instance_stop_handler(httpd_req_t *req) {
    if (!validate_auth(req)) return httpd_resp_sendstr(req, "Unauthorized");
    uint32_t id;
    if (!get_id_from_query(req, &id)) {
        httpd_resp_set_status(req, "400 Bad Request");
        return httpd_resp_sendstr(req, "Missing or invalid id");
    }
    esp_err_t ret = rid_manager_stop(id);
    if (ret != ESP_OK) {
        httpd_resp_set_status(req, "404 Not Found");
        return httpd_resp_sendstr(req, "Not found");
    }
    rid_manager_save_all();
    return httpd_resp_sendstr(req, "OK");
}

// ==================== 主页处理（与之前相同，但实例管理 JS 调用 API 时使用 ?id= 方式） ====================
static esp_err_t root_get_handler(httpd_req_t *req) {
    rid_sys_info_t sys_info;
    rid_get_sys_info(&sys_info);
    rid_dynamic_config_t cfg;
    rid_get_config_snapshot(&cfg);

    SEND_CHUNK("<!doctype html><html><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>C-RID Control</title>"
        "<style>body{font-family:sans-serif;max-width:960px;margin:40px auto;padding:0 16px;line-height:1.5}"
        "input,select{width:100%;padding:8px;font-size:14px;box-sizing:border-box;margin-bottom:10px}"
        "button{padding:10px 15px;font-size:14px;background:#007bff;color:#fff;border:none;border-radius:4px;cursor:pointer}"
        "button:disabled{background:#ccc} .box{background:#f5f5f5;padding:15px;border-radius:8px;margin-bottom:15px}"
        "table{width:100%;border-collapse:collapse} th,td{padding:6px;border-bottom:1px solid #ddd;text-align:left;font-size:13px}"
        "th{width:40%;color:#555} .status{margin-top:10px;font-weight:bold;font-size:14px}"
        ".instance-card{border:1px solid #ddd;padding:10px;margin:10px 0;border-radius:5px;background:#fff}"
        ".instance-card h4{margin:0 0 10px 0} .btn-danger{background:#dc3545} .btn-success{background:#28a745}"
        ".btn-warning{background:#ffc107;color:#000}</style></head><body>"
        "<h1>C-RID Simulator Control</h1>");

    // 系统信息
    SEND_CHUNK("<div class=\"box\"><h3>System Information</h3><table>");
    char buf[256];
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
    SEND_CHUNK("</table></div>");

    // 全局配置
    SEND_CHUNK("<div class=\"box\"><h3>Global Flight Configuration</h3>"
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

    // 实例管理
    SEND_CHUNK("<div class=\"box\"><h3>Drone Instances</h3>"
        "<div id=\"instances-list\"></div>"
        "<button id=\"add-instance\" class=\"btn-success\">Add Instance</button>"
        "</div>");

    // OTA
    SEND_CHUNK("<div class=\"box\"><h3>Firmware Update</h3>"
        "<form id=\"otaForm\">"
        "<input type=\"file\" id=\"firmwareFile\" accept=\".bin\" required>"
        "<button type=\"submit\" id=\"otaBtn\">Upload & OTA</button>"
        "</form>"
        "<p id=\"otaStatus\" class=\"status\"></p></div>");

    // JavaScript
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
    SEND_CHUNK("';\n"
        "document.getElementById('configForm').addEventListener('submit', async function(e) {\n"
        "  e.preventDefault();\n"
        "  const lat = document.getElementById('lat').value;\n"
        "  const lon = document.getElementById('lon').value;\n"
        "  const mode = document.getElementById('mode').value;\n"
        "  const st = document.getElementById('cfgStatus');\n"
        "  st.innerText = 'Saving...'; st.style.color='blue';\n"
        "  try {\n"
        "    const res = await fetch('/config', {method:'POST', headers:{'Content-Type':'text/plain'}, body: lat+','+lon+','+mode});\n"
        "    st.innerText = await res.text();\n"
        "    st.style.color = res.ok ? 'green' : 'red';\n"
        "  } catch(err) { st.innerText = 'Error: ' + err; st.style.color='red'; }\n"
        "});\n");

    // 实例管理 JS（使用 ?id= 方式）
    SEND_CHUNK(
        "async function loadInstances() {\n"
        "  try {\n"
        "    const res = await fetch('/api/instances');\n"
        "    if (!res.ok) throw new Error('HTTP '+res.status);\n"
        "    const data = await res.json();\n"
        "    const container = document.getElementById('instances-list');\n"
        "    container.innerHTML = '';\n"
        "    if (data.length === 0) { container.innerHTML = '<p>No instances. Add one below.</p>'; return; }\n"
        "    data.forEach(inst => {\n"
        "      const card = document.createElement('div');\n"
        "      card.className = 'instance-card';\n"
        "      card.dataset.id = inst.id;\n"
        "      card.innerHTML = `\n"
        "        <h4>Instance ${inst.id} (${inst.active ? '🟢 Active' : '🔴 Stopped'})</h4>\n"
        "        <div style=\"display:grid;grid-template-columns:1fr 1fr;gap:10px;\">\n"
        "          <div><label>Standard</label><select class=\"std-select\">\n"
        "            <option value=\"0\" ${inst.standard==0?'selected':''}>GB42590</option>\n"
        "            <option value=\"1\" ${inst.standard==1?'selected':''}>GB46750</option>\n"
        "            <option value=\"2\" ${inst.standard==2?'selected':''}>ASTM</option>\n"
        "          </select></div>\n"
        "          <div><label>UAS ID</label><input class=\"uas-id\" value=\"${inst.uas_id}\" maxlength=\"20\"></div>\n"
        "          <div><label>Latitude</label><input class=\"lat\" type=\"number\" step=\"0.000001\" value=\"${inst.latitude}\"></div>\n"
        "          <div><label>Longitude</label><input class=\"lon\" type=\"number\" step=\"0.000001\" value=\"${inst.longitude}\"></div>\n"
        "          <div><label>Altitude (MSL)</label><input class=\"alt\" type=\"number\" step=\"0.5\" value=\"${inst.altitude_msl}\"></div>\n"
        "          <div><label>Flight Mode</label><select class=\"mode-select\">\n"
        "            <option value=\"0\" ${inst.flight_mode==0?'selected':''}>Circle</option>\n"
        "            <option value=\"1\" ${inst.flight_mode==1?'selected':''}>PingPong</option>\n"
        "            <option value=\"2\" ${inst.flight_mode==2?'selected':''}>S-Search</option>\n"
        "          </select></div>\n"
        "        </div>\n"
        "        <div style=\"margin-top:10px;\">\n"
        "          <button class=\"btn-success start-btn\" ${inst.active?'disabled':''}>Start</button>\n"
        "          <button class=\"btn-warning stop-btn\" ${!inst.active?'disabled':''}>Stop</button>\n"
        "          <button class=\"btn-primary save-btn\">Save</button>\n"
        "          <button class=\"btn-danger delete-btn\">Delete</button>\n"
        "        </div>\n"
        "      `;\n"
        "      container.appendChild(card);\n"
        "    });\n"
        "    document.querySelectorAll('.start-btn').forEach(btn => {\n"
        "      btn.addEventListener('click', async function() {\n"
        "        const id = this.closest('.instance-card').dataset.id;\n"
        "        const res = await fetch(`/api/instance/start?id=${id}`, {method:'POST'});\n"
        "        if (res.ok) loadInstances(); else alert('Failed');\n"
        "      });\n"
        "    });\n"
        "    document.querySelectorAll('.stop-btn').forEach(btn => {\n"
        "      btn.addEventListener('click', async function() {\n"
        "        const id = this.closest('.instance-card').dataset.id;\n"
        "        const res = await fetch(`/api/instance/stop?id=${id}`, {method:'POST'});\n"
        "        if (res.ok) loadInstances(); else alert('Failed');\n"
        "      });\n"
        "    });\n"
        "    document.querySelectorAll('.delete-btn').forEach(btn => {\n"
        "      btn.addEventListener('click', async function() {\n"
        "        if (!confirm('Delete instance?')) return;\n"
        "        const id = this.closest('.instance-card').dataset.id;\n"
        "        const res = await fetch(`/api/instance?id=${id}`, {method:'DELETE'});\n"
        "        if (res.ok) loadInstances(); else alert('Failed');\n"
        "      });\n"
        "    });\n"
        "    document.querySelectorAll('.save-btn').forEach(btn => {\n"
        "      btn.addEventListener('click', async function() {\n"
        "        const card = this.closest('.instance-card');\n"
        "        const id = card.dataset.id;\n"
        "        const data = {\n"
        "          uas_id: card.querySelector('.uas-id').value,\n"
        "          latitude: parseFloat(card.querySelector('.lat').value),\n"
        "          longitude: parseFloat(card.querySelector('.lon').value),\n"
        "          altitude_msl: parseFloat(card.querySelector('.alt').value),\n"
        "          altitude_agl: parseFloat(card.querySelector('.alt').value),\n"
        "          flight_mode: parseInt(card.querySelector('.mode-select').value)\n"
        "        };\n"
        "        const res = await fetch(`/api/instance?id=${id}`, {\n"
        "          method: 'PUT',\n"
        "          headers: {'Content-Type':'application/json'},\n"
        "          body: JSON.stringify(data)\n"
        "        });\n"
        "        if (res.ok) loadInstances(); else alert('Failed');\n"
        "      });\n"
        "    });\n"
        "  } catch(err) {\n"
        "    document.getElementById('instances-list').innerHTML = '<p>Error loading instances: '+err.message+'</p>';\n"
        "  }\n"
        "}\n"
        "document.getElementById('add-instance').addEventListener('click', async function() {\n"
        "  const data = {standard:0, uas_id:'ESP32-DRONE', latitude:23.14287, longitude:113.26026, altitude_msl:50, flight_mode:0};\n"
        "  const res = await fetch('/api/instance', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(data)});\n"
        "  if (res.ok) loadInstances(); else alert('Failed');\n"
        "});\n"
        "loadInstances();\n");

    // OTA JS
    SEND_CHUNK("document.getElementById('otaForm').addEventListener('submit', async function(e) {\n"
        "  e.preventDefault();\n"
        "  const file = document.getElementById('firmwareFile').files[0];\n"
        "  if (!file) return;\n"
        "  const st = document.getElementById('otaStatus');\n"
        "  const btn = document.getElementById('otaBtn');\n"
        "  st.innerText = 'Uploading ' + file.name + '...'; st.style.color='blue'; btn.disabled=true;\n"
        "  try {\n"
        "    const res = await fetch('/ota', {method:'POST', headers:{'Content-Type':'application/octet-stream'}, body:file});\n"
        "    st.innerText = await res.text();\n"
        "    st.style.color = res.ok ? 'green' : 'red';\n"
        "    if(!res.ok) btn.disabled=false;\n"
        "  } catch(err) { st.innerText = 'Error: ' + err; st.style.color='red'; btn.disabled=false; }\n"
        "});\n");

    SEND_CHUNK("</script></body></html>");
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
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

    httpd_uri_t root_uri = { .uri = "/", .method = HTTP_GET, .handler = root_get_handler };
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