#include "cJSON.h"

#include "rid_api.h"
#include "rid_manager.h"
#include "rid_config.h"
#include "rid_auth.h"




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

// 将原 instances_get_handler 等函数移到此处，并包含必要的头文件
// 注意：instance_to_json_cb 可放在此文件作为静态函数
// ==================== API 回调函数（纯 C） ====================
void instance_to_json_cb(drone_instance_t *inst, void *ctx) {
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
esp_err_t instances_get_handler(httpd_req_t *req) {
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
esp_err_t instance_post_handler(httpd_req_t *req) {
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
esp_err_t instance_put_handler(httpd_req_t *req) {
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
esp_err_t instance_delete_handler(httpd_req_t *req) {
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
esp_err_t instance_start_handler(httpd_req_t *req) {
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
esp_err_t instance_stop_handler(httpd_req_t *req) {
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

