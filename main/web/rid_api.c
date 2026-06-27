#include "cJSON.h"
#include "esp_log.h"
#include "rid_api.h"
#include "rid_manager.h"
#include "rid_config.h"
#include "rid_auth.h"
#include <string.h>

static const char *TAG = "RID_API";

// ==================== 辅助：从 URL 查询字符串提取 id ====================
static bool get_id_from_query(httpd_req_t *req, uint32_t *id) {
    char query[64];
    size_t qlen = sizeof(query);
    if (httpd_req_get_url_query_str(req, query, qlen) != ESP_OK) {
        return false;
    }
    char id_str[16];
    if (httpd_query_key_value(query, "id", id_str, sizeof(id_str)) != ESP_OK) {
        return false;
    }
    *id = (uint32_t)atoi(id_str);
    return true;
}

// ==================== 实例转 JSON 回调 ====================
static void instance_to_json_cb(drone_instance_t *inst, void *ctx) {
    cJSON *array = (cJSON*)ctx;
    cJSON *obj = cJSON_CreateObject();
    if (!obj) return;

    // 基础字段
    cJSON_AddNumberToObject(obj, "id", (double)inst->id);
    cJSON_AddNumberToObject(obj, "standard", inst->standard);
    cJSON_AddStringToObject(obj, "uas_id", inst->config.uas_id);
    cJSON_AddNumberToObject(obj, "latitude", inst->config.latitude);
    cJSON_AddNumberToObject(obj, "longitude", inst->config.longitude);
    cJSON_AddNumberToObject(obj, "altitude_msl", inst->config.altitude_msl);
    cJSON_AddNumberToObject(obj, "altitude_agl", inst->config.altitude_agl);
    cJSON_AddNumberToObject(obj, "speed_horizontal", inst->config.speed_horizontal);
    cJSON_AddNumberToObject(obj, "speed_vertical", inst->config.speed_vertical);
    cJSON_AddNumberToObject(obj, "heading", inst->config.heading);
    cJSON_AddNumberToObject(obj, "flight_mode", inst->config.flight_mode);
    cJSON_AddBoolToObject(obj, "active", inst->active);

    // GB42590 / ASTM 通用字段
    cJSON_AddNumberToObject(obj, "id_type", inst->config.id_type);
    cJSON_AddNumberToObject(obj, "ua_type", inst->config.ua_type);
    cJSON_AddNumberToObject(obj, "status", inst->config.status);
    cJSON_AddNumberToObject(obj, "height_type", inst->config.height_type);
    cJSON_AddNumberToObject(obj, "h_acc", inst->config.h_acc);
    cJSON_AddNumberToObject(obj, "v_acc", inst->config.v_acc);
    cJSON_AddNumberToObject(obj, "spd_acc", inst->config.spd_acc);
    cJSON_AddNumberToObject(obj, "ts_acc", inst->config.ts_acc);

    // GB46750 特有字段
    cJSON_AddStringToObject(obj, "reg_mark", inst->config.reg_mark);
    cJSON_AddNumberToObject(obj, "op_category", inst->config.op_category);
    cJSON_AddNumberToObject(obj, "ua_class", inst->config.ua_class);
    cJSON_AddNumberToObject(obj, "gcs_pos_type", inst->config.gcs_pos_type);
    cJSON_AddNumberToObject(obj, "coord_type", inst->config.coord_type);

    cJSON_AddItemToArray(array, obj);
}

// ==================== GET /api/instances ====================
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

// 辅助校验函数（静态）
static bool validate_config(const rid_config_t *cfg) {
    // 经纬度
    if (cfg->latitude < -90.0f || cfg->latitude > 90.0f) {
        ESP_LOGE(TAG, "Invalid latitude: %.6f", cfg->latitude);
        return false;
    }
    if (cfg->longitude < -180.0f || cfg->longitude > 180.0f) {
        ESP_LOGE(TAG, "Invalid longitude: %.6f", cfg->longitude);
        return false;
    }
    // 高度
    if (cfg->altitude_msl < -1000.0f || cfg->altitude_msl > 31767.5f) {
        ESP_LOGE(TAG, "Invalid altitude_msl: %.2f", cfg->altitude_msl);
        return false;
    }
    if (cfg->altitude_agl < -1000.0f || cfg->altitude_agl > 31767.5f) {
        ESP_LOGE(TAG, "Invalid altitude_agl: %.2f", cfg->altitude_agl);
        return false;
    }
    // 速度
    if (cfg->speed_horizontal < 0.0f || cfg->speed_horizontal > 254.25f) {
        ESP_LOGE(TAG, "Invalid speed_horizontal: %.2f", cfg->speed_horizontal);
        return false;
    }
    if (cfg->speed_vertical < -62.0f || cfg->speed_vertical > 62.0f) {
        ESP_LOGE(TAG, "Invalid speed_vertical: %.2f", cfg->speed_vertical);
        return false;
    }
    // 航向
    if (cfg->heading < 0.0f || cfg->heading >= 360.0f) {
        ESP_LOGE(TAG, "Invalid heading: %.1f", cfg->heading);
        return false;
    }
    // 枚举字段范围（可根据标准枚举值校验，这里简单判断范围）
    if (cfg->id_type > 4) return false;
    if (cfg->ua_type > 15) return false;
    if (cfg->status > 4) return false;
    if (cfg->height_type > 1) return false;
    if (cfg->h_acc > 12) return false;
    if (cfg->v_acc > 6) return false;
    if (cfg->spd_acc > 4) return false;
    if (cfg->ts_acc > 8) return false;
    // GB46750 字段
    if (cfg->op_category > 3) return false;
    if (cfg->ua_class > 4) return false;
    if (cfg->gcs_pos_type > 1) return false;
    if (cfg->coord_type > 1) return false;
    // 其他字段不强制校验
    return true;
}

// ==================== POST /api/instance ====================
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
        return httpd_resp_sendstr(req, "{\"error\":\"Empty body\"}");
    }
    buf[len] = '\0';

    cJSON *json = cJSON_Parse(buf);
    if (!json) {
        httpd_resp_set_status(req, "400 Bad Request");
        return httpd_resp_sendstr(req, "{\"error\":\"Invalid JSON\"}");
    }

    // 解析标准
    cJSON *std_item = cJSON_GetObjectItem(json, "standard");
    if (!std_item || !cJSON_IsNumber(std_item)) {
        cJSON_Delete(json);
        httpd_resp_set_status(req, "400 Bad Request");
        return httpd_resp_sendstr(req, "{\"error\":\"Missing or invalid standard\"}");
    }
    rid_standard_t standard = (rid_standard_t)std_item->valueint;

    // 创建配置结构体并初始化默认值
    rid_config_t cfg;
    rid_config_init_default(&cfg);

    // 解析通用字段（必填）
    cJSON *item;
    if ((item = cJSON_GetObjectItem(json, "uas_id"))) {
        strncpy(cfg.uas_id, item->valuestring, sizeof(cfg.uas_id) - 1);
        cfg.uas_id[sizeof(cfg.uas_id) - 1] = '\0';
    }
    if ((item = cJSON_GetObjectItem(json, "latitude"))) cfg.latitude = item->valuedouble;
    if ((item = cJSON_GetObjectItem(json, "longitude"))) cfg.longitude = item->valuedouble;
    if ((item = cJSON_GetObjectItem(json, "altitude_msl"))) cfg.altitude_msl = item->valuedouble;
    if ((item = cJSON_GetObjectItem(json, "altitude_agl"))) cfg.altitude_agl = item->valuedouble;
    if ((item = cJSON_GetObjectItem(json, "speed_horizontal"))) cfg.speed_horizontal = item->valuedouble;
    if ((item = cJSON_GetObjectItem(json, "speed_vertical"))) cfg.speed_vertical = item->valuedouble;
    if ((item = cJSON_GetObjectItem(json, "heading"))) cfg.heading = item->valuedouble;
    if ((item = cJSON_GetObjectItem(json, "flight_mode"))) cfg.flight_mode = item->valueint;

    // 解析标准相关字段
    if (standard == RID_STANDARD_GB46750) {
        // GB46750 特有
        if ((item = cJSON_GetObjectItem(json, "reg_mark"))) {
            strncpy(cfg.reg_mark, item->valuestring, sizeof(cfg.reg_mark) - 1);
            cfg.reg_mark[sizeof(cfg.reg_mark) - 1] = '\0';
        }
        if ((item = cJSON_GetObjectItem(json, "op_category"))) cfg.op_category = item->valueint;
        if ((item = cJSON_GetObjectItem(json, "ua_class"))) cfg.ua_class = item->valueint;
        if ((item = cJSON_GetObjectItem(json, "gcs_pos_type"))) cfg.gcs_pos_type = item->valueint;
        if ((item = cJSON_GetObjectItem(json, "coord_type"))) cfg.coord_type = item->valueint;
        if ((item = cJSON_GetObjectItem(json, "h_acc"))) cfg.h_acc = item->valueint;
        if ((item = cJSON_GetObjectItem(json, "v_acc"))) cfg.v_acc = item->valueint;
        if ((item = cJSON_GetObjectItem(json, "spd_acc"))) cfg.spd_acc = item->valueint;
        if ((item = cJSON_GetObjectItem(json, "ts_acc"))) cfg.ts_acc = item->valueint;
    } else {
        // GB42590 / ASTM 字段
        if ((item = cJSON_GetObjectItem(json, "id_type"))) cfg.id_type = item->valueint;
        if ((item = cJSON_GetObjectItem(json, "ua_type"))) cfg.ua_type = item->valueint;
        if ((item = cJSON_GetObjectItem(json, "status"))) cfg.status = item->valueint;
        if ((item = cJSON_GetObjectItem(json, "height_type"))) cfg.height_type = item->valueint;
        if ((item = cJSON_GetObjectItem(json, "h_acc"))) cfg.h_acc = item->valueint;
        if ((item = cJSON_GetObjectItem(json, "v_acc"))) cfg.v_acc = item->valueint;
        if ((item = cJSON_GetObjectItem(json, "spd_acc"))) cfg.spd_acc = item->valueint;
        if ((item = cJSON_GetObjectItem(json, "ts_acc"))) cfg.ts_acc = item->valueint;
    }

    // 在 instance_post_handler 中，填充完 cfg 后
    if (!validate_config(&cfg)) {
        cJSON_Delete(json);
        httpd_resp_set_status(req, "400 Bad Request");
        return httpd_resp_sendstr(req, "{\"error\":\"Invalid parameter values\"}");
    }

    // 创建实例
    uint32_t id;
    esp_err_t ret = rid_manager_create(standard, &cfg, &id);
    cJSON_Delete(json);

    if (ret != ESP_OK) {
        const char *err_msg = (ret == ESP_ERR_INVALID_ARG) ? "UAS ID already exists" : "Create failed";
        httpd_resp_set_status(req, "500 Internal Server Error");
        char resp[128];
        snprintf(resp, sizeof(resp), "{\"error\":\"%s\"}", err_msg);
        httpd_resp_set_type(req, "application/json");
        return httpd_resp_sendstr(req, resp);
    }

    // 保存到 NVS
    rid_manager_save_all();

    httpd_resp_set_status(req, "201 Created");
    httpd_resp_set_type(req, "application/json");
    char resp[32];
    snprintf(resp, sizeof(resp), "{\"id\":%u}", (unsigned)id);
    return httpd_resp_sendstr(req, resp);
}

// ==================== PUT /api/instance?id=xxx ====================
esp_err_t instance_put_handler(httpd_req_t *req) {
    if (!validate_auth(req)) {
        httpd_resp_set_status(req, "401 Unauthorized");
        httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"C-RID OTA\"");
        return httpd_resp_sendstr(req, "Unauthorized");
    }

    uint32_t id;
    if (!get_id_from_query(req, &id)) {
        httpd_resp_set_status(req, "400 Bad Request");
        return httpd_resp_sendstr(req, "{\"error\":\"Missing or invalid id\"}");
    }

    char buf[512];
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (len <= 0) {
        httpd_resp_set_status(req, "400 Bad Request");
        return httpd_resp_sendstr(req, "{\"error\":\"Empty body\"}");
    }
    buf[len] = '\0';

    cJSON *json = cJSON_Parse(buf);
    if (!json) {
        httpd_resp_set_status(req, "400 Bad Request");
        return httpd_resp_sendstr(req, "{\"error\":\"Invalid JSON\"}");
    }

    // 获取现有配置
    rid_config_t cfg;
    esp_err_t ret = rid_manager_get_config(id, &cfg);
    if (ret != ESP_OK) {
        cJSON_Delete(json);
        httpd_resp_set_status(req, "404 Not Found");
        return httpd_resp_sendstr(req, "{\"error\":\"Instance not found\"}");
    }

    // 解析通用字段
    cJSON *item;
    if ((item = cJSON_GetObjectItem(json, "uas_id"))) {
        strncpy(cfg.uas_id, item->valuestring, sizeof(cfg.uas_id) - 1);
        cfg.uas_id[sizeof(cfg.uas_id) - 1] = '\0';
    }
    if ((item = cJSON_GetObjectItem(json, "latitude"))) cfg.latitude = item->valuedouble;
    if ((item = cJSON_GetObjectItem(json, "longitude"))) cfg.longitude = item->valuedouble;
    if ((item = cJSON_GetObjectItem(json, "altitude_msl"))) cfg.altitude_msl = item->valuedouble;
    if ((item = cJSON_GetObjectItem(json, "altitude_agl"))) cfg.altitude_agl = item->valuedouble;
    if ((item = cJSON_GetObjectItem(json, "speed_horizontal"))) cfg.speed_horizontal = item->valuedouble;
    if ((item = cJSON_GetObjectItem(json, "speed_vertical"))) cfg.speed_vertical = item->valuedouble;
    if ((item = cJSON_GetObjectItem(json, "heading"))) cfg.heading = item->valuedouble;
    if ((item = cJSON_GetObjectItem(json, "flight_mode"))) cfg.flight_mode = item->valueint;

    // 解析标准，并更新 standard 字段（如果提供）
    cJSON *std_item = cJSON_GetObjectItem(json, "standard");
    if (std_item && cJSON_IsNumber(std_item)) {
        rid_standard_t new_std = (rid_standard_t)std_item->valueint;
        ret = rid_manager_update_standard(id, new_std);
        if (ret != ESP_OK) {
            cJSON_Delete(json);
            httpd_resp_set_status(req, "500 Internal Server Error");
            return httpd_resp_sendstr(req, "{\"error\":\"Failed to update standard\"}");
        }
    }

    // 确定当前标准（更新后的）
    rid_standard_t current_std = rid_manager_get_standard(id);
    if (current_std == RID_STANDARD_GB46750) {
        // GB46750 特有
        if ((item = cJSON_GetObjectItem(json, "reg_mark"))) {
            strncpy(cfg.reg_mark, item->valuestring, sizeof(cfg.reg_mark) - 1);
            cfg.reg_mark[sizeof(cfg.reg_mark) - 1] = '\0';
        }
        if ((item = cJSON_GetObjectItem(json, "op_category"))) cfg.op_category = item->valueint;
        if ((item = cJSON_GetObjectItem(json, "ua_class"))) cfg.ua_class = item->valueint;
        if ((item = cJSON_GetObjectItem(json, "gcs_pos_type"))) cfg.gcs_pos_type = item->valueint;
        if ((item = cJSON_GetObjectItem(json, "coord_type"))) cfg.coord_type = item->valueint;
        if ((item = cJSON_GetObjectItem(json, "h_acc"))) cfg.h_acc = item->valueint;
        if ((item = cJSON_GetObjectItem(json, "v_acc"))) cfg.v_acc = item->valueint;
        if ((item = cJSON_GetObjectItem(json, "spd_acc"))) cfg.spd_acc = item->valueint;
        if ((item = cJSON_GetObjectItem(json, "ts_acc"))) cfg.ts_acc = item->valueint;
    } else {
        // GB42590 / ASTM
        if ((item = cJSON_GetObjectItem(json, "id_type"))) cfg.id_type = item->valueint;
        if ((item = cJSON_GetObjectItem(json, "ua_type"))) cfg.ua_type = item->valueint;
        if ((item = cJSON_GetObjectItem(json, "status"))) cfg.status = item->valueint;
        if ((item = cJSON_GetObjectItem(json, "height_type"))) cfg.height_type = item->valueint;
        if ((item = cJSON_GetObjectItem(json, "h_acc"))) cfg.h_acc = item->valueint;
        if ((item = cJSON_GetObjectItem(json, "v_acc"))) cfg.v_acc = item->valueint;
        if ((item = cJSON_GetObjectItem(json, "spd_acc"))) cfg.spd_acc = item->valueint;
        if ((item = cJSON_GetObjectItem(json, "ts_acc"))) cfg.ts_acc = item->valueint;
    }

    // 在 instance_post_handler 中，填充完 cfg 后
    if (!validate_config(&cfg)) {
        cJSON_Delete(json);
        httpd_resp_set_status(req, "400 Bad Request");
        return httpd_resp_sendstr(req, "{\"error\":\"Invalid parameter values\"}");
    }

    // 更新配置
    ret = rid_manager_update_config(id, &cfg);
    cJSON_Delete(json);
    if (ret != ESP_OK) {
        httpd_resp_set_status(req, "500 Internal Server Error");
        return httpd_resp_sendstr(req, "{\"error\":\"Update failed\"}");
    }

    // 保存到 NVS
    rid_manager_save_all();

    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, "{\"status\":\"OK\"}");
}

// ==================== DELETE /api/instance?id=xxx ====================
esp_err_t instance_delete_handler(httpd_req_t *req) {
    if (!validate_auth(req)) {
        httpd_resp_set_status(req, "401 Unauthorized");
        httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"C-RID OTA\"");
        return httpd_resp_sendstr(req, "Unauthorized");
    }

    uint32_t id;
    if (!get_id_from_query(req, &id)) {
        httpd_resp_set_status(req, "400 Bad Request");
        return httpd_resp_sendstr(req, "{\"error\":\"Missing or invalid id\"}");
    }

    esp_err_t ret = rid_manager_delete(id);
    if (ret != ESP_OK) {
        httpd_resp_set_status(req, "404 Not Found");
        return httpd_resp_sendstr(req, "{\"error\":\"Not found\"}");
    }

    rid_manager_save_all();
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, "{\"status\":\"OK\"}");
}

// ==================== POST /api/instance/start?id=xxx ====================
esp_err_t instance_start_handler(httpd_req_t *req) {
    if (!validate_auth(req)) {
        httpd_resp_set_status(req, "401 Unauthorized");
        httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"C-RID OTA\"");
        return httpd_resp_sendstr(req, "Unauthorized");
    }

    uint32_t id;
    if (!get_id_from_query(req, &id)) {
        httpd_resp_set_status(req, "400 Bad Request");
        return httpd_resp_sendstr(req, "{\"error\":\"Missing or invalid id\"}");
    }

    esp_err_t ret = rid_manager_start(id);
    if (ret != ESP_OK) {
        httpd_resp_set_status(req, "404 Not Found");
        return httpd_resp_sendstr(req, "{\"error\":\"Instance not found\"}");
    }

    rid_manager_save_all();
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, "{\"status\":\"OK\"}");
}

// ==================== POST /api/instance/stop?id=xxx ====================
esp_err_t instance_stop_handler(httpd_req_t *req) {
    if (!validate_auth(req)) {
        httpd_resp_set_status(req, "401 Unauthorized");
        httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"C-RID OTA\"");
        return httpd_resp_sendstr(req, "Unauthorized");
    }

    uint32_t id;
    if (!get_id_from_query(req, &id)) {
        httpd_resp_set_status(req, "400 Bad Request");
        return httpd_resp_sendstr(req, "{\"error\":\"Missing or invalid id\"}");
    }

    esp_err_t ret = rid_manager_stop(id);
    if (ret != ESP_OK) {
        httpd_resp_set_status(req, "404 Not Found");
        return httpd_resp_sendstr(req, "{\"error\":\"Instance not found\"}");
    }

    rid_manager_save_all();
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, "{\"status\":\"OK\"}");
}

