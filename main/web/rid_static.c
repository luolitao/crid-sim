#include "rid_static.h"
#include "rid_static_index.h"   // 由 xxd 生成
#include "rid_static_config.h"   // 由 xxd 生成
#include "rid_static_ota.h"   // 由 xxd 生成

esp_err_t serve_index_html(httpd_req_t *req) {
    httpd_resp_set_type(req, "text/html");
    // 使用 xxd 生成的数组
    extern unsigned char webui_index_html[];
    extern unsigned int webui_index_html_len;
    return httpd_resp_send(req, (const char *)webui_index_html, webui_index_html_len);
}

esp_err_t serve_config_html(httpd_req_t *req) {
    httpd_resp_set_type(req, "text/html");
    // 使用 xxd 生成的数组
    extern unsigned char webui_config_html[];
    extern unsigned int webui_config_html_len;
    return httpd_resp_send(req, (const char *)webui_config_html, webui_config_html_len);
}

esp_err_t serve_ota_html(httpd_req_t *req) {
    httpd_resp_set_type(req, "text/html");
    // 使用 xxd 生成的数组
    extern unsigned char webui_ota_html[];
    extern unsigned int webui_ota_html_len;
    return httpd_resp_send(req, (const char *)webui_ota_html, webui_ota_html_len);
}