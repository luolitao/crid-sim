#ifndef RID_STATIC_H
#define RID_STATIC_H

#include "esp_http_server.h"

esp_err_t serve_index_html(httpd_req_t *req);
esp_err_t serve_config_html(httpd_req_t *req); 
esp_err_t serve_ota_html(httpd_req_t *req); 

#endif