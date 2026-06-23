#ifndef RID_API_H
#define RID_API_H

#include "esp_http_server.h"

esp_err_t instances_get_handler(httpd_req_t *req);
esp_err_t instance_post_handler(httpd_req_t *req);
esp_err_t instance_put_handler(httpd_req_t *req);
esp_err_t instance_delete_handler(httpd_req_t *req);
esp_err_t instance_start_handler(httpd_req_t *req);
esp_err_t instance_stop_handler(httpd_req_t *req);
#endif