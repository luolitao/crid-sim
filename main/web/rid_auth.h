#ifndef RID_AUTH_H
#define RID_AUTH_H
#include "esp_http_server.h"
#include <stdbool.h>
bool validate_auth(httpd_req_t *req);
#endif