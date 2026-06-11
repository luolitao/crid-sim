#ifndef CRID_OTA_H
#define CRID_OTA_H

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t crid_ota_perform(const char *ota_url);

#ifdef __cplusplus
}
#endif

#endif // CRID_OTA_H
