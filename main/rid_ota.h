#ifndef CRID_OTA_H
#define CRID_OTA_H

#include "esp_err.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// 传统的 URL OTA
esp_err_t crid_ota_perform(const char *ota_url);

// 流式 OTA API (供 Web 文件上传使用)
typedef void* crid_ota_handle_t;
esp_err_t crid_ota_begin(crid_ota_handle_t *out_handle);
esp_err_t crid_ota_write(crid_ota_handle_t handle, const uint8_t *data, size_t size);
esp_err_t crid_ota_end(crid_ota_handle_t handle);

// 确认 OTA 成功，取消自动回退机制
esp_err_t crid_ota_confirm(void);

#ifdef __cplusplus
}
#endif
#endif // CRID_OTA_H