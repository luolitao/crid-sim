#ifndef RID_OTA_H
#define RID_OTA_H

#include "esp_err.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// 传统的 URL OTA
esp_err_t rid_ota_perform(const char *ota_url);

// 流式 OTA API (供 Web 文件上传使用)
typedef void* rid_ota_handle_t;
esp_err_t rid_ota_begin(rid_ota_handle_t *out_handle);
esp_err_t rid_ota_write(rid_ota_handle_t handle, const uint8_t *data, size_t size);
esp_err_t rid_ota_end(rid_ota_handle_t handle);
esp_err_t rid_ota_begin_with_size(rid_ota_handle_t *out_handle, uint32_t image_size);

// 确认 OTA 成功，取消自动回退机制
esp_err_t rid_ota_confirm(void);
esp_err_t rid_ota_auto_confirm(void);  // 自动确认

#ifdef __cplusplus
}
#endif
#endif // RID_OTA_H