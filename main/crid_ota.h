#ifndef CRID_OTA_H
#define CRID_OTA_H

#include "esp_err.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 传统的基于 URL 的 OTA 更新 (供 CLI 等使用)
 * @param ota_url 固件下载地址
 * @return esp_err_t 
 */
esp_err_t crid_ota_perform(const char *ota_url);

// ==========================================
// 以下为新增加的流式 OTA API (供 Web 上传使用)
// ==========================================

// 不透明句柄，用于管理 OTA 会话状态
typedef void* crid_ota_handle_t;

/**
 * @brief 初始化 OTA 会话并获取下一个更新分区
 * @param out_handle 输出的 OTA 句柄
 * @return esp_err_t 
 */
esp_err_t crid_ota_begin(crid_ota_handle_t *out_handle);

/**
 * @brief 向 OTA 分区写入数据块
 * @param handle OTA 句柄
 * @param data 数据指针
 * @param size 数据大小
 * @return esp_err_t 
 */
esp_err_t crid_ota_write(crid_ota_handle_t handle, const uint8_t *data, size_t size);

/**
 * @brief 结束 OTA 会话，校验镜像并设置为启动分区
 * @param handle OTA 句柄
 * @return esp_err_t 
 */
esp_err_t crid_ota_end(crid_ota_handle_t handle);

#ifdef __cplusplus
}
#endif
#endif // CRID_OTA_H