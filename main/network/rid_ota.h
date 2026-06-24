#ifndef RID_OTA_H
#define RID_OTA_H

#include "esp_err.h"
#include <stdint.h>
#include <stddef.h>


typedef struct {
    char label[16];            // 分区标签
    bool active;               // 是否当前运行分区
    uint32_t size;             // 分区大小（字节）
    uint32_t image_size;       // 实际固件大小（如果存在）
    char version[32];          // 固件版本（从描述符读取）
} rid_ota_partition_info_t;


// 传统 URL OTA (保持不变)
esp_err_t rid_ota_perform(const char *ota_url);

// 流式 OTA API (保持不变)
typedef void* rid_ota_handle_t;
esp_err_t rid_ota_begin(rid_ota_handle_t *out_handle);
esp_err_t rid_ota_write(rid_ota_handle_t handle, const uint8_t *data, size_t size);
esp_err_t rid_ota_end(rid_ota_handle_t handle);

// 新增：结束 OTA 但不切换启动分区，用于手动控制
esp_err_t rid_ota_end_no_switch(rid_ota_handle_t handle);

// 获取分区信息
esp_err_t rid_ota_get_running_partition(char *label, size_t len);
esp_err_t rid_ota_get_next_partition(char *label, size_t len);

// 设置下次启动分区
esp_err_t rid_ota_set_boot_partition(const char *label);

// 重启设备
esp_err_t rid_ota_reboot(void);

// 获取上次上传的固件信息（在上传后记录）
esp_err_t rid_ota_get_uploaded_info(char *partition, size_t p_len,
                                     char *version, size_t v_len,
                                     char *time, size_t t_len,  // 新增
                                     uint32_t *size);

// 确认 OTA 成功（保留）
esp_err_t rid_ota_confirm(void);
esp_err_t rid_ota_auto_confirm(void);

#endif // RID_OTA_H