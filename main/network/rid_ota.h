#ifndef RID_OTA_H
#define RID_OTA_H

#include "esp_err.h"
#include <stdint.h>
#include <stddef.h>


// 分区信息结构体
typedef struct {
    char label[16];
    char version[32];
    char compile_time[32];
    uint32_t size;
    bool is_running;
    bool is_boot;
    bool is_valid;
} ota_partition_info_t;

/**
 * @brief 获取所有OTA分区信息（ota_0和ota_1）
 * @param infos 指向指针的指针，将被分配数组
 * @param count 返回分区数量
 * @return ESP_OK on success
 */
esp_err_t rid_ota_get_all_partitions(ota_partition_info_t *infos, int *count);

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