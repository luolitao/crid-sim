#include <string.h>
#include <stdlib.h>
#include "sdkconfig.h"
#include "esp_err.h"
#include "esp_http_client.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_app_desc.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "esp_system.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_image_format.h"

#include "rid_ota.h"

#ifndef CONFIG_RID_OTA_BUF_SIZE
#define CONFIG_RID_OTA_BUF_SIZE 4096
#endif

#ifndef CONFIG_RID_OTA_TIMEOUT_MS
#define CONFIG_RID_OTA_TIMEOUT_MS 30000
#endif

static const char *TAG = "RID_OTA";
static SemaphoreHandle_t s_ota_mutex = NULL;
// 保存上传的固件信息
static char s_uploaded_partition[16] = {0};
static char s_uploaded_version[64] = {0};
static char s_uploaded_time[64] = {0};     // 固件编译时间
static char s_uploaded_upload_time[64] = {0}; // 上传完成时间
static uint32_t s_uploaded_size = 0;


// ================= 流式 OTA 核心实现 =================
typedef struct {
    esp_ota_handle_t ota_handle;
    const esp_partition_t *update_partition;
    size_t total_written;
} rid_ota_ctx_t;

typedef esp_err_t (*ota_read_callback_t)(void *ctx, uint8_t *buf, size_t *len);

static esp_err_t write_ota_stream(rid_ota_handle_t handle, ota_read_callback_t read_cb, void *ctx) {
    uint8_t *buffer = malloc(CONFIG_RID_OTA_BUF_SIZE);
    if (!buffer) return ESP_ERR_NO_MEM;
    esp_err_t ret = ESP_OK;
    size_t len;
    while (1) {
        ret = read_cb(ctx, buffer, &len);
        if (ret != ESP_OK) break;
        if (len == 0) break;  // EOF
        ret = rid_ota_write(handle, buffer, len);
        if (ret != ESP_OK) break;
    }
    free(buffer);
    return ret;
}

static esp_err_t http_read_callback(void *ctx, uint8_t *buf, size_t *len) {
    esp_http_client_handle_t client = (esp_http_client_handle_t)ctx;
    int ret = esp_http_client_read(client, (char*)buf, CONFIG_RID_OTA_BUF_SIZE);
    if (ret < 0) return ESP_FAIL;
    *len = ret;
    return ESP_OK;
}

// ------------------- 公共内部辅助：获取锁和分区 -------------------
static esp_err_t ota_begin_internal(rid_ota_handle_t *out_handle, uint32_t image_size) {
    if (out_handle == NULL) return ESP_ERR_INVALID_ARG;
    if (s_ota_mutex == NULL) {
        s_ota_mutex = xSemaphoreCreateMutex();
        if (s_ota_mutex == NULL) return ESP_ERR_NO_MEM;
    }
    if (xSemaphoreTake(s_ota_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
        return ESP_ERR_INVALID_STATE;  // 已有 OTA 进行中
    }

    const esp_partition_t *update_partition = esp_ota_get_next_update_partition(NULL);
    if (update_partition == NULL) {
        xSemaphoreGive(s_ota_mutex);
        return ESP_FAIL;
    }

    rid_ota_ctx_t *ctx = (rid_ota_ctx_t *)malloc(sizeof(rid_ota_ctx_t));
    if (ctx == NULL) {
        xSemaphoreGive(s_ota_mutex);
        return ESP_ERR_NO_MEM;
    }

    ctx->update_partition = update_partition;
    ctx->total_written = 0;

    esp_err_t ret = esp_ota_begin(update_partition, image_size, &ctx->ota_handle);
    if (ret != ESP_OK) {
        free(ctx);
        xSemaphoreGive(s_ota_mutex);
        return ret;
    }

    *out_handle = (rid_ota_handle_t)ctx;
    return ESP_OK;
}

esp_err_t rid_ota_begin_with_size(rid_ota_handle_t *out_handle, uint32_t image_size) {
    return ota_begin_internal(out_handle, image_size);
}

esp_err_t rid_ota_begin(rid_ota_handle_t *out_handle) {
    if (out_handle == NULL) {
        ESP_LOGE(TAG, "Invalid out_handle");
        return ESP_ERR_INVALID_ARG;
    }
    if (s_ota_mutex == NULL) {
        s_ota_mutex = xSemaphoreCreateMutex();
        if (s_ota_mutex == NULL) {
            ESP_LOGE(TAG, "Failed to create mutex");
            return ESP_ERR_NO_MEM;
        }
    }
    if (xSemaphoreTake(s_ota_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
        ESP_LOGE(TAG, "OTA mutex timeout - another OTA in progress?");
        return ESP_ERR_INVALID_STATE;
    }

    const esp_partition_t *update_partition = esp_ota_get_next_update_partition(NULL);
    if (update_partition == NULL) {
        ESP_LOGE(TAG, "No OTA partition found! Check partition table.");
        xSemaphoreGive(s_ota_mutex);
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "OTA target partition: %s, offset: 0x%08x, size: %d",
             update_partition->label, update_partition->address, update_partition->size);

    rid_ota_ctx_t *ctx = (rid_ota_ctx_t *)malloc(sizeof(rid_ota_ctx_t));
    if (ctx == NULL) {
        ESP_LOGE(TAG, "Failed to allocate OTA context");
        xSemaphoreGive(s_ota_mutex);
        return ESP_ERR_NO_MEM;
    }
    ctx->update_partition = update_partition;
    ctx->total_written = 0;

    esp_err_t ret = esp_ota_begin(update_partition, OTA_SIZE_UNKNOWN, &ctx->ota_handle);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_begin failed: %s", esp_err_to_name(ret));
        free(ctx);
        xSemaphoreGive(s_ota_mutex);
        return ret;
    }

    *out_handle = (rid_ota_handle_t)ctx;
    ESP_LOGI(TAG, "OTA session started successfully");
    return ESP_OK;
}

static void abort_ota_session(rid_ota_ctx_t *ctx) {
    if (ctx) {
        esp_ota_abort(ctx->ota_handle);
        free(ctx);
    }
    if (s_ota_mutex) xSemaphoreGive(s_ota_mutex);
}

esp_err_t rid_ota_write(rid_ota_handle_t handle, const uint8_t *data, size_t size) {
    if (handle == NULL || data == NULL || size == 0) return ESP_ERR_INVALID_ARG;
    rid_ota_ctx_t *ctx = (rid_ota_ctx_t *)handle;
    esp_err_t ret = esp_ota_write(ctx->ota_handle, data, size);
    if (ret == ESP_OK) {
        ctx->total_written += size;
    } else {
        abort_ota_session(ctx);
    }
    return ret;
}

esp_err_t rid_ota_end(rid_ota_handle_t handle) {
    if (handle == NULL) return ESP_ERR_INVALID_ARG;
    rid_ota_ctx_t *ctx = (rid_ota_ctx_t *)handle;
    
    esp_err_t ret = esp_ota_end(ctx->ota_handle);
    if (ret != ESP_OK) {
        esp_ota_abort(ctx->ota_handle);
        free(ctx);
        if (s_ota_mutex) xSemaphoreGive(s_ota_mutex);
        return ret;
    }

    ret = esp_ota_set_boot_partition(ctx->update_partition);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set boot partition, OTA may be incomplete");
        free(ctx);
        if (s_ota_mutex) xSemaphoreGive(s_ota_mutex);
        return ret;
    }
    
    ESP_LOGI(TAG, "OTA image written successfully (%d bytes)", ctx->total_written);
    free(ctx);
    if (s_ota_mutex) xSemaphoreGive(s_ota_mutex);
    return ESP_OK;
}

// ================= 确认 OTA 成功 (取消回退) =================
esp_err_t rid_ota_confirm(void) {
    nvs_handle_t nvs;
    uint8_t pending = 0;
    
    if (nvs_open("ridd", NVS_READWRITE, &nvs) == ESP_OK) {
        nvs_get_u8(nvs, "ota_pending", &pending);
        if (pending == 1) {
            esp_err_t ret = esp_ota_mark_app_valid_cancel_rollback();
            if (ret == ESP_OK) {
                nvs_set_u8(nvs, "ota_pending", 0);
                nvs_commit(nvs);
                ESP_LOGI(TAG, "OTA confirmed valid. Rollback cancelled.");
                nvs_close(nvs);
                return ESP_OK;
            }
        }
        nvs_close(nvs);
    }
    return ESP_ERR_INVALID_STATE;
}

// 自动确认（启动时调用），返回 ESP_OK 表示已确认或无需确认
esp_err_t rid_ota_auto_confirm(void) {
    nvs_handle_t nvs;
    uint8_t pending = 0;
    if (nvs_open("ridd", NVS_READWRITE, &nvs) == ESP_OK) {
        nvs_get_u8(nvs, "ota_pending", &pending);
        if (pending == 1) {
            esp_err_t ret = esp_ota_mark_app_valid_cancel_rollback();
            if (ret == ESP_OK) {
                nvs_set_u8(nvs, "ota_pending", 0);
                nvs_commit(nvs);
                ESP_LOGI(TAG, "OTA auto-confirmed at boot. Rollback disabled.");
                nvs_close(nvs);
                return ESP_OK;
            }
        }
        nvs_close(nvs);
    }
    return ESP_ERR_INVALID_STATE;  // 无待确认项
}

// ================= 传统的 URL OTA 实现 =================
esp_err_t rid_ota_perform(const char *ota_url) {
    if (ota_url == NULL || ota_url[0] == '\0') return ESP_ERR_INVALID_ARG;
    ESP_LOGI(TAG, "Starting OTA from %s", ota_url);

    esp_http_client_config_t http_config = {
        .url = ota_url,
        .timeout_ms = CONFIG_RID_OTA_TIMEOUT_MS,
        .keep_alive_enable = true
    };
    esp_http_client_handle_t client = esp_http_client_init(&http_config);
    if (client == NULL) return ESP_FAIL;

    esp_err_t ret = esp_http_client_open(client, 0);
    if (ret != ESP_OK) {
        esp_http_client_cleanup(client);
        return ret;
    }
    esp_http_client_fetch_headers(client);

    int content_length = esp_http_client_get_content_length(client);
    rid_ota_handle_t ota_handle = NULL;
    if (content_length > 0) {
        ret = rid_ota_begin_with_size(&ota_handle, content_length);
    } else {
        ret = rid_ota_begin(&ota_handle);
    }
    if (ret != ESP_OK) {
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        return ret;
    }

    ret = write_ota_stream(ota_handle, http_read_callback, client);
    esp_http_client_close(client);
    esp_http_client_cleanup(client);

    if (ret != ESP_OK) {
        // write_ota_stream 内部若失败，rid_ota_write 已调用 abort_ota_session 释放锁和 ctx
        ESP_LOGE(TAG, "OTA write failed, aborting");
        return ret;
    }

    ret = rid_ota_end(ota_handle);
    if (ret == ESP_OK) {
        // 设置待确认标志，启用自动回退保护
        nvs_handle_t nvs;
        if (nvs_open("ridd", NVS_READWRITE, &nvs) == ESP_OK) {
            nvs_set_u8(nvs, "ota_pending", 1);
            nvs_commit(nvs);
            nvs_close(nvs);
        }
        ESP_LOGI(TAG, "OTA succeeded, rebooting now...");
        esp_restart();
    }
    return ret;
}


// 获取当前运行分区名
esp_err_t rid_ota_get_running_partition(char *label, size_t len) {
    const esp_partition_t *part = esp_ota_get_running_partition();
    if (!part) return ESP_ERR_NOT_FOUND;
    strncpy(label, part->label, len - 1);
    label[len - 1] = '\0';
    return ESP_OK;
}

// 获取下一个可用于升级的分区名
esp_err_t rid_ota_get_next_partition(char *label, size_t len) {
    const esp_partition_t *part = esp_ota_get_next_update_partition(NULL);
    if (!part) return ESP_ERR_NOT_FOUND;
    strncpy(label, part->label, len - 1);
    label[len - 1] = '\0';
    return ESP_OK;
}

// 结束 OTA 但不切换启动分区，并记录上传信息
esp_err_t rid_ota_end_no_switch(rid_ota_handle_t handle) {
    if (handle == NULL) return ESP_ERR_INVALID_ARG;
    rid_ota_ctx_t *ctx = (rid_ota_ctx_t *)handle;

    esp_err_t ret = esp_ota_end(ctx->ota_handle);
    if (ret != ESP_OK) {
        esp_ota_abort(ctx->ota_handle);
        free(ctx);
        return ret;
    }

    // 记录分区名和写入大小
    strncpy(s_uploaded_partition, ctx->update_partition->label,
            sizeof(s_uploaded_partition) - 1);
    s_uploaded_size = ctx->total_written;

    // 读取固件头部获取编译时间和版本
    esp_app_desc_t app_desc;
    ret = esp_partition_read(ctx->update_partition, 0, &app_desc, sizeof(app_desc));
    if (ret == ESP_OK) {
        strncpy(s_uploaded_version, app_desc.version, sizeof(s_uploaded_version) - 1);
        strncpy(s_uploaded_time, app_desc.time, sizeof(s_uploaded_time) - 1);
    } else {
        strcpy(s_uploaded_version, "Unknown");
        strcpy(s_uploaded_time, "Unknown");
    }

    // 记录上传完成时间
    time_t now;
    time(&now);
    struct tm tm_info;
    localtime_r(&now, &tm_info);
    strftime(s_uploaded_upload_time, sizeof(s_uploaded_upload_time),
             "%Y-%m-%d %H:%M:%S", &tm_info);

    free(ctx);
    ESP_LOGI(TAG, "Uploaded firmware: partition=%s, version=%s, build=%s, uploaded=%s, size=%u",
             s_uploaded_partition, s_uploaded_version, s_uploaded_time,
             s_uploaded_upload_time, s_uploaded_size);
    return ESP_OK;
}

// 设置下次启动分区
esp_err_t rid_ota_set_boot_partition(const char *label) {
    const esp_partition_t *part = esp_partition_find_first(
        ESP_PARTITION_TYPE_APP, ESP_PARTITION_SUBTYPE_ANY, label);
    if (!part) return ESP_ERR_NOT_FOUND;
    esp_err_t ret = esp_ota_set_boot_partition(part);
    if (ret == ESP_OK) {
        ESP_LOGI(TAG, "Set boot partition to %s", label);
    }
    return ret;
}

// 重启设备
esp_err_t rid_ota_reboot(void) {
    ESP_LOGI(TAG, "Rebooting...");
    esp_restart();
    return ESP_OK; // 不会执行到这里
}

// 获取上次上传的信息
esp_err_t rid_ota_get_uploaded_info(char *partition, size_t p_len,
                                     char *version, size_t v_len,
                                     char *time, size_t t_len,
                                     uint32_t *size) {
    if (s_uploaded_partition[0] == 0) {
        return ESP_ERR_NOT_FOUND;
    }
    if (partition) {
        strncpy(partition, s_uploaded_partition, p_len - 1);
        partition[p_len - 1] = '\0';
    }
    if (version) {
        strncpy(version, s_uploaded_version, v_len - 1);
        version[v_len - 1] = '\0';
    }
    if (time) {
        strncpy(time, s_uploaded_time, t_len - 1);
        time[t_len - 1] = '\0';
    }
    if (size) {
        *size = s_uploaded_size;
    }
    return ESP_OK;
}

// 获取所有 OTA 分区信息
esp_err_t rid_ota_get_all_partitions(ota_partition_info_t *infos, int *count) {
    if (!infos || !count) return ESP_ERR_INVALID_ARG;
    *count = 0;

    const esp_partition_t *running = esp_ota_get_running_partition();
    const esp_partition_t *boot = esp_ota_get_boot_partition();

    esp_partition_iterator_t it = esp_partition_find(ESP_PARTITION_TYPE_APP, ESP_PARTITION_SUBTYPE_ANY, NULL);
    while (it && *count < 8) {
        const esp_partition_t *part = esp_partition_get(it);
        if (part) {
            ota_partition_info_t *info = &infos[*count];
            strncpy(info->label, part->label, sizeof(info->label)-1);
            info->label[sizeof(info->label)-1] = '\0';
            info->size = part->size;
            info->is_running = (running && strcmp(part->label, running->label) == 0);
            info->is_boot = (boot && strcmp(part->label, boot->label) == 0);
            info->is_valid = false;  // 不尝试读取版本，统一标记为无效
            // 版本和编译时间置空
            info->version[0] = '\0';
            info->compile_time[0] = '\0';
            (*count)++;
        }
        it = esp_partition_next(it);
    }
    esp_partition_iterator_release(it);
    return ESP_OK;
}