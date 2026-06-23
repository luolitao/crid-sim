#include <string.h>
#include <stdlib.h>
#include "sdkconfig.h"
#include "esp_err.h"
#include "esp_http_client.h"
#include "esp_ota_ops.h"
#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "rid_ota.h"

#ifndef CONFIG_rid_OTA_BUF_SIZE
#define CONFIG_rid_OTA_BUF_SIZE 4096
#endif

#ifndef CONFIG_rid_OTA_TIMEOUT_MS
#define CONFIG_rid_OTA_TIMEOUT_MS 30000
#endif

static const char *TAG = "RID_OTA";
static SemaphoreHandle_t s_ota_mutex = NULL;

// ================= 流式 OTA 核心实现 =================
typedef struct {
    esp_ota_handle_t ota_handle;
    const esp_partition_t *update_partition;
    size_t total_written;
} rid_ota_ctx_t;

typedef esp_err_t (*ota_read_callback_t)(void *ctx, uint8_t *buf, size_t *len);

static esp_err_t write_ota_stream(rid_ota_handle_t handle, ota_read_callback_t read_cb, void *ctx) {
    uint8_t *buffer = malloc(CONFIG_rid_OTA_BUF_SIZE);
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
    int ret = esp_http_client_read(client, (char*)buf, CONFIG_rid_OTA_BUF_SIZE);
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
    
    if (nvs_open("cridd", NVS_READWRITE, &nvs) == ESP_OK) {
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
    if (nvs_open("cridd", NVS_READWRITE, &nvs) == ESP_OK) {
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
        .timeout_ms = CONFIG_rid_OTA_TIMEOUT_MS,
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
        if (nvs_open("cridd", NVS_READWRITE, &nvs) == ESP_OK) {
            nvs_set_u8(nvs, "ota_pending", 1);
            nvs_commit(nvs);
            nvs_close(nvs);
        }
        ESP_LOGI(TAG, "OTA succeeded, rebooting now...");
        esp_restart();
    }
    return ret;
}