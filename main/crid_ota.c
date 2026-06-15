#include "crid_ota.h"
#include <string.h>
#include <stdlib.h>
#include "sdkconfig.h"
#include "esp_err.h"
#include "esp_http_client.h"
#include "esp_ota_ops.h"
#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"

static const char *TAG = "CRID_OTA";

// ================= 流式 OTA 核心实现 =================
typedef struct {
    esp_ota_handle_t ota_handle;
    const esp_partition_t *update_partition;
    size_t total_written;
} crid_ota_ctx_t;

esp_err_t crid_ota_begin(crid_ota_handle_t *out_handle) {
    if (out_handle == NULL) return ESP_ERR_INVALID_ARG;
    const esp_partition_t *update_partition = esp_ota_get_next_update_partition(NULL);
    if (update_partition == NULL) return ESP_FAIL;

    crid_ota_ctx_t *ctx = (crid_ota_ctx_t *)malloc(sizeof(crid_ota_ctx_t));
    if (ctx == NULL) return ESP_ERR_NO_MEM;

    ctx->update_partition = update_partition;
    ctx->total_written = 0;

    esp_err_t ret = esp_ota_begin(update_partition, OTA_SIZE_UNKNOWN, &ctx->ota_handle);
    if (ret != ESP_OK) { free(ctx); return ret; }

    *out_handle = (crid_ota_handle_t)ctx;
    return ESP_OK;
}

esp_err_t crid_ota_write(crid_ota_handle_t handle, const uint8_t *data, size_t size) {
    if (handle == NULL || data == NULL || size == 0) return ESP_ERR_INVALID_ARG;
    crid_ota_ctx_t *ctx = (crid_ota_ctx_t *)handle;
    esp_err_t ret = esp_ota_write(ctx->ota_handle, data, size);
    if (ret == ESP_OK) ctx->total_written += size;
    return ret;
}

esp_err_t crid_ota_end(crid_ota_handle_t handle) {
    if (handle == NULL) return ESP_ERR_INVALID_ARG;
    crid_ota_ctx_t *ctx = (crid_ota_ctx_t *)handle;
    
    esp_err_t ret = esp_ota_end(ctx->ota_handle);
    if (ret != ESP_OK) { free(ctx); return ret; }

    ret = esp_ota_set_boot_partition(ctx->update_partition);
    if (ret != ESP_OK) { free(ctx); return ret; }

    ESP_LOGI(TAG, "OTA image written successfully (%d bytes)", ctx->total_written);
    free(ctx);
    return ESP_OK;
}

// ================= 确认 OTA 成功 (取消回退) =================
esp_err_t crid_ota_confirm(void) {
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

// ================= 传统的 URL OTA 实现 =================
esp_err_t crid_ota_perform(const char *ota_url) {
    if (ota_url == NULL || ota_url[0] == '\0') return ESP_ERR_INVALID_ARG;
    ESP_LOGI(TAG, "Starting OTA from %s", ota_url);

    esp_http_client_config_t http_config = { .url = ota_url, .timeout_ms = 30000, .keep_alive_enable = true };
    esp_http_client_handle_t client = esp_http_client_init(&http_config);
    if (client == NULL) return ESP_FAIL;

    esp_err_t ret = esp_http_client_open(client, 0);
    if (ret != ESP_OK) { esp_http_client_cleanup(client); return ret; }
    esp_http_client_fetch_headers(client);

    crid_ota_handle_t ota_handle = NULL;
    ret = crid_ota_begin(&ota_handle);
    if (ret != ESP_OK) { esp_http_client_close(client); esp_http_client_cleanup(client); return ret; }

    char buffer[1024];
    int data_read = 0;
    while ((data_read = esp_http_client_read(client, buffer, sizeof(buffer))) > 0) {
        ret = crid_ota_write(ota_handle, (const uint8_t *)buffer, data_read);
        if (ret != ESP_OK) {
            crid_ota_end(ota_handle);
            esp_http_client_close(client);
            esp_http_client_cleanup(client);
            return ret;
        }
    }
    esp_http_client_close(client);
    esp_http_client_cleanup(client);

    if (data_read < 0) { crid_ota_end(ota_handle); return ESP_FAIL; }

    ret = crid_ota_end(ota_handle);
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