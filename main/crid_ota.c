#include "crid_ota.h"
#include <string.h>
#include <stdlib.h>
#include "sdkconfig.h"
#include "esp_err.h"
#include "esp_http_client.h"
#include "esp_ota_ops.h"
#include "esp_log.h"
#include "esp_system.h"

static const char *TAG = "CRID_OTA";

// ==========================================
// 流式 OTA 核心实现 (供 Web 上传和 CLI 复用)
// ==========================================
typedef struct {
    esp_ota_handle_t ota_handle;
    const esp_partition_t *update_partition;
    size_t total_written;
} crid_ota_ctx_t;

esp_err_t crid_ota_begin(crid_ota_handle_t *out_handle) {
    if (out_handle == NULL) return ESP_ERR_INVALID_ARG;

    const esp_partition_t *update_partition = esp_ota_get_next_update_partition(NULL);
    if (update_partition == NULL) {
        ESP_LOGE(TAG, "No OTA partition available");
        return ESP_FAIL;
    }

    crid_ota_ctx_t *ctx = (crid_ota_ctx_t *)malloc(sizeof(crid_ota_ctx_t));
    if (ctx == NULL) {
        return ESP_ERR_NO_MEM;
    }

    ctx->update_partition = update_partition;
    ctx->total_written = 0;

    esp_err_t ret = esp_ota_begin(update_partition, OTA_SIZE_UNKNOWN, &ctx->ota_handle);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_begin failed: %s", esp_err_to_name(ret));
        free(ctx);
        return ret;
    }

    *out_handle = (crid_ota_handle_t)ctx;
    ESP_LOGI(TAG, "OTA session started");
    return ESP_OK;
}

esp_err_t crid_ota_write(crid_ota_handle_t handle, const uint8_t *data, size_t size) {
    if (handle == NULL || data == NULL || size == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    crid_ota_ctx_t *ctx = (crid_ota_ctx_t *)handle;
    
    esp_err_t ret = esp_ota_write(ctx->ota_handle, data, size);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_write failed: %s", esp_err_to_name(ret));
        return ret;
    }
    ctx->total_written += size;
    return ESP_OK;
}

esp_err_t crid_ota_end(crid_ota_handle_t handle) {
    if (handle == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    crid_ota_ctx_t *ctx = (crid_ota_ctx_t *)handle;
    
    // esp_ota_end 会自动校验 app 镜像的头部和校验和
    esp_err_t ret = esp_ota_end(ctx->ota_handle);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_end failed (invalid image?): %s", esp_err_to_name(ret));
        free(ctx);
        return ret;
    }

    ret = esp_ota_set_boot_partition(ctx->update_partition);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_set_boot_partition failed: %s", esp_err_to_name(ret));
        free(ctx);
        return ret;
    }

    ESP_LOGI(TAG, "OTA image written and verified successfully (%d bytes)", ctx->total_written);
    free(ctx);
    return ESP_OK;
}


// ==========================================
// 传统的 URL OTA 实现 (供 CLI 使用)
// ==========================================
esp_err_t crid_ota_perform(const char *ota_url) {
    if (ota_url == NULL || ota_url[0] == '\0') {
        return ESP_ERR_INVALID_ARG;
    }
    ESP_LOGI(TAG, "Starting OTA from %s", ota_url);

    esp_http_client_config_t http_config = {
        .url = ota_url,
        .timeout_ms = 30000,
        .keep_alive_enable = true,
    };
    
    esp_http_client_handle_t client = esp_http_client_init(&http_config);
    if (client == NULL) {
        ESP_LOGE(TAG, "Failed to create HTTP client");
        return ESP_FAIL;
    }

    esp_err_t ret = esp_http_client_open(client, 0);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "esp_http_client_open failed: %s", esp_err_to_name(ret));
        esp_http_client_cleanup(client);
        return ret;
    }

    int content_length = esp_http_client_fetch_headers(client);
    ESP_LOGI(TAG, "HTTP content length: %d", content_length);

    // 复用新的流式 API 进行写入，节省内存并保持逻辑统一
    crid_ota_handle_t ota_handle = NULL;
    ret = crid_ota_begin(&ota_handle);
    if (ret != ESP_OK) {
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        return ret;
    }

    char buffer[1024];
    int data_read = 0;
    while ((data_read = esp_http_client_read(client, buffer, sizeof(buffer))) > 0) {
        ret = crid_ota_write(ota_handle, (const uint8_t *)buffer, data_read);
        if (ret != ESP_OK) {
            crid_ota_end(ota_handle); // 清理失败的会话
            esp_http_client_close(client);
            esp_http_client_cleanup(client);
            return ret;
        }
    }

    esp_http_client_close(client);
    esp_http_client_cleanup(client);

    if (data_read < 0) {
        ESP_LOGE(TAG, "HTTP read failed");
        crid_ota_end(ota_handle);
        return ESP_FAIL;
    }

    // 结束 OTA 并校验
    ret = crid_ota_end(ota_handle);
    if (ret == ESP_OK) {
        ESP_LOGI(TAG, "OTA succeeded, rebooting now...");
        esp_restart();
        return ESP_OK; // esp_restart 不会返回，但为了消除编译器警告加上
    }

    ESP_LOGE(TAG, "OTA failed: %s", esp_err_to_name(ret));
    return ret;
}