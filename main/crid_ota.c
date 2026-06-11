#include "crid_ota.h"

#include <string.h>
#include "sdkconfig.h"
#include "esp_err.h"
#include "esp_http_client.h"
#include "esp_ota_ops.h"
#include "esp_log.h"
#include "esp_system.h"

static const char *TAG = "CRID_OTA";

static esp_err_t write_ota_from_http(esp_http_client_handle_t client) {
    const esp_partition_t *update_partition = esp_ota_get_next_update_partition(NULL);
    if (update_partition == NULL) {
        ESP_LOGE(TAG, "No OTA partition available");
        return ESP_FAIL;
    }

    esp_ota_handle_t ota_handle = 0;
    esp_err_t ret = esp_ota_begin(update_partition, OTA_SIZE_UNKNOWN, &ota_handle);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_begin failed: %s", esp_err_to_name(ret));
        return ret;
    }

    char buffer[1024];
    int data_read = 0;
    int total_written = 0;

    while ((data_read = esp_http_client_read(client, buffer, sizeof(buffer))) > 0) {
        ret = esp_ota_write(ota_handle, buffer, data_read);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "esp_ota_write failed: %s", esp_err_to_name(ret));
            esp_ota_end(ota_handle);
            return ret;
        }
        total_written += data_read;
    }

    if (data_read < 0) {
        ESP_LOGE(TAG, "HTTP read failed");
        esp_ota_end(ota_handle);
        return ESP_FAIL;
    }

    ret = esp_ota_end(ota_handle);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_end failed: %s", esp_err_to_name(ret));
        return ret;
    }

    ret = esp_ota_set_boot_partition(update_partition);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_set_boot_partition failed: %s", esp_err_to_name(ret));
        return ret;
    }

    ESP_LOGI(TAG, "OTA image written successfully (%d bytes)", total_written);
    return ESP_OK;
}

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

    ret = write_ota_from_http(client);
    esp_http_client_close(client);
    esp_http_client_cleanup(client);

    if (ret == ESP_OK) {
        ESP_LOGI(TAG, "OTA succeeded, rebooting now...");
        esp_restart();
        return ESP_OK;
    }

    ESP_LOGE(TAG, "OTA failed: %s", esp_err_to_name(ret));
    return ret;
}
