#include "crid_ota.h"

#include <string.h>
#include "esp_err.h"
#include "esp_http_client.h"
#include "esp_ota_ops.h"
#include "esp_https_ota.h"
#include "esp_log.h"
#include "esp_system.h"

static const char *TAG = "CRID_OTA";

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

    esp_https_ota_config_t ota_config = {
        .http_config = &http_config,
    };

    esp_err_t ret = esp_https_ota(&ota_config);
    if (ret == ESP_OK) {
        ESP_LOGI(TAG, "OTA succeeded, rebooting now...");
        esp_restart();
        return ESP_OK;
    }

    ESP_LOGE(TAG, "OTA failed: %s", esp_err_to_name(ret));
    return ret;
}
