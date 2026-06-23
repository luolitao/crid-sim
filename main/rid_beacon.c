#include "sdkconfig.h"
#include "rid_beacon.h"
#include "rid_messages.h"
#include "rid_utils.h"
#include "rid_standard.h"
#include "rid_gb46750.h"
#include <string.h>
#include "esp_log.h"

static const char *TAG = "RID_BEACON";

bool rid_build_beacon_frame(const rid_config_t *config,
                            uint8_t message_counter,
                            const rid_standard_meta_t *meta,
                            uint8_t *frame, uint16_t max_len,
                            uint16_t *out_len) {
    if (!config || !frame || !out_len || !meta) {
        ESP_LOGE(TAG, "Invalid parameters");
        return false;
    }

    ESP_LOGD(TAG, "Building beacon: standard=%d, counter=%d, len=%d", 
             meta->standard, message_counter, max_len);

    uint16_t pos = 0;
#define REQUIRE_SPACE(n) if (pos + (n) > max_len) { ESP_LOGE(TAG, "Buffer too small"); return false; }

    // --- MAC Header (24) ---
    REQUIRE_SPACE(24);
    frame[pos++] = 0x80; frame[pos++] = 0x00;
    frame[pos++] = 0x00; frame[pos++] = 0x00;
    memset(&frame[pos], 0xFF, 6); pos += 6;
    memcpy(&frame[pos], config->mac_address, 6); pos += 6;
    memcpy(&frame[pos], config->mac_address, 6); pos += 6;
    frame[pos++] = 0x00; frame[pos++] = 0x00;

    // --- Beacon Body ---
    REQUIRE_SPACE(8); memset(&frame[pos], 0, 8); pos += 8;
    REQUIRE_SPACE(2); write_le16(&frame[pos], 100); pos += 2;
    REQUIRE_SPACE(2); frame[pos++] = 0x21; frame[pos++] = 0x04;

    // --- SSID IE ---
    size_t ssid_len = strlen(config->ssid);
    if (ssid_len > 32) ssid_len = 32;
    REQUIRE_SPACE(2 + ssid_len);
    frame[pos++] = 0x00; frame[pos++] = (uint8_t)ssid_len;
    memcpy(&frame[pos], config->ssid, ssid_len); pos += ssid_len;

    // --- Supported Rates ---
    REQUIRE_SPACE(2 + 8);
    frame[pos++] = 0x01; frame[pos++] = 0x08;
    uint8_t rates[] = {0x82,0x84,0x8b,0x96,0x24,0x30,0x48,0x6c};
    memcpy(&frame[pos], rates, 8); pos += 8;

    // --- DS Parameter Set ---
    REQUIRE_SPACE(3);
    frame[pos++] = 0x03; frame[pos++] = 0x01; frame[pos++] = config->channel;

    // ===== Vendor Specific IE =====
#define VENDOR_HEADER_LEN 5  // OUI(3) + Type(1) + Counter(1)

    if (meta->use_gb46750_encoder) {
        ESP_LOGD(TAG, "Using GB46750 encoder");
        uint8_t gb_payload[128];
        int payload_len = rid_build_gb46750_payload(config, gb_payload, sizeof(gb_payload));
        if (payload_len < 0) {
            ESP_LOGE(TAG, "GB46750 payload build failed");
            return false;
        }
        size_t ie_len = VENDOR_HEADER_LEN + payload_len;
        if (pos + 2 + ie_len > max_len) {
            ESP_LOGE(TAG, "Buffer too small for GB46750 IE");
            return false;
        }
        frame[pos++] = 0xDD;
        frame[pos++] = (uint8_t)ie_len;
        frame[pos++] = 0xFA; frame[pos++] = 0x0B; frame[pos++] = 0xBC;
        frame[pos++] = 0x0D;
        frame[pos++] = message_counter;
        memcpy(&frame[pos], gb_payload, payload_len);
        pos += payload_len;
        // ESP_LOGI(TAG, "GB46750 encoded, total len=%d, payload_len=%d", pos, payload_len);
    } else {
        ESP_LOGD(TAG, "Using packed messages (ASTM/GB42590)");
        uint8_t packed[RID_MAX_PACK_MESSAGES * RID_SINGLE_MSG_SIZE + 3];
        int packed_len = rid_pack_messages(packed, meta->pack_format, meta->builders, meta->msg_count, config);
        if (packed_len < 0) {
            ESP_LOGE(TAG, "Pack messages failed");
            return false;
        }
        uint8_t ie_len = 3 + 1 + 1 + packed_len; // OUI(3)+Type(1)+Counter(1)+packed
        if (pos + 2 + ie_len > max_len) {
            ESP_LOGE(TAG, "Buffer too small for packed IE");
            return false;
        }
        frame[pos++] = 0xDD;
        frame[pos++] = ie_len;
        frame[pos++] = 0xFA; frame[pos++] = 0x0B; frame[pos++] = 0xBC;
        frame[pos++] = 0x0D;
        frame[pos++] = message_counter;
        memcpy(&frame[pos], packed, packed_len);
        pos += packed_len;
        // ESP_LOGI(TAG, "Packed messages, total len=%d, packed_len=%d", pos, packed_len);
    }

    *out_len = pos;
    // ESP_LOGI(TAG, "Beacon built: len=%d", pos);

    // 每256帧打印一次前80字节（调试）
    static uint32_t frame_count = 0;
    if (++frame_count % 0xFF == 0) {
        ESP_LOGD(TAG, "Frame hex (first 80 bytes):");
        // ESP_LOG_BUFFER_HEX(TAG, frame, pos > 80 ? 80 : pos);
    }

    return true;
}