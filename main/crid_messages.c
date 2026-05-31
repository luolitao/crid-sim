#include "crid_messages.h"
#include <string.h>
#include <math.h>
#include "esp_log.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "sys/time.h"

static const char *TAG = "CN_C-RID_MSG";

// --- 辅助函数：写入 int32_t 为小端序 ---
static inline void write_le32(uint8_t *buf, int32_t val) {
    for (int i = 0; i < 4; i++) {
        buf[i] = (val >> (i * 8)) & 0xFF;
    }
}

// --- 辅助函数：写入 uint16_t 为小端序 ---
static inline void write_le16(uint8_t *buf, uint16_t val) {
    buf[0] = val & 0xFF;
    buf[1] = (val >> 8) & 0xFF;
}

// --- 辅助函数：写入 uint32_t 为小端序 ---
static inline void write_le32_u32(uint8_t *buf, uint32_t val) {
    for (int i = 0; i < 4; i++) {
        buf[i] = (val >> (i * 8)) & 0xFF;
    }
}

// --- 编码地速 (符合 ASTM F3411-22a 表) ---
// 速度 < 63.75 m/s: encoded = speed / 0.25
// 速度 >= 63.75 m/s 且 <= 254.25 m/s: encoded = 255 + (speed - 63.75) / 0.75
// 速度 > 254.25 m/s: encoded = 254 (max)
static uint8_t encode_ground_speed(float speed_ms) {
    if (speed_ms < 0.0f) speed_ms = 0.0f;
    if (speed_ms < 63.75f) {
        return (uint8_t)(speed_ms / 0.25f);
    } else if (speed_ms <= 254.25f) {
        return (uint8_t)(255 + (speed_ms - 63.75f) / 0.75f);
    } else {
        return 254;
    }
}

// --- 编码高度 (cm，偏移 -1000m) ---
static uint16_t encode_altitude_cm(float altitude_m) {
    int32_t val = (int32_t)((altitude_m + 1000.0f) * 100.0f);
    if (val < 0) val = 0;
    if (val > 65535) val = 65535;
    return (uint16_t)val;
}

void crid_build_basic_id_message(const cn_crid_config_t *config, uint8_t *message) {
    memset(message, 0, CRID_MESSAGE_SIZE);

    // 报头: [消息类型(高4位)] + [接口版本(低4位)]
    message[0] = (MSG_TYPE_BASIC_ID << 4) | 0x01;

    // 字节1: ID类型(高4位) + UA类型(低4位) - 符合试行标准表3
    message[1] = (config->id_type << 4) | config->ua_type;

    // 字节2-21: UAS ID (20字节, ASCII, 不足填充空格)
    memset(&message[2], 0x20, CRID_UAS_ID_MAX_LEN);
    size_t id_len = strlen(config->uas_id);
    if (id_len > CRID_UAS_ID_MAX_LEN) id_len = CRID_UAS_ID_MAX_LEN;
    memcpy(&message[2], config->uas_id, id_len);

    // 字节22-24: 预留
    // 已由 memset 置零

    ESP_LOGD(TAG, "Basic ID message built (UAS: %s)", config->uas_id);
}

void crid_build_location_message(const cn_crid_config_t *config, uint8_t *message) {
    memset(message, 0, CRID_MESSAGE_SIZE);

    // 报头: [消息类型(高4位)] + [接口版本(低4位)]
    message[0] = (MSG_TYPE_LOCATION << 4) | 0x01;

    // 字节1: 运行状态(高4位) + 标志位(低4位)
    message[1] = (config->status << 4) | 0x00;

    // 字节2: 航迹角 (0-179)
    uint8_t track_angle = (uint8_t)config->heading;
    if (track_angle > 179) track_angle = 179;
    message[2] = track_angle;

    // 字节3: 地速
    message[3] = encode_ground_speed(config->speed_horizontal);

    // 字节4: 垂直速度 (m/s * 2, int8_t)
    int16_t vs_raw = (int16_t)(config->speed_vertical * 2.0f);
    if (vs_raw > 127) vs_raw = 127;
    if (vs_raw < -128) vs_raw = -128;
    message[4] = (uint8_t)((int8_t)vs_raw);

    // 字节5-8: 纬度 (小端序, 1E-7 度单位)
    write_le32(&message[5], (int32_t)(config->latitude * 1e7));

    // 字节9-12: 经度 (小端序, 1E-7 度单位)
    write_le32(&message[9], (int32_t)(config->longitude * 1e7));

    // 字节13-14: 气压高度 (小端序, cm) — 不再加随机抖动
    write_le16(&message[13], encode_altitude_cm(config->altitude_msl));

    // 字节15-16: 几何高度 (小端序, cm)
    write_le16(&message[15], encode_altitude_cm(config->altitude_msl));

    // 字节17-18: 距地高度 (小端序, cm)
    write_le16(&message[17], encode_altitude_cm(config->altitude_agl));

    // 字节19: 水平精度(高4位) + 垂直精度(低4位)
    message[19] = (0x04 << 4) | 0x04; // <= 6m

    // 字节20: 速度精度
    message[20] = 0x02; // <= 0.3m/s

    // 字节21-22: 时间戳 (自当前小时起的 1/10 秒，小端序)
    uint64_t tick_ms = ((uint64_t)xTaskGetTickCount() * 1000ULL) / configTICK_RATE_HZ;
    uint16_t ts = (uint16_t)((tick_ms % 3600000ULL) / 100ULL);
    write_le16(&message[21], ts);

    // 字节23: 时间戳精度 (0.2s)
    message[23] = 0x0A;

    // 字节24: 预留 (已由 memset 置零)

    ESP_LOGD(TAG, "Location message built (%.6f, %.6f)", config->latitude, config->longitude);
}

void crid_build_system_message(const cn_crid_config_t *config, uint8_t *message) {
    memset(message, 0, CRID_MESSAGE_SIZE);

    // 报头
    message[0] = (MSG_TYPE_SYSTEM << 4) | 0x01;

    // 字节1: 坐标系(1b) + 区域(3b) + 控制站位置类型(2b)
    message[1] = (0x00 << 7) | (0x02 << 4) | 0x01; // WGS84 + China + Takeoff

    // 字节2-5: 控制站纬度 (小端序, 1E-7)
    write_le32(&message[2], (int32_t)(config->operator_lat * 1e7));

    // 字节6-9: 控制站经度 (小端序, 1E-7)
    write_le32(&message[6], (int32_t)(config->operator_lon * 1e7));

    // 字节10-11: 运行区域计数
    write_le16(&message[10], 1);

    // 字节12: 运行区域半径 (m * 10)
    message[12] = 0x64; // 100m

    // 字节13-14: 运行区域高度上限 (cm)
    write_le16(&message[13], encode_altitude_cm(100.0f));

    // 字节15-16: 运行区域高度下限 (cm)
    write_le16(&message[16], encode_altitude_cm(50.0f));

    // 字节17: UA 运行类别(高4b) + UA 等级(低4b) — 开放类 + 轻型
    message[17] = 0x10;

    // 字节18-19: 操作员高度 (cm)
    write_le16(&message[18], encode_altitude_cm(config->operator_alt));

    // 字节20-23: 时间戳 (自 2019-01-01 00:00:00 UTC 的秒数，小端序)
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint32_t ts_since_2019 = (uint32_t)(tv.tv_sec - 1546300800);
    write_le32_u32(&message[20], ts_since_2019);

    // 字节24: 预留

    ESP_LOGD(TAG, "System message built (Op: %.6f, %.6f)", config->operator_lat, config->operator_lon);
}

bool crid_build_beacon_frame(const cn_crid_config_t *config,
                              uint8_t *frame, uint16_t max_len,
                              uint16_t *out_len) {
    if (config == NULL || frame == NULL || out_len == NULL) return false;

    uint16_t pos = 0;

    // --- 预估帧长度，确保不越界 ---
    // MAC Header: 24 + Timestamp: 8 + Beacon Interval: 2 + Capability: 2 + SSID IE: 2+ssid_len
    // + Rates IE: 2+8 + DS IE: 3 + Vendor IE: 1+1+3+1+1+3+25*3 = ~166
    #define BEACON_FRAME_ESTIMATED_LEN 200
    if (max_len < BEACON_FRAME_ESTIMATED_LEN) {
        ESP_LOGE(TAG, "Frame buffer too small: %u < %u", max_len, BEACON_FRAME_ESTIMATED_LEN);
        return false;
    }

    // --- MAC Header (24 bytes) ---
    frame[pos++] = 0x80; // Type=Management, Subtype=Beacon
    frame[pos++] = 0x00;
    frame[pos++] = 0x00; // Duration
    frame[pos++] = 0x00;

    // Destination Address (Broadcast)
    memset(&frame[pos], 0xFF, 6);
    pos += 6;

    // Source Address
    memcpy(&frame[pos], config->mac_address, 6);
    pos += 6;

    // BSSID
    memcpy(&frame[pos], config->mac_address, 6);
    pos += 6;

    // Sequence Control
    frame[pos++] = 0x00;
    frame[pos++] = 0x00;

    // --- Beacon Body ---
    // Timestamp (8 bytes)
    memset(&frame[pos], 0, 8);
    pos += 8;

    // Beacon Interval (100ms)
    write_le16(&frame[pos], 100);
    pos += 2;

    // Capability Information
    frame[pos++] = 0x21;
    frame[pos++] = 0x04;

    // --- SSID IE ---
    frame[pos++] = 0x00; // IE ID
    size_t ssid_len = strlen(config->ssid);
    frame[pos++] = (uint8_t)ssid_len;
    memcpy(&frame[pos], config->ssid, ssid_len);
    pos += ssid_len;

    // --- Supported Rates IE ---
    frame[pos++] = 0x01; // IE ID
    frame[pos++] = 0x08; // Length
    uint8_t rates[] = {0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c};
    memcpy(&frame[pos], rates, 8);
    pos += 8;

    // --- DS Parameter Set IE ---
    frame[pos++] = 0x03;
    frame[pos++] = 0x01;
    frame[pos++] = config->channel;

    // --- China C-RID Vendor Specific IE ---
    // 计算打包消息长度: 头部3字节 + 3条报文 * 25字节 = 78
    #define PACKED_MSG_HEADER_LEN 3
    #define PACKED_MSG_TOTAL_LEN (PACKED_MSG_HEADER_LEN + 3 * CRID_MESSAGE_SIZE)

    frame[pos++] = 0xDD; // Vendor Specific IE ID
    frame[pos++] = 3 + 1 + 1 + PACKED_MSG_TOTAL_LEN; // OUI(3) + Type(1) + Counter(1) + Packed

    // OUI: FA 0B BC
    frame[pos++] = CRID_OUI_0;
    frame[pos++] = CRID_OUI_1;
    frame[pos++] = CRID_OUI_2;

    // Vendor Type: 0x0D
    frame[pos++] = CRID_VENDOR_TYPE;

    // Message Counter
    uint8_t msg_counter = config->message_counter;
    frame[pos++] = msg_counter;

    // --- 构建打包消息 ---
    uint8_t packed_msg[PACKED_MSG_TOTAL_LEN];
    uint8_t packed_pos = 0;

    // 打包格式标识
    packed_msg[packed_pos++] = 0xF1;
    // 每条消息长度: 25
    packed_msg[packed_pos++] = CRID_MESSAGE_SIZE;
    // 消息数量: 3
    packed_msg[packed_pos++] = 0x03;

    // 构建三条报文
    uint8_t basic_msg[CRID_MESSAGE_SIZE];
    crid_build_basic_id_message(config, basic_msg);
    memcpy(&packed_msg[packed_pos], basic_msg, CRID_MESSAGE_SIZE);
    packed_pos += CRID_MESSAGE_SIZE;

    uint8_t location_msg[CRID_MESSAGE_SIZE];
    crid_build_location_message(config, location_msg);
    memcpy(&packed_msg[packed_pos], location_msg, CRID_MESSAGE_SIZE);
    packed_pos += CRID_MESSAGE_SIZE;

    uint8_t system_msg[CRID_MESSAGE_SIZE];
    crid_build_system_message(config, system_msg);
    memcpy(&packed_msg[packed_pos], system_msg, CRID_MESSAGE_SIZE);
    packed_pos += CRID_MESSAGE_SIZE;

    // 复制打包消息到帧
    memcpy(&frame[pos], packed_msg, PACKED_MSG_TOTAL_LEN);
    pos += PACKED_MSG_TOTAL_LEN;

    *out_len = pos;

    ESP_LOGI(TAG, "Beacon frame built: %u bytes, counter=%u, pos=(%.6f,%.6f)",
             *out_len, msg_counter, config->latitude, config->longitude);
    return true;
}
