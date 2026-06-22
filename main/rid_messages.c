#include "rid_messages.h"
#include "rid_utils.h"
#include "rid_standard.h"
#include "rid_gb46750.h"
#include <string.h>
#include <math.h>
#include <time.h>
#include <sys/time.h>
#include "esp_log.h"

// 如果不需要日志，可以注释掉 TAG
static const char *TAG = "RID_MSG";

void rid_encode_basic_id(const rid_config_t *config, uint8_t *out) {
    memset(out, 0, RID_SINGLE_MSG_SIZE);
    out[0] = (RID_PROTOCOL_VERSION & 0x0F) | ((RID_MSG_BASIC_ID & 0x0F) << 4);
    out[1] = (config->ua_type & 0x0F) | ((config->id_type & 0x0F) << 4);
    strncpy((char*)(out + 2), config->uas_id, 20);
}

void rid_encode_location(const rid_config_t *config, uint8_t *out) {
    memset(out, 0, RID_SINGLE_MSG_SIZE);
    out[0] = (RID_PROTOCOL_VERSION & 0x0F) | ((RID_MSG_LOCATION & 0x0F) << 4);
    
    bool is_west = false;
    uint8_t dir = encode_direction(config->heading, &is_west);
    uint8_t speed_mult = (config->speed_horizontal >= 63.75f) ? 1 : 0;
    // Byte1: Status(4) | HeightType(1) | EW_Dir(1) | SpeedMult(1) | Reserved(1)
    out[1] = ((config->status & 0x0F) << 4) |
             ((config->height_type & 0x01) << 3) |
             ((is_west ? 1 : 0) << 2) |
             ((speed_mult & 0x01) << 1);
    out[2] = dir;
    out[3] = encode_speed_h(config->speed_horizontal);
    out[4] = (uint8_t)encode_speed_v(config->speed_vertical);
    
    int32_t lat = encode_lat_lon(config->latitude, true);
    int32_t lon = encode_lat_lon(config->longitude, false);
    write_le32(out + 5, lat);
    write_le32(out + 9, lon);
    
    uint16_t alt_baro = encode_altitude(config->altitude_msl);
    uint16_t alt_geo = encode_altitude(config->altitude_msl); // 此处假设几何高度等于气压高度
    uint16_t height = encode_altitude(config->altitude_agl);
    write_le16(out + 13, alt_baro);
    write_le16(out + 15, alt_geo);
    write_le16(out + 17, height);
    
    // 精度字段（固定值或从 config 读取）
    out[19] = (RID_ACC_10M << 4) | RID_ACC_3M;      // Vert=10m, Horiz=3m
    out[20] = (RID_ACC_UNKNOWN << 4) | RID_ACC_0_3M; // Baro=unknown, Speed=0.3m/s
    
    // 时间戳（当前秒内 0.1s 单位）
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm *tm_utc = gmtime(&tv.tv_sec);
    float sec_of_hour = tm_utc->tm_min * 60.0f + tm_utc->tm_sec + tv.tv_usec / 1e6;
    uint16_t ts = encode_timestamp(sec_of_hour);
    write_le16(out + 21, ts);
    
    out[23] = RID_ACC_TS_0_2S;   // 使用新定义的常量
}

void rid_encode_system(const rid_config_t *config, uint8_t *out) {
    memset(out, 0, RID_SINGLE_MSG_SIZE);
    out[0] = (RID_PROTOCOL_VERSION & 0x0F) | ((RID_MSG_SYSTEM & 0x0F) << 4);
    // 假设 operator_location_type 为 LIVE_GNSS (1)
    out[1] = (config->operator_location_type & 0x03) | ((config->category_eu & 0x07) << 2);
    
    int32_t lat = encode_lat_lon(config->operator_lat, true);
    int32_t lon = encode_lat_lon(config->operator_lon, false);
    write_le32(out + 2, lat);
    write_le32(out + 6, lon);
    
    // area_count = 1, area_radius = 100m
    write_le16(out + 10, 1);
    out[12] = 0x64; // 100
    
    uint16_t ceiling = encode_altitude(100.0f);
    uint16_t floor = encode_altitude(50.0f);
    write_le16(out + 13, ceiling);
    write_le16(out + 15, floor);
    
    out[17] = (config->category_eu & 0x0F) | ((config->class_eu & 0x0F) << 4);
    uint16_t op_alt = encode_altitude(config->operator_alt);
    write_le16(out + 18, op_alt);
    
    // 完整时间戳（2019-01-01 秒数）
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint32_t ts = (uint32_t)(tv.tv_sec - 1546300800);
    write_le32_u32(out + 20, ts);
}

void rid_encode_self_id(const rid_config_t *config, uint8_t *out) {
    memset(out, 0, RID_SINGLE_MSG_SIZE);
    out[0] = (RID_PROTOCOL_VERSION & 0x0F) | ((RID_MSG_SELF_ID & 0x0F) << 4);
    out[1] = DESC_TYPE_TEXT; // 0
    strncpy((char*)(out + 2), config->drone_name, 23);
}

void rid_encode_operator_id(const rid_config_t *config, uint8_t *out) {
    memset(out, 0, RID_SINGLE_MSG_SIZE);
    out[0] = (RID_PROTOCOL_VERSION & 0x0F) | ((RID_MSG_OPERATOR_ID & 0x0F) << 4);
    out[1] = 0; // CAA Registration ID
    strncpy((char*)(out + 2), config->operator_id, 20);
}

void rid_encode_auth(const rid_config_t *config, uint8_t *out) {
    memset(out, 0, RID_SINGLE_MSG_SIZE);
    out[0] = (RID_PROTOCOL_VERSION & 0x0F) | ((RID_MSG_AUTH & 0x0F) << 4);
    out[1] = 0; // AuthType=None
    out[2] = 0; // LastPageIndex
    out[3] = 0; // Length
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint32_t ts = (uint32_t)(tv.tv_sec - 1546300800);
    write_le32_u32(out + 4, ts);
    // 其余为0
}

// ==================== 打包函数实现 ====================
int rid_pack_messages(uint8_t *out, pack_format_t format,
                      const msg_builder_t builders[], uint8_t count,
                      const rid_config_t *config) {
    if (!out || !builders || count == 0) {
        ESP_LOGE("RID_MSG", "Invalid pack parameters");
        return -1;
    }
    // ESP_LOGI("RID_MSG", "Packing %d messages, format=%d", count, format);
    uint8_t temp[RID_MAX_PACK_MESSAGES][RID_SINGLE_MSG_SIZE];
    size_t pos = 0;
    if (format == PACK_FORMAT_ASTM) {
        out[pos++] = (RID_MSG_PACK << 4) | RID_PROTOCOL_VERSION; // 0xF1
        out[pos++] = count;
    } else if (format == PACK_FORMAT_GB42590) {
        out[pos++] = 0xF1;
        out[pos++] = RID_SINGLE_MSG_SIZE;
        out[pos++] = count;
    } else {
        ESP_LOGE("RID_MSG", "Unsupported format");
        return -1;
    }
    for (int i = 0; i < count; i++) {
        builders[i](config, temp[i]);
        memcpy(out + pos, temp[i], RID_SINGLE_MSG_SIZE);
        pos += RID_SINGLE_MSG_SIZE;
    }
    // ESP_LOGI("RID_MSG", "Packed %d bytes, header type %d", pos, format);
    // ESP_LOG_BUFFER_HEX(TAG, out, pos > 16 ? 16 : pos);
    return (int)pos;
}

// ==================== GB46750 构建器 (特殊处理) ====================
int rid_build_gb46750_payload(const rid_config_t *config, uint8_t *out, size_t max_len) {
    if (!config || !out) return -1;
    gb46750_data_t data;
    gb46750_from_config(config, &data);
    return gb46750_encode(&data, out, max_len);
}