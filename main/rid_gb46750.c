// rid_gb46750.c
#include "rid_gb46750.h"
#include "rid_config.h"
#include <string.h>
#include <math.h>
#include <time.h>
#include <sys/time.h>

// ==================== 辅助编码函数 ====================

// 编码经纬度: 1e-7 度/LSB
static int32_t encode_latlon(double deg) {
    if (deg < -180.0 || deg > 180.0) return 0;
    return (int32_t)round(deg * 1e7);
}

// 编码高度: 0.5m/LSB, 偏移 -1000m
static uint16_t encode_altitude(float m) {
    if (m < -1000.0f) return 0xFFFF;
    if (m > 31767.5f) return 0xFFFE;
    return (uint16_t)round((m + 1000.0f) * 2.0f);
}

// 编码航迹角: 1度/LSB, 0-359, 255=无效
static uint8_t encode_track_angle(float deg) {
    if (deg < 0.0f || deg >= 360.0f) return 255;
    uint8_t val = (uint8_t)round(deg);
    // if (val >= 360) val = 0;
    return val;
}

// 编码地速: 0.25m/s/LSB, 0-254.25m/s, 255=无效
static uint8_t encode_ground_speed(float ms) {
    if (ms < 0.0f || ms > 254.25f) return 255;
    return (uint8_t)round(ms * 4.0f);
}

// 编码垂直速度: 0.25m/s/LSB, 偏移 +63, 1-187, 255=无效
static uint8_t encode_vert_speed(float ms) {
    if (ms < -62.0f || ms > 62.0f) return 255;
    int16_t val = (int16_t)round(ms * 4.0f + 63.0f);
    if (val < 1) val = 1;
    if (val > 187) val = 187;
    return (uint8_t)val;
}

// 编码时间戳: 自 2019-01-01 00:00:00 UTC 的秒数
static uint32_t encode_timestamp(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint32_t)(tv.tv_sec - 1546300800);
}

// 获取时间戳精度 (固定为 0.2s)
static gb_ts_acc_t get_ts_acc(void) {
    return GB_TS_ACC_LTE_200MS;
}

// ==================== 标志位自动计算 ====================

static void gb46750_calc_flags(gb46750_data_t *data) {
    uint8_t f1 = 0, f2 = 0, f3 = 0;

    // 字节1: 必填字段 (M)[reference:14]
    f1 |= GB_FLAG_BYTE1_UAS_ID;         // 001 唯一产品识别码
    f1 |= GB_FLAG_BYTE1_REG_MARK;       // 002 实名登记标志
    f1 |= GB_FLAG_BYTE1_UA_CLASS;       // 004 无人机分类
    f1 |= GB_FLAG_BYTE1_GCS_POS_TYPE;   // 005 遥控站位置类型
    f1 |= GB_FLAG_BYTE1_GCS_POS;        // 006 遥控站位置
    f1 |= GB_FLAG_BYTE1_GCS_ALT;        // 007 遥控站高度

    // 字节1可选: 运行类别 (003)
    if (data->op_category != GB_OP_CATEGORY_UNDEFINED) {
        f1 |= GB_FLAG_BYTE1_OP_CATEGORY;
    }

    // 字节2: 必填字段 (M)[reference:15]
    f2 |= GB_FLAG_BYTE2_UA_POS;         // 008 无人机位置
    f2 |= GB_FLAG_BYTE2_TRACK;          // 009 航迹角
    f2 |= GB_FLAG_BYTE2_GROUND_SPEED;   // 010 地速
    f2 |= GB_FLAG_BYTE2_GEO_ALT;        // 013 大地高度

    // 字节2可选: 相对高度 (011), 垂直速度 (012), 气压高度 (014)
    if (data->rel_altitude != 0.0f || data->rel_altitude > -1000.0f) {
        f2 |= GB_FLAG_BYTE2_REL_ALT;
    }
    if (data->vert_speed != 0.0f) {
        f2 |= GB_FLAG_BYTE2_VERT_SPEED;
    }
    if (data->baro_altitude != 0.0f || data->baro_altitude > -1000.0f) {
        f2 |= GB_FLAG_BYTE2_BARO_ALT;
    }

    // 字节3: 必填字段 (M)[reference:16]
    f3 |= GB_FLAG_BYTE3_OP_STATUS;      // 015 运行状态
    f3 |= GB_FLAG_BYTE3_COORD_TYPE;     // 016 坐标系类型
    f3 |= GB_FLAG_BYTE3_H_ACC;          // 017 水平精度
    f3 |= GB_FLAG_BYTE3_V_ACC;          // 018 垂直精度
    f3 |= GB_FLAG_BYTE3_SPD_ACC;        // 019 速度精度
    f3 |= GB_FLAG_BYTE3_TIMESTAMP;      // 020 时间戳
    f3 |= GB_FLAG_BYTE3_TS_ACC;         // 021 时间戳精度

    data->flag_byte1 = f1;
    data->flag_byte2 = f2;
    data->flag_byte3 = f3;
}

// ==================== 主编码函数 ====================

int gb46750_encode(const gb46750_data_t *data, uint8_t *out, size_t max_len) {
    if (!data || !out) return -1;

    // 复制并计算标志位
    gb46750_data_t local = *data;
    gb46750_calc_flags(&local);

    // 计算最大长度: 头部4字节 + 各字段
    size_t pos = 0;
    if (max_len < 4) return -1;

    // Byte 0: 数据类型 (固定 0xFF)
    out[pos++] = GB_DATA_TYPE;                      // 0xFF[reference:17]

    // Byte 1: 版本 (0x20) + 保留位
    out[pos++] = GB_VERSION_BASE;                   // 0x20[reference:18]

    // Byte 2-4: 数据标识 (3字节)
    out[pos++] = local.flag_byte1;
    out[pos++] = local.flag_byte2;
    out[pos++] = local.flag_byte3;

    // ===== 按标志位顺序编码字段 =====

    // ---- 字节1标志位 ----
    if (local.flag_byte1 & GB_FLAG_BYTE1_UAS_ID) {
        if (pos + 20 > max_len) return -1;
        memcpy(out + pos, local.uas_id, 20);
        pos += 20;
    }

    if (local.flag_byte1 & GB_FLAG_BYTE1_REG_MARK) {
        if (pos + 1 > max_len) return -1;
        out[pos++] = local.reg_mark;
    }

    if (local.flag_byte1 & GB_FLAG_BYTE1_OP_CATEGORY) {
        if (pos + 1 > max_len) return -1;
        out[pos++] = (uint8_t)local.op_category;
    }

    if (local.flag_byte1 & GB_FLAG_BYTE1_UA_CLASS) {
        if (pos + 1 > max_len) return -1;
        out[pos++] = (uint8_t)local.ua_class;
    }

    if (local.flag_byte1 & GB_FLAG_BYTE1_GCS_POS_TYPE) {
        if (pos + 1 > max_len) return -1;
        out[pos++] = (uint8_t)local.gcs_pos_type;
    }

    if (local.flag_byte1 & GB_FLAG_BYTE1_GCS_POS) {
        if (pos + 8 > max_len) return -1;
        int32_t lat = encode_latlon(local.gcs_latitude);
        int32_t lon = encode_latlon(local.gcs_longitude);
        memcpy(out + pos, &lat, 4);
        memcpy(out + pos + 4, &lon, 4);
        pos += 8;
    }

    if (local.flag_byte1 & GB_FLAG_BYTE1_GCS_ALT) {
        if (pos + 2 > max_len) return -1;
        uint16_t alt = encode_altitude(local.gcs_altitude);
        memcpy(out + pos, &alt, 2);
        pos += 2;
    }

    // ---- 字节2标志位 ----
    if (local.flag_byte2 & GB_FLAG_BYTE2_UA_POS) {
        if (pos + 8 > max_len) return -1;
        int32_t lat = encode_latlon(local.ua_latitude);
        int32_t lon = encode_latlon(local.ua_longitude);
        memcpy(out + pos, &lat, 4);
        memcpy(out + pos + 4, &lon, 4);
        pos += 8;
    }

    if (local.flag_byte2 & GB_FLAG_BYTE2_TRACK) {
        if (pos + 1 > max_len) return -1;
        out[pos++] = encode_track_angle(local.track_angle);
    }

    if (local.flag_byte2 & GB_FLAG_BYTE2_GROUND_SPEED) {
        if (pos + 1 > max_len) return -1;
        out[pos++] = encode_ground_speed(local.ground_speed);
    }

    if (local.flag_byte2 & GB_FLAG_BYTE2_REL_ALT) {
        if (pos + 2 > max_len) return -1;
        uint16_t alt = encode_altitude(local.rel_altitude);
        memcpy(out + pos, &alt, 2);
        pos += 2;
    }

    if (local.flag_byte2 & GB_FLAG_BYTE2_VERT_SPEED) {
        if (pos + 1 > max_len) return -1;
        out[pos++] = encode_vert_speed(local.vert_speed);
    }

    if (local.flag_byte2 & GB_FLAG_BYTE2_GEO_ALT) {
        if (pos + 2 > max_len) return -1;
        uint16_t alt = encode_altitude(local.geo_altitude);
        memcpy(out + pos, &alt, 2);
        pos += 2;
    }

    if (local.flag_byte2 & GB_FLAG_BYTE2_BARO_ALT) {
        if (pos + 2 > max_len) return -1;
        uint16_t alt = encode_altitude(local.baro_altitude);
        memcpy(out + pos, &alt, 2);
        pos += 2;
    }

    // ---- 字节3标志位 ----
    if (local.flag_byte3 & GB_FLAG_BYTE3_OP_STATUS) {
        if (pos + 1 > max_len) return -1;
        out[pos++] = (uint8_t)local.op_status;
    }

    if (local.flag_byte3 & GB_FLAG_BYTE3_COORD_TYPE) {
        if (pos + 1 > max_len) return -1;
        out[pos++] = (uint8_t)local.coord_type;
    }

    if (local.flag_byte3 & GB_FLAG_BYTE3_H_ACC) {
        if (pos + 1 > max_len) return -1;
        out[pos++] = (uint8_t)local.h_acc;
    }

    if (local.flag_byte3 & GB_FLAG_BYTE3_V_ACC) {
        if (pos + 1 > max_len) return -1;
        out[pos++] = (uint8_t)local.v_acc;
    }

    if (local.flag_byte3 & GB_FLAG_BYTE3_SPD_ACC) {
        if (pos + 1 > max_len) return -1;
        out[pos++] = (uint8_t)local.spd_acc;
    }

    if (local.flag_byte3 & GB_FLAG_BYTE3_TIMESTAMP) {
        if (pos + 4 > max_len) return -1;
        uint32_t ts = local.timestamp;
        memcpy(out + pos, &ts, 4);
        pos += 4;
    }

    if (local.flag_byte3 & GB_FLAG_BYTE3_TS_ACC) {
        if (pos + 1 > max_len) return -1;
        out[pos++] = (uint8_t)local.ts_acc;
    }

    return (int)pos;
}

// ==================== 配置转换函数 ====================

void gb46750_from_config(const rid_config_t *cfg, gb46750_data_t *out) {
    if (!cfg || !out) return;

    memset(out, 0, sizeof(gb46750_data_t));

    // 复制 UAS ID
    strncpy(out->uas_id, cfg->uas_id, 20);
    out->uas_id[20] = '\0';

    // 实名登记标志 (固定为已登记)
    out->reg_mark = 1;

    // 运行类别 (默认开放类)
    out->op_category = GB_OP_CATEGORY_OPEN;

    // 无人机分类 (根据配置或默认)
    out->ua_class = GB_UA_CLASS_LIGHT;

    // 遥控站位置类型 (默认起飞点)
    out->gcs_pos_type = GB_GCS_POS_TYPE_TAKEOFF;

    // 遥控站位置 (使用操作员位置)
    out->gcs_latitude = cfg->operator_lat;
    out->gcs_longitude = cfg->operator_lon;
    out->gcs_altitude = cfg->operator_alt;

    // 无人机位置
    out->ua_latitude = cfg->latitude;
    out->ua_longitude = cfg->longitude;

    // 航迹角
    out->track_angle = cfg->heading;

    // 地速
    out->ground_speed = cfg->speed_horizontal;

    // 相对高度 (使用 AGL)
    out->rel_altitude = cfg->altitude_agl;

    // 垂直速度
    out->vert_speed = cfg->speed_vertical;

    // 大地高度 (使用 MSL)
    out->geo_altitude = cfg->altitude_msl;

    // 气压高度 (可选, 使用 MSL)
    out->baro_altitude = cfg->altitude_msl;

    // 运行状态
    out->op_status = (cfg->status == 1) ? GB_OP_STATUS_AIRBORNE : GB_OP_STATUS_GROUND;

    // 坐标系 (WGS84)
    out->coord_type = GB_COORD_TYPE_WGS84;

    // 精度 (使用默认值)
    out->h_acc = GB_HACC_LT_3M;
    out->v_acc = GB_VACC_LT_3M;
    out->spd_acc = GB_SPD_ACC_LT_03MS;

    // 时间戳
    out->timestamp = encode_timestamp();
    out->ts_acc = get_ts_acc();

    // 标志位将在编码时自动计算
}