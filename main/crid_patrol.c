#include "crid_patrol.h"
#include <math.h>
#include "esp_log.h"

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

static const char *TAG = "CN_C-RID_PATROL";

// 预计算常量，避免每次调用都重新计算
static const float SPEED_ANGULAR_FACTOR = 0.1f;
static const float ALTITUDE_AMPLITUDE = 5.0f;
static const float SPEED_H_BASE = 1.5f;
static const float SPEED_H_AMPLITUDE = 0.5f;
static const float SPEED_V_AMPLITUDE = 0.5f;
static const float RAD_TO_DEG = 180.0f / M_PI;

void crid_patrol_step(cn_crid_config_t *config) {
    if (config == NULL) return;

    config->time_counter += 1.0f;

    // 预计算角度和三角函数值
    const float angle = config->time_counter * config->patrol_speed;
    const float cos_angle = cosf(angle);
    const float sin_angle = sinf(angle);
    
    // 圆形巡游路径
    float new_lat = config->base_latitude + config->patrol_radius_lat * cos_angle;
    float new_lon = config->base_longitude + config->patrol_radius_lon * sin_angle;

    // 高度周期性缓慢变化：在 45m ~ 55m 之间波动，周期约 62.8 秒
    // 使用基准高度计算偏移，避免累积误差
    const float time_angle = config->time_counter * SPEED_ANGULAR_FACTOR;
    const float sin_time = sinf(time_angle);
    const float cos_time = cosf(time_angle);
    
    float alt_offset = ALTITUDE_AMPLITUDE * sin_time;
    float new_alt_msl = config->base_altitude_msl + alt_offset;
    float new_alt_agl = new_alt_msl - 5.0f;

    // 速度变化
    float new_speed_h = SPEED_H_BASE + SPEED_H_AMPLITUDE * sin_time;
    // 垂直速度 = 高度对时间的导数：d/dt[5*sin(0.1*t)] = 0.5*cos(0.1*t)
    // 幅度 ±0.5 m/s，符合低速飞行特征
    float new_speed_v = SPEED_V_AMPLITUDE * cos_time;

    // 航向（基于运动切线方向，正北为 0°，顺时针增加）
    // 位置：lat = base + r_lat*cos(angle), lon = base + r_lon*sin(angle)
    // d(lat)/dt = -r_lat*sin(angle)*omega, d(lon)/dt = r_lon*cos(angle)*omega
    // 航向 = atan2(dlon, dlat) （注意：atan2(x, y) 给出从 y 轴顺时针的角度）
    const float dlat = -config->patrol_radius_lat * sin_angle * config->patrol_speed;
    const float dlon = config->patrol_radius_lon * cos_angle * config->patrol_speed;
    float new_heading = atan2f(dlon, dlat) * RAD_TO_DEG;
    if (new_heading < 0.0f) new_heading += 360.0f;

    crid_config_update_position(config, new_lat, new_lon,
                                new_alt_msl, new_alt_agl,
                                new_speed_h, new_speed_v,
                                new_heading);

    ESP_LOGI(TAG, "Patrol step: pos=(%.6f,%.6f), alt=%.1fm, hdg=%.1f°, spd=%.1fm/s",
             new_lat, new_lon, new_alt_msl, new_heading, new_speed_h);
}
