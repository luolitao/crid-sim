#include "crid_patrol.h"
#include <math.h>
#include "esp_log.h"

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

static const char *TAG = "CN_C-RID_PATROL";

void crid_patrol_step(cn_crid_config_t *config) {
    if (config == NULL) return;

    config->time_counter += 1.0f;

    float angle = config->time_counter * config->patrol_speed;

    // 圆形巡游路径
    float new_lat = config->base_latitude +
                    config->patrol_radius_lat * cosf(angle);
    float new_lon = config->base_longitude +
                    config->patrol_radius_lon * sinf(angle);

    // 高度轻微波动
    float new_alt_msl = config->altitude_msl +
                        0.5f * sinf(config->time_counter * 0.1f);
    float new_alt_agl = new_alt_msl - 5.0f;

    // 速度变化
    float new_speed_h = 1.5f + 0.5f * sinf(config->time_counter * 0.1f);
    float new_speed_v = 0.1f * cosf(config->time_counter * 0.1f);

    // 航向（基于运动切线方向）
    float dx = config->patrol_radius_lon * cosf(angle) * config->patrol_speed;
    float dy = -config->patrol_radius_lat * sinf(angle) * config->patrol_speed;
    float new_heading = atan2f(dy, dx) * 180.0f / M_PI;
    if (new_heading < 0.0f) new_heading += 360.0f;

    crid_config_update_position(config, new_lat, new_lon,
                                new_alt_msl, new_alt_agl,
                                new_speed_h, new_speed_v,
                                new_heading);

    ESP_LOGI(TAG, "Patrol step: pos=(%.6f,%.6f), alt=%.1fm, hdg=%.1f°, spd=%.1fm/s",
             new_lat, new_lon, new_alt_msl, new_heading, new_speed_h);
}
