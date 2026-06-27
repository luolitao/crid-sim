#include "rid_patrol.h"
#include "rid_config.h"
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "esp_log.h"

static const char *TAG = "RID_PATROL";

// ==================== 内部辅助函数 ====================

static double deg_to_rad(double deg) {
    return deg * M_PI / 180.0;
}

static double rad_to_deg(double rad) {
    return rad * 180.0 / M_PI;
}

// ==================== 默认参数 ====================

patrol_params_t rid_patrol_default_params(patrol_scenario_t scenario) {
    patrol_params_t p = {
        .scenario = scenario,
        .center_lat = 23.14287,
        .center_lon = 113.26026,
        .altitude_msl = 50.0f,
        .altitude_agl = 50.0f,
        .radius = 0.0005f,        // ~55m
        .speed = 5.0f,
        .heading_initial = 0.0f,
        .period = 60.0f,
        .amplitude = 0.0005f,
        .randomize = false,
        .time_offset = 0.0f
    };

    switch (scenario) {
        case PATROL_SCENARIO_HOVER:
            p.speed = 0.0f;
            p.radius = 0.0f;
            break;
        case PATROL_SCENARIO_CIRCLE:
            p.speed = 10.0f;
            p.radius = 0.001f;   // ~110m
            p.period = 60.0f;
            break;
        case PATROL_SCENARIO_FIGURE_EIGHT:
            p.speed = 8.0f;
            p.radius = 0.001f;
            p.amplitude = 0.001f;
            p.period = 90.0f;
            break;
        case PATROL_SCENARIO_LINE:
            p.speed = 15.0f;
            p.radius = 0.0f;
            p.heading_initial = 45.0f;
            break;
        case PATROL_SCENARIO_RANDOM_WALK:
            p.speed = 3.0f;
            p.radius = 0.0f;
            p.randomize = true;
            break;
        default:
            break;
    }
    return p;
}

// ==================== 核心计算函数 ====================

void rid_patrol_calculate(const patrol_params_t *params,
                          double time_sec,
                          double *out_lat,
                          double *out_lon,
                          float *out_heading) {
    if (!params) {
        if (out_lat) *out_lat = 0;
        if (out_lon) *out_lon = 0;
        if (out_heading) *out_heading = 0;
        return;
    }

    double lat = params->center_lat;
    double lon = params->center_lon;
    float heading = params->heading_initial;

    // 应用时间偏移，使不同实例错开相位
    double t = time_sec + params->time_offset;

    double rad_radius = deg_to_rad((double)params->radius);
    double rad_amplitude = deg_to_rad((double)params->amplitude);

    switch (params->scenario) {
        case PATROL_SCENARIO_HOVER:
            // 位置不变
            break;

        case PATROL_SCENARIO_CIRCLE: {
            double angle = 2.0 * M_PI * t / params->period;
            lat += rad_radius * sin(angle);
            lon += rad_radius * cos(angle);
            heading = rad_to_deg(angle + M_PI / 2.0);
            if (heading >= 360.0f) heading -= 360.0f;
            break;
        }

        case PATROL_SCENARIO_FIGURE_EIGHT: {
            double angle = 2.0 * M_PI * t / params->period;
            double x = rad_radius * sin(angle);
            double y = rad_amplitude * sin(2.0 * angle) / 2.0;
            lat += x;
            lon += y;
            // 航向近似为轨迹切线方向
            double dx = rad_radius * cos(angle);
            double dy = rad_amplitude * cos(2.0 * angle);
            heading = rad_to_deg(atan2(dy, dx));
            if (heading < 0) heading += 360.0f;
            break;
        }

        case PATROL_SCENARIO_LINE: {
            double rad_h = deg_to_rad(params->heading_initial);
            double dist = params->speed * t;
            // 经纬度换算：1度纬度约111.32km，1度经度随纬度变化
            double lat_per_meter = 1.0 / 111320.0;
            double lon_per_meter = 1.0 / (111320.0 * cos(deg_to_rad(lat)));
            lat += dist * sin(rad_h) * lat_per_meter;
            lon += dist * cos(rad_h) * lon_per_meter;
            heading = params->heading_initial;
            break;
        }

        case PATROL_SCENARIO_RANDOM_WALK: {
            // 使用正弦和余弦产生确定性伪随机运动
            double phase = t * 0.13;
            lat += 0.00015 * sin(phase * 1.3) + 0.00008 * cos(phase * 0.7);
            lon += 0.00015 * cos(phase * 0.9) + 0.00008 * sin(phase * 1.1);
            heading = fmod(t * 8.0 + params->heading_initial, 360.0f);
            break;
        }

        default:
            break;
    }

    if (out_lat) *out_lat = lat;
    if (out_lon) *out_lon = lon;
    if (out_heading) *out_heading = heading;
}

// ==================== 兼容旧接口 ====================

// 全局变量用于兼容旧接口
// 注意：这些变量仅供旧接口使用，新代码应使用参数结构体
static float g_altitude_msl = 50.0f;
static float g_altitude_agl = 60.0f;
static double g_center_lat = 23.14287;
static double g_center_lon = 113.26026;
static float g_speed = 5.0f;
static float g_heading_initial = 0.0f;
static float g_period = 60.0f;
static float g_radius = 0.001f;
static float g_amplitude = 0.001f;

static patrol_params_t g_global_params;

// 更新全局参数（由 rid_config_update_position 间接调用）
void rid_patrol_update_global_params(const rid_config_t *cfg) {
    if (!cfg) return;
    g_center_lat = cfg->base_latitude;
    g_center_lon = cfg->base_longitude;
    g_altitude_msl = cfg->altitude_msl;
    g_altitude_agl = cfg->altitude_agl;
    g_speed = cfg->patrol_speed;
    g_global_params.center_lat = g_center_lat;
    g_global_params.center_lon = g_center_lon;
    g_global_params.altitude_msl = g_altitude_msl;
    g_global_params.altitude_agl = g_altitude_agl;
    g_global_params.speed = g_speed;
}

void rid_patrol_params_from_mode(uint8_t mode, const rid_config_t *base_cfg, patrol_params_t *out_params) {
    patrol_scenario_t scenario;
    switch (mode) {
        case 0: scenario = PATROL_SCENARIO_CIRCLE; break;
        case 1: scenario = PATROL_SCENARIO_LINE; break;    // PingPong
        case 2: scenario = PATROL_SCENARIO_FIGURE_EIGHT; break; // S-Search
        case 3: scenario = PATROL_SCENARIO_HOVER; break;
        case 4: scenario = PATROL_SCENARIO_RANDOM_WALK; break;
        default: scenario = PATROL_SCENARIO_HOVER; break;
    }
    *out_params = rid_patrol_default_params(scenario);
    out_params->center_lat = base_cfg->base_latitude;
    out_params->center_lon = base_cfg->base_longitude;
    out_params->altitude_msl = base_cfg->altitude_msl;
    out_params->altitude_agl = base_cfg->altitude_agl;
    out_params->speed = base_cfg->patrol_speed;
    out_params->time_offset = (float)base_cfg->time_counter * 0.1f;
}

void rid_patrol_calculate_next(double *lat, double *lon, float *heading) {
    // 使用全局配置中的飞行模式
    int mode = 0; // 从 g_rid_config 获取
    // 实际应传入 mode，这里使用默认
    rid_patrol_calculate_next_with_mode(0, lat, lon, heading);
}

void rid_patrol_calculate_next_with_mode(int mode, double *lat, double *lon, float *heading) {
    // 构建临时参数
    patrol_params_t params = rid_patrol_default_params(PATROL_SCENARIO_HOVER);
    switch (mode) {
        case 0: params.scenario = PATROL_SCENARIO_CIRCLE; break;
        case 1: params.scenario = PATROL_SCENARIO_LINE; break;
        case 2: params.scenario = PATROL_SCENARIO_FIGURE_EIGHT; break;
        default: params.scenario = PATROL_SCENARIO_HOVER; break;
    }
    params.center_lat = g_center_lat;
    params.center_lon = g_center_lon;
    params.altitude_msl = g_altitude_msl;
    params.altitude_agl = g_altitude_agl;
    params.speed = g_speed;
    params.period = g_period;
    params.radius = g_radius;
    params.amplitude = g_amplitude;

    // 使用当前时间
    double time_sec = 0; // 实际应使用 esp_timer_get_time()
    rid_patrol_calculate(&params, time_sec, lat, lon, heading);
}

// ==================== 批量生成（原 mock 功能） ====================

static void generate_uas_id(char *buf, size_t size, const char *prefix, int index) {
    if (prefix == NULL) prefix = "DRONE";
    snprintf(buf, size, "%s-%03d", prefix, index);
}

int rid_patrol_generate_batch(rid_standard_t std,
                              int count,
                              const char *base_id,
                              const patrol_params_t *params,
                              rid_config_t *out_configs) {
    if (count <= 0 || !out_configs || !params) return 0;

    int generated = 0;
    for (int i = 0; i < count; i++) {
        rid_config_t *cfg = &out_configs[i];
        char uas_id[32];
        generate_uas_id(uas_id, sizeof(uas_id), base_id ? base_id : "DRONE", i + 1);

        rid_config_init_default(cfg);
        strncpy(cfg->uas_id, uas_id, sizeof(cfg->uas_id) - 1);
        cfg->uas_id[sizeof(cfg->uas_id) - 1] = '\0';

        // 对每个实例添加随机偏移（如果启用）
        patrol_params_t local_params = *params;
        if (params->randomize) {
            local_params.center_lat += (double)(rand() % 10000) * 0.0000001;
            local_params.center_lon += (double)(rand() % 10000) * 0.0000001;
            local_params.time_offset = (float)(rand() % 1000) * 0.1f;
        }

        cfg->latitude = (float)local_params.center_lat;
        cfg->longitude = (float)local_params.center_lon;
        cfg->altitude_msl = local_params.altitude_msl;
        cfg->altitude_agl = local_params.altitude_agl;
        cfg->speed_horizontal = local_params.speed;
        cfg->heading = local_params.heading_initial;
        cfg->base_latitude = local_params.center_lat;
        cfg->base_longitude = local_params.center_lon;
        cfg->patrol_speed = local_params.speed;
        cfg->time_counter = local_params.time_offset;

        generated++;
    }
    return generated;
}