#ifndef RID_PATROL_H
#define RID_PATROL_H

#include "rid_config.h"
#include "rid_standard.h"
#include <stdint.h>
#include <stdbool.h>



// ==================== 场景类型枚举 ====================
typedef enum {
    PATROL_SCENARIO_HOVER = 0,         // 悬停
    PATROL_SCENARIO_CIRCLE,            // 匀速圆周
    PATROL_SCENARIO_FIGURE_EIGHT,      // 8 字轨迹
    PATROL_SCENARIO_LINE,              // 直线匀速
    PATROL_SCENARIO_RANDOM_WALK,       // 随机游走
    PATROL_SCENARIO_MAX
} patrol_scenario_t;

// 兼容旧的 flight_mode 枚举
// 注意：这些值映射到新的场景类型
#define PATROL_MODE_CIRCLE     PATROL_SCENARIO_CIRCLE
#define PATROL_MODE_PINGPONG   PATROL_SCENARIO_LINE       // 直线往返可视为直线
#define PATROL_MODE_S_SEARCH   PATROL_SCENARIO_FIGURE_EIGHT  // S 形搜索可视为 8 字

// ==================== 轨迹参数结构体 ====================
typedef struct {
    patrol_scenario_t scenario;        // 场景类型
    double center_lat;                 // 中心纬度 (度)
    double center_lon;                 // 中心经度 (度)
    float altitude_msl;                // 海拔高度 (米)
    float altitude_agl;                // 离地高度 (米)
    float radius;                      // 半径 (度，用于圆周和 8 字)
    float speed;                       // 速度 (m/s)
    float heading_initial;             // 初始航向 (度)
    float period;                      // 周期 (秒，用于圆周和 8 字)
    float amplitude;                   // 振幅 (度，用于 8 字)
    bool randomize;                    // 是否随机初始化位置
    float time_offset;                 // 时间偏移 (秒)，用于不同实例错开相位
} patrol_params_t;

// ==================== API 函数 ====================

/**
 * @brief 根据场景参数和时间计算当前位置
 * @param params      场景参数指针
 * @param time_sec    当前时间 (秒)
 * @param out_lat     输出纬度 (度)
 * @param out_lon     输出经度 (度)
 * @param out_heading 输出航向 (度)
 */
void rid_patrol_calculate(const patrol_params_t *params,
                          double time_sec,
                          double *out_lat,
                          double *out_lon,
                          float *out_heading);

/**
 * @brief 获取默认的场景参数
 * @param scenario 场景类型
 * @return 填充好的参数结构体
 */
patrol_params_t rid_patrol_default_params(patrol_scenario_t scenario);

/**
 * @brief 从旧的 flight_mode 和配置生成场景参数
 * @param mode       flight_mode (0=Circle, 1=PingPong, 2=S-Search)
 * @param base_cfg   基础配置 (提供经纬度、速度等)
 * @param out_params 输出参数
 */
void rid_patrol_params_from_mode(uint8_t mode,
                                 const rid_config_t *base_cfg,
                                 patrol_params_t *out_params);

/**
 * @brief 兼容旧接口：根据全局 flight_mode 计算下一个位置
 * @param lat  输出纬度
 * @param lon  输出经度
 * @param heading 输出航向
 * 
 * @deprecated 建议使用 rid_patrol_calculate 和实例自己的参数
 */
void rid_patrol_calculate_next(double *lat, double *lon, float *heading);

/**
 * @brief 兼容旧接口：根据指定的 flight_mode 计算下一个位置
 * @param mode 飞行模式
 * @param lat  输出纬度
 * @param lon  输出经度
 * @param heading 输出航向
 * 
 * @deprecated 建议使用 rid_patrol_calculate 和实例自己的参数
 */
void rid_patrol_calculate_next_with_mode(int mode, double *lat, double *lon, float *heading);

/**
 * @brief 批量生成实例配置（用于测试）
 * @param std         标准类型
 * @param count       实例数量
 * @param base_id     基础 UAS ID 前缀
 * @param params      场景参数（所有实例共享同一场景，但位置随机偏移）
 * @param out_configs 输出配置数组（需提前分配 count 个）
 * @return 实际生成的实例数
 */
int rid_patrol_generate_batch(rid_standard_t std,
                              int count,
                              const char *base_id,
                              const patrol_params_t *params,
                              rid_config_t *out_configs);

#ifdef __cplusplus
}
#endif

#endif // RID_PATROL_H