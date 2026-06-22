#ifndef rid_PATROL_H
#define rid_PATROL_H

#include "rid_config.h"

/**
 * 多模式轨迹状态机计算引擎
 * @param out_lat 计算得到的当前纬度输出
 * @param out_lon 计算得到的当前经度输出
 * @param out_heading 当前航向角输出 (0~360度)
 */
void rid_patrol_calculate_next(double *out_lat, double *out_lon, float *out_heading);

/**
 * @brief 执行一步巡游位置更新
 *
 * 在基准位置周围做圆形巡游运动，更新 config 中的位置、高度、速度和航向。
 * 每调用一次推进一个时间步长。
 *
 * @param config 配置结构体指针（会原地更新）
 */

void rid_patrol_step(rid_config_t *config);

void rid_patrol_calculate_next_with_mode(int mode, double *lat, double *lon, float *heading);

#endif // rid_PATROL_H