#ifndef RID_CONFIG_H
#define RID_CONFIG_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"    // 提供 SemaphoreHandle_t

#ifdef __cplusplus
extern "C" {
#endif

// ==================== 飞行模式枚举 ====================
typedef enum {
    FLIGHT_MODE_CIRCLE = 0,
    FLIGHT_MODE_PINGPONG = 1,
    FLIGHT_MODE_S_SEARCH = 2,
    FLIGHT_MODE_HOVER = 3,
    FLIGHT_MODE_RANDOM_WALK = 4,
    FLIGHT_MODE_MAX
} flight_mode_t;

// ==================== 动态配置结构体（用于全局默认参数） ====================
typedef struct {
    double init_lat;
    double init_lon;
    float speed;
    uint8_t flight_mode;
    uint8_t channel;
} rid_dynamic_config_t;

// 全局动态配置变量（在 rid_config.c 中定义）
extern rid_dynamic_config_t g_rid_config;
extern SemaphoreHandle_t g_rid_config_mutex;

#define rid_NVS_NAMESPACE "rid_cfg"
#define RID_UAS_ID_MAX_LEN 20
#define rid_SSID_MAX_LEN 32
#define DEFAULT_WIFI_CHANNEL 6

// ==================== 实例完整配置结构体 ====================
typedef struct {
    // MAC 地址
    uint8_t mac_address[6];

    // --- 通用字段（GB42590 / ASTM / GB46750 共用） ---
    char uas_id[21];              // UAS ID / 唯一产品识别码
    uint8_t id_type;              // ID类型（0=None,1=Serial,2=CAA,3=UTM,4=Session）
    uint8_t ua_type;              // UA类型（0=None,1=Aeroplane,2=Helicopter,...）
    float latitude;               // 纬度
    float longitude;              // 经度
    float altitude_msl;           // 几何高度（MSL）
    float altitude_agl;           // 相对高度（AGL / 起飞点高度）
    float speed_horizontal;       // 地速 (m/s)
    float speed_vertical;         // 垂直速度 (m/s)
    float heading;                // 航向 (度)
    uint8_t status;               // 运行状态 (0=Undeclared,1=Ground,2=Airborne,3=Emergency,4=Failure)
    float operator_lat;           // 控制站纬度
    float operator_lon;           // 控制站经度
    float operator_alt;           // 控制站高度
    char operator_id[21];         // 操作员ID
    char drone_name[21];          // 无人机名称（Self-ID）
    uint8_t operator_location_type; // 控制站位置类型 (0=Takeoff,1=Dynamic,2=Fixed)
    uint8_t category_eu;          // 运行类别 (0=Undefined,1=Open,2=Specific,3=Certified)
    uint8_t class_eu;             // 等级 (0=Undefined,1-7=Class0-6)
    uint8_t height_type;          // 高度类型 (0=Over Takeoff,1=AGL)
    char ssid[rid_SSID_MAX_LEN + 1];
    uint8_t channel;
    uint8_t message_counter;
    double base_latitude;          // 巡航基准纬度
    double base_longitude;         // 巡航基准经度
    float base_altitude_msl;
    float patrol_radius_lat;       // 经度方向半径
    float patrol_radius_lon;       // 纬度方向半径
    float patrol_speed;            // 巡航速度
    float time_counter;            // 时间计数器（用于相位）
    uint8_t flight_mode;           // 飞行模式（对应 flight_mode_t）

    // --- GB46750 特有字段 ---
    char reg_mark[9];              // 实名登记标志（8位字符 + '\0'）
    uint8_t op_category;           // 运行类别（0=未定义,1=开放类,2=特定类,3=审定类）
    uint8_t ua_class;              // 无人机分类（0=微型,1=轻型,2=小型,3=中型,4=大型）
    uint8_t gcs_pos_type;          // 遥控站位置类型（0=起飞点,1=遥控站）
    uint8_t coord_type;            // 坐标系类型（0=WGS-84,1=CGCS2000）
    uint8_t h_acc;                 // 水平精度（0-12）
    uint8_t v_acc;                 // 垂直精度（0-6）
    uint8_t spd_acc;               // 速度精度（0-4）
    uint8_t ts_acc;                // 时间戳精度（0-8）
} rid_config_t;

// ==================== 系统信息结构体 ====================
typedef struct {
    char chip_model[16];
    char flash_size[8];
    char mac_addr[18];
    uint32_t uptime_sec;
    char sys_time[32];
    uint32_t free_heap;
    char partition_name[16];
} rid_sys_info_t;

// ==================== 函数声明 ====================

// 系统信息
void rid_get_sys_info(rid_sys_info_t *info);
void rid_get_config_snapshot(rid_dynamic_config_t *cfg);
void rid_time_sync_init(void);

// NVS 管理（全局动态配置）
esp_err_t rid_nvs_init(void);
esp_err_t rid_nvs_load_config(rid_dynamic_config_t *cfg);
esp_err_t rid_nvs_save_config(const rid_dynamic_config_t *cfg);

// 实例配置初始化与更新
void rid_config_init_default(rid_config_t *config);
void rid_config_update_position(rid_config_t *config, float lat, float lon,
                                float alt_msl, float alt_agl, float speed_h,
                                float speed_v, float heading);


                                
#ifdef __cplusplus
}
#endif

#endif // RID_CONFIG_H