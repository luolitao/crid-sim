// rid_gb46750.h
#ifndef RID_GB46750_H
#define RID_GB46750_H

#include "rid_config.h"
#include <stdint.h>
#include <stdbool.h>

// ==================== GB46750-2025 固定常量 ====================
#define GB_DATA_TYPE           0xFF        // 数据类型固定值[reference:4]
#define GB_VERSION_BASE        0x20        // 版本固定 0x20（二进制 001xxxxx）[reference:5]

// ==================== 数据标识位掩码（第1字节）[reference:6] ====================
#define GB_FLAG_BYTE1_UAS_ID        0x80    // 001 唯一产品识别码 (M)
#define GB_FLAG_BYTE1_REG_MARK      0x40    // 002 实名登记标志 (M)
#define GB_FLAG_BYTE1_OP_CATEGORY   0x20    // 003 运行类别 (O)
#define GB_FLAG_BYTE1_UA_CLASS      0x10    // 004 无人机分类 (M)
#define GB_FLAG_BYTE1_GCS_POS_TYPE  0x08    // 005 遥控站位置类型 (M)
#define GB_FLAG_BYTE1_GCS_POS       0x04    // 006 遥控站位置 (M)
#define GB_FLAG_BYTE1_GCS_ALT       0x02    // 007 遥控站高度 (M)
#define GB_FLAG_BYTE1_EXT           0x01    // 扩展标志位

// ==================== 数据标识位掩码（第2字节）[reference:7] ====================
#define GB_FLAG_BYTE2_UA_POS        0x80    // 008 无人机位置 (M)
#define GB_FLAG_BYTE2_TRACK         0x40    // 009 航迹角 (M)
#define GB_FLAG_BYTE2_GROUND_SPEED  0x20    // 010 地速 (M)
#define GB_FLAG_BYTE2_REL_ALT       0x10    // 011 相对高度 (O)
#define GB_FLAG_BYTE2_VERT_SPEED    0x08    // 012 垂直速度 (O)
#define GB_FLAG_BYTE2_GEO_ALT       0x04    // 013 大地高度 (M)
#define GB_FLAG_BYTE2_BARO_ALT      0x02    // 014 气压高度 (O)
#define GB_FLAG_BYTE2_EXT           0x01    // 扩展标志位

// ==================== 数据标识位掩码（第3字节）[reference:8] ====================
#define GB_FLAG_BYTE3_OP_STATUS     0x80    // 015 运行状态 (M)
#define GB_FLAG_BYTE3_COORD_TYPE    0x40    // 016 坐标系类型 (M)
#define GB_FLAG_BYTE3_H_ACC         0x20    // 017 水平精度 (M)
#define GB_FLAG_BYTE3_V_ACC         0x10    // 018 垂直精度 (M)
#define GB_FLAG_BYTE3_SPD_ACC       0x08    // 019 速度精度 (M)
#define GB_FLAG_BYTE3_TIMESTAMP     0x04    // 020 时间戳 (M)
#define GB_FLAG_BYTE3_TS_ACC        0x02    // 021 时间戳精度 (M)
#define GB_FLAG_BYTE3_EXT           0x00    // 扩展标志位

// ==================== 枚举定义[reference:9] ====================
// 运行类别 (003)
/*
0:未定义 ;
1:开放类 ;
2:特定类 ;
3:审定类 ; 
4~ 15:预留
*/
typedef enum {
    GB_OP_CATEGORY_UNDEFINED = 0,
    GB_OP_CATEGORY_OPEN = 1,
    GB_OP_CATEGORY_SPECIFIC = 2,
    GB_OP_CATEGORY_CERTIFIED = 3
} gb_op_category_t;

// 无人机分类 (004)
/*
0:微型无人驾驶航空器 ;
1:轻型无人驾驶航空器 ;
2:小型无人驾驶航空器 ;
3: 中型无人驾驶航空器 ;
4:大型无人驾驶航空器 ; 
5~ 15:预留
*/
typedef enum {
    GB_UA_CLASS_MICRO = 0,
    GB_UA_CLASS_LIGHT = 1,
    GB_UA_CLASS_SMALL = 2,
    GB_UA_CLASS_MEDIUM = 3,
    GB_UA_CLASS_LARGE = 4
} gb_ua_class_t;

// 遥控站位置类型 (005)
/*
0:起飞点位置 ;
1:遥控站位置 ; 
2~ 15:预留
*/
typedef enum {
    GB_GCS_POS_TYPE_TAKEOFF = 0,
    GB_GCS_POS_TYPE_GCS = 1
} gb_gcs_pos_type_t;

// 运行状态 (015)
/*
0:未报告 ;
1:地面 ;
2:空中 ;
3: 民用无人驾驶航空器为紧急状态 ;
4:运行识别发送功能失效(民用无人驾驶航空器为非紧急状态);
5:运行识别发送功能失效(民用无人驾驶航空器为紧急状态) ;
6~ 15:预留
*/
typedef enum {
    GB_OP_STATUS_NOT_REPORTED = 0,
    GB_OP_STATUS_GROUND = 1,
    GB_OP_STATUS_AIRBORNE = 2,
    GB_OP_STATUS_EMERGENCY = 3,
    GB_OP_STATUS_RID_FAIL_NORMAL = 4,
    GB_OP_STATUS_RID_FAIL_EMERG = 5
} gb_op_status_t;

// 坐标系类型 (016)
typedef enum {
    GB_COORD_TYPE_WGS84 = 0,
    GB_COORD_TYPE_CGCS2000 = 1
} gb_coord_type_t;

// 水平精度 NACp (017)[reference:10]
/*
置信度为95% ,取值范围为 :
0:大于或等于18.52 km ( 10 n mile) 或未知 ;
1:小于18.52 km(10 n mile) ;
2:小于7.41 km(4 n mile) ;
3:小于3.70 km(2 n mile) ;
4:小于1852 m(1 n mile) ;
5:小于926 m(0. 5 n mile) ;
6:小于556 m(0. 3 n mile) ;
7:小于185 m(0. 1 n mile) ;
8:小于92. 6 m(0. 05 n mile) ;
9:小于30 m ;
10:小于10 m ;
11:小于3 m ;
12:小于1 m ; 
13~15:预留
*/
typedef enum {
    GB_HACC_UNKNOWN_OR_GTE_18520M = 0,
    GB_HACC_LT_18520M = 1,
    GB_HACC_LT_7410M = 2,
    GB_HACC_LT_3700M = 3,
    GB_HACC_LT_1852M = 4,
    GB_HACC_LT_926M = 5,
    GB_HACC_LT_556M = 6,
    GB_HACC_LT_185M = 7,
    GB_HACC_LT_92M = 8,
    GB_HACC_LT_30M = 9,
    GB_HACC_LT_10M = 10,
    GB_HACC_LT_3M = 11,
    GB_HACC_LT_1M = 12
} gb_hacc_t;

// 垂直精度 GVA (018)[reference:11]
/*
置信度为95% ,取值范围为:
0:大于或等于150 m或未知;
1:小于150 m ;
2:小于45 m ;
3:小于25 m ;
4:小于10 m ;
5:小于3 m ;
6:小于1 m ; 
7~15:预留
*/
typedef enum {
    GB_VACC_UNKNOWN_OR_GTE_150M = 0,
    GB_VACC_LT_150M = 1,
    GB_VACC_LT_45M = 2,
    GB_VACC_LT_25M = 3,
    GB_VACC_LT_10M = 4,
    GB_VACC_LT_3M = 5,
    GB_VACC_LT_1M = 6
} gb_vacc_t;

// 速度精度 NACv (019)[reference:12]
typedef enum {
    GB_SPD_ACC_UNKNOWN_OR_GTE_10MS = 0,
    GB_SPD_ACC_LT_10MS = 1,
    GB_SPD_ACC_LT_3MS = 2,
    GB_SPD_ACC_LT_1MS = 3,
    GB_SPD_ACC_LT_03MS = 4
} gb_spd_acc_t;

// 时间戳精度 (021)[reference:13]
typedef enum {
    GB_TS_ACC_UNKNOWN_OR_GT_500MS = 0,
    GB_TS_ACC_LTE_500MS = 1,
    GB_TS_ACC_LTE_400MS = 2,
    GB_TS_ACC_LTE_300MS = 3,
    GB_TS_ACC_LTE_200MS = 4,
    GB_TS_ACC_LTE_100MS = 5,
    GB_TS_ACC_LTE_50MS = 6,
    GB_TS_ACC_LTE_20MS = 7,
    GB_TS_ACC_LTE_10MS = 8
} gb_ts_acc_t;

// ==================== GB46750 数据包结构 ====================
typedef struct {
    // 必填字段 (M)
    char uas_id[20];                // 001 唯一产品识别码
    char reg_mark[8];               // 002 实名登记标志 (0=未登记, 1=已登记)
    gb_ua_class_t ua_class;         // 004 无人机分类
    gb_gcs_pos_type_t gcs_pos_type; // 005 遥控站位置类型
    double gcs_latitude;            // 006 遥控站位置 (度)
    double gcs_longitude;           // 006 遥控站位置 (度)
    float gcs_altitude;             // 007 遥控站高度 (米)
    double ua_latitude;             // 008 无人机位置 (度)
    double ua_longitude;            // 008 无人机位置 (度)
    float track_angle;              // 009 航迹角 (度, 0-360)
    float ground_speed;             // 010 地速 (m/s)
    float geo_altitude;             // 013 大地高度 (米)
    gb_op_status_t op_status;       // 015 运行状态
    gb_coord_type_t coord_type;     // 016 坐标系类型
    gb_hacc_t h_acc;                // 017 水平精度
    gb_vacc_t v_acc;                // 018 垂直精度
    gb_spd_acc_t spd_acc;           // 019 速度精度
    uint32_t timestamp;             // 020 时间戳 (自 2019-01-01 00:00:00 UTC 的秒数)
    gb_ts_acc_t ts_acc;             // 021 时间戳精度

    // 可选字段 (O)
    gb_op_category_t op_category;   // 003 运行类别
    float rel_altitude;             // 011 相对高度 (米)
    float vert_speed;               // 012 垂直速度 (m/s)
    float baro_altitude;            // 014 气压高度 (米)

    // 标志位自动计算
    uint8_t flag_byte1;
    uint8_t flag_byte2;
    uint8_t flag_byte3;
} gb46750_data_t;

// ==================== GB46750 编码器 API ====================

/**
 * @brief 编码 GB46750 数据包
 * @param data  输入数据
 * @param out   输出缓冲区
 * @param max_len 缓冲区最大长度
 * @return 实际编码长度，失败返回 -1
 */
int gb46750_encode(const gb46750_data_t *data, uint8_t *out, size_t max_len);

/**
 * @brief 从 rid_config_t 转换为 gb46750_data_t
 * @param cfg   源配置
 * @param out  目标 GB46750 数据
 */
void gb46750_from_config(const rid_config_t *cfg, gb46750_data_t *out);


#endif // RID_GB46750_H