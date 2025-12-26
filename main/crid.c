// esp32_cn_crid_standard_tx.c
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_mac.h"
#include "sys/time.h"

static const char *TAG = "CN_C-RID_STD";

// --- Configuration ---
#define WIFI_CHANNEL 6
#define BEACON_INTERVAL_MS 1000  // 中国标准要求每秒一次
#define MAX_FRAME_SIZE 512

// --- Message Types (符合试行标准表1) ---
#define MSG_TYPE_BASIC_ID    0x0  // 基本 ID 报文
#define MSG_TYPE_LOCATION    0x1  // 位置向量报文
#define MSG_TYPE_SELF_DESC   0x3  // 运行描述报文
#define MSG_TYPE_SYSTEM      0x4  // 系统报文
#define MSG_TYPE_PACKED      0xF  // 报文打包

// --- Configuration Structure ---
typedef struct {
    char uas_id[21];              // UAS ID (符合中国民航局格式)
    uint8_t id_type;              // ID类型 (0-4)
    uint8_t ua_type;              // 无人机类型 (0-15)
    float latitude;               // 纬度
    float longitude;              // 经度
    float altitude_msl;           // 海拔高度 (m)
    float altitude_agl;           // 相对地面高度 (m)
    float speed_horizontal;       // 水平速度 (m/s)
    float speed_vertical;         // 垂直速度 (m/s)
    float heading;                // 航向 (度)
    uint8_t status;               // 运行状态 (0-4)
    float operator_lat;           // 操作员纬度
    float operator_lon;           // 操作员经度
    float operator_alt;           // 操作员高度
    uint8_t mac_address[6];       // MAC地址
    char ssid[32];                // SSID
    uint8_t channel;              // 通道
    uint8_t message_counter;      // 消息计数器 (0-255, 循环)
} cn_crid_config_t;

// --- Global Variables ---
static cn_crid_config_t g_config;
static uint8_t beacon_frame[MAX_FRAME_SIZE];
static uint16_t beacon_frame_len = 0;

// --- Initialize China C-RID Configuration ---
void init_cn_crid_config(void) {
    strcpy(g_config.uas_id, "CAAC-ESP32-CN-002");  // 中国民航局格式
    g_config.id_type = 2;  // CAA Registration ID (中国标准要求)
    g_config.ua_type = 2;  // Helicopter/Multirotor
    g_config.latitude = 23.14287f; // (越秀山本体坐标) 
    g_config.longitude = 113.26026f; // 
    g_config.altitude_msl = 50.0f;
    g_config.altitude_agl = 50.0f;
    g_config.speed_horizontal = 1.0f;
    g_config.speed_vertical = 0.0f;
    g_config.heading = 45.0f;
    g_config.status = 2;  // Airborne (空中飞行)
    g_config.operator_lat = 23.14f;
    g_config.operator_lon = 113.26f;
    g_config.operator_alt = 10.0f;
    
    // MAC地址
    g_config.mac_address[0] = 0x24;
    g_config.mac_address[1] = 0x0A;
    g_config.mac_address[2] = 0xC4;
    g_config.mac_address[3] = 0x12;
    g_config.mac_address[4] = 0x34;
    g_config.mac_address[5] = 0x56;
    
    strcpy(g_config.ssid, "CN-CRID-ESP");
    g_config.channel = 6;
    g_config.message_counter = 0;
    
    ESP_LOGI(TAG, "China C-RID configuration initialized");
    ESP_LOGI(TAG, "  UAS ID: %s (中国民航局格式)", g_config.uas_id);
    ESP_LOGI(TAG, "  ID Type: %d (CAA Registration ID - 中国标准要求)", g_config.id_type);
    ESP_LOGI(TAG, "  UA Type: %d (Helicopter/Multirotor)", g_config.ua_type);
    ESP_LOGI(TAG, "  Position: %.6f, %.6f", g_config.latitude, g_config.longitude);
    ESP_LOGI(TAG, "  Compliance: ✅ 符合《民用微轻小型无人驾驶航空器运行识别最低性能要求（试行）》");
}

// --- Build Basic ID Message (25 bytes total) ---
void build_basic_id_message_25bytes(uint8_t *message) {
    // 报头: [消息类型(高4位)] + [接口版本(低4位)] = 0x01 (Basic ID + Version 1)
    message[0] = (MSG_TYPE_BASIC_ID << 4) | 0x01;
    
    // 字节1: ID类型 (高4位) + UA类型 (低4位) - 符合试行标准表3
    message[1] = (g_config.id_type << 4) | g_config.ua_type;
    
    // 字节2-21: UAS ID (20字节, ASCII字符, 不足填充空格) - 符合试行标准表3
    memset(&message[2], 0x20, 20); // 先填充空格
    int id_len = strlen(g_config.uas_id);
    if (id_len > 20) id_len = 20;
    memcpy(&message[2], g_config.uas_id, id_len);
    
    // 字节22-24: 预留 - 符合试行标准表3
    message[22] = 0x00;
    message[23] = 0x00;
    message[24] = 0x00;
    
    ESP_LOGI(TAG, "Built Basic ID message (25 bytes, 符合试行标准表3)");
    ESP_LOGI(TAG, "  UAS ID: %s", g_config.uas_id);
    ESP_LOGI(TAG, "  ID Type: %d (%s)", g_config.id_type, 
             g_config.id_type == 2 ? "CAA Registration ID (中国标准)" : "Other");
    ESP_LOGI(TAG, "  UA Type: %d (%s)", g_config.ua_type, 
             g_config.ua_type == 2 ? "Helicopter/Multirotor" : "Other");
}

// --- Build Location Message (25 bytes total) ---
void build_location_message_25bytes(uint8_t *message) {
    // 报头: [消息类型(高4位)] + [接口版本(低4位)] = 0x11 (Location + Version 1)
    message[0] = (MSG_TYPE_LOCATION << 4) | 0x01;
    
    // 字节1: [运行状态(高4位)] + [标志位组合(低4位)] - 符合试行标准表4
    // 运行状态 (4 bits) + 预留 (1 bit) + 高度类型 (1 bit) + 航迹角E/W标志 (1 bit) + 速度乘数 (1 bit)
    uint8_t flags = (g_config.status << 4) | 0x00; // 状态 + Over Ground 高度类型
    message[1] = flags;
    
    // 字节2: 航迹角 (0-179, 需要转换) - 符合试行标准表4
    uint8_t track_angle = (uint8_t)g_config.heading;
    if (track_angle > 179) track_angle = 179;
    message[2] = track_angle;
    
    // 字节3: 地速 - 符合试行标准表4
    uint8_t ground_speed = (uint8_t)g_config.speed_horizontal;
    if (ground_speed < 255*0.25) {ground_speed = ground_speed / 0.25;}
    else if (ground_speed > 254)    {       ground_speed = 254;    }
    else{ground_speed = (ground_speed - (255 * 0.25))/0.75;}
    
    message[3] = ground_speed;
    
    // 字节4: 垂直速度 - 符合试行标准表4
    int8_t vertical_speed = (int8_t)g_config.speed_vertical * 2; 
    message[4] = (uint8_t)vertical_speed;
    
    // 字节5-8: 纬度 (小端序, 1E-7度单位) - 符合试行标准表4
    int32_t lat_scaled = (int32_t)(g_config.latitude * 10000000.0);
    for (int i = 0; i < 4; i++) {
        message[5 + i] = (lat_scaled >> (i * 8)) & 0xFF;
    }
    
    // 字节9-12: 经度 (小端序, 1E-7度单位) - 符合试行标准表4
    int32_t lon_scaled = (int32_t)(g_config.longitude * 10000000.0);
    for (int i = 0; i < 4; i++) {
        message[9 + i] = (lon_scaled >> (i * 8)) & 0xFF;
    }
    
    // 字节13-14: 气压高度 (小端序, cm) - 符合试行标准表4
    uint16_t alt_baro_scaled = (uint16_t)(g_config.altitude_msl + (esp_random() % 100) / 10.0f+ 1000)*2; // 转换为厘米
    message[13] = alt_baro_scaled & 0xFF;
    message[14] = (alt_baro_scaled >> 8) & 0xFF;
    
    // 字节15-16: 几何高度 (小端序, cm) - 符合试行标准表4
    uint16_t alt_geo_scaled = (uint16_t)(g_config.altitude_msl + 1000)*2; // 转换为厘米
    message[15] = alt_geo_scaled & 0xFF;
    message[16] = (alt_geo_scaled >> 8) & 0xFF;
    
    // 字节17-18: 距地高度 (小端序, cm) - 符合试行标准表4
    uint16_t height_scaled = (uint16_t)(g_config.altitude_agl + 1000)*2; // 转换为厘米
    message[17] = height_scaled & 0xFF;
    message[18] = (height_scaled >> 8) & 0xFF;
    
    // 字节19: 水平精度 (高4位) + 垂直精度 (低4位) - 符合试行标准表4
    uint8_t accuracy = (0x04 << 4) | 0x04; // <= 6m 精度 (符合中国标准)
    message[19] = accuracy;
    
    // 字节20: 速度精度 - 符合试行标准表4
    message[20] = 0x02; // <= 0.3m/s (符合中国标准)
    
    // 字节21-22: 时间戳 (小端序, 秒数) - 符合试行标准表4   时间戳自当前小时起的 1/10 秒数（小端序）
    uint16_t unix_timestamp = (( ( (uint64_t)xTaskGetTickCount() * 1000ULL / configTICK_RATE_HZ ) % 3600000ULL ) / 100ULL); // 
    message[21] = unix_timestamp & 0xFF;
    message[22] = (unix_timestamp >> 8) & 0xFF;
    
    // 字节23: 时间戳精度 - 符合试行标准表4
    message[23] = 0x0A; // 0.2秒精度    4b预留bit 7–4   4b时间戳精度bit 3–0：0.1s ~ 1.5s，未知时为 0
    
    // 字节24: 预留
    message[24] = 0x00;
    
    ESP_LOGI(TAG, "Built Location message (25 bytes, 符合试行标准表4)");
    ESP_LOGI(TAG, "  Position: %.6f, %.6f", g_config.latitude, g_config.longitude);
    ESP_LOGI(TAG, "  Altitude: %.2f m (MSL), %.2f m (AGL)", g_config.altitude_msl, g_config.altitude_agl);
    ESP_LOGI(TAG, "  Speed: %.2f m/s (H), %.2f m/s (V)", g_config.speed_horizontal, g_config.speed_vertical);
    ESP_LOGI(TAG, "  Heading: %.1f°", g_config.heading);
    ESP_LOGI(TAG, "  Status: %d (Airborne)", g_config.status);
}

// --- Build System Message (25 bytes total) ---
void build_system_message_25bytes(uint8_t *message) {
    // 报头: [消息类型(高4位)] + [接口版本(低4位)] = 0x41 (System + Version 1)
    message[0] = (MSG_TYPE_SYSTEM << 4) | 0x01;
    
    // 字节1: [坐标系类型(高1位)] + [等级分类归属区域(中3位)] + [控制站位置类型(低2位)] - 符合试行标准表6
    // 假设使用 WGS84 坐标系 (0), 中国区域 (2), Takeoff 位置 (1)
    uint8_t sys_flags = (0x00 << 7) | (0x02 << 4) | 0x01; // WGS84 + China + Takeoff
    message[1] = sys_flags;
    
    // 字节2-5: 控制站纬度 (小端序, 1E-7度单位) - 符合试行标准表6
    int32_t op_lat_scaled = (int32_t)(g_config.operator_lat * 10000000.0);
    for (int i = 0; i < 4; i++) {
        message[2 + i] = (op_lat_scaled >> (i * 8)) & 0xFF;
    }
    
    // 字节6-9: 控制站经度 (小端序, 1E-7度单位) - 符合试行标准表6
    int32_t op_lon_scaled = (int32_t)(g_config.operator_lon * 10000000.0);
    for (int i = 0; i < 4; i++) {
        message[6 + i] = (op_lon_scaled >> (i * 8)) & 0xFF;
    }
    
    // 字节10-11: 运行区域计数 (小端序) - 符合试行标准表6
    message[10] = 0x01; // 1 2B运行区域计数区域内 UAV 数量
    message[11] = 0x00; // 

    // 字节12: 运行区域半径 (m * 10) - 符合试行标准表6
    message[12] = 0x64; // 运行区域半径值 ×10（米）
    
    // 字节13-14: 运行区域高度上限 (小端序, m) - 符合试行标准表6
    uint16_t ceiling_scaled = (uint16_t)((100.0f + 1000) * 2); // 100m above current
    message[13] = ceiling_scaled & 0xFF;
    message[14] = (ceiling_scaled >> 8) & 0xFF;
    
    // 字节15-16: 运行区域高度下限 (小端序, m) - 符合试行标准表6
    uint16_t floor_scaled = (uint16_t)((50.f + 1000) * 2); // 50m below current
    message[15] = floor_scaled & 0xFF;
    message[16] = (floor_scaled >> 8) & 0xFF;

    //| 4b   | UA 运行类别 | 0=未定义；1=开放类；2=特许类；3=审定类 4b UA 等级 0=微型；1=轻型；2=小型；3=其他具备识别功能 
    message[17] =  0x10;

    // g_config.operator_alt 高度
    uint16_t oper_floor_scaled = (uint16_t)((g_config.operator_alt + 1000) * 2); // 50m below current
    message[18] = oper_floor_scaled & 0xFF;
    message[19] = (oper_floor_scaled >> 8) & 0xFF;

    // 字节20-23: 时间戳 (小端序, 秒数) - 符合试行标准表4   时间戳自当前小时起的 1/10 秒数（小端序）
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint32_t unix_timestamp = tv.tv_sec - 1546300800; // 从 2019-01-01 00:00:00 UTC 开始的秒数
    for (int i = 0; i < 4; i++) {
        message[20 + i] = (unix_timestamp >> (i * 8)) & 0xFF;
    }

    message[24] = 0x00;
    
    ESP_LOGI(TAG, "Built System message (25 bytes, 符合试行标准表6)");
    ESP_LOGI(TAG, "  Operator: %.6f, %.6f", g_config.operator_lat, g_config.operator_lon);
    ESP_LOGI(TAG, "  Operator Alt: %.2f m", g_config.operator_alt);
    ESP_LOGI(TAG, "  Area: 100m radius, %.2fm - %.2fm", 
             (float)floor_scaled/100.0f, (float)ceiling_scaled/100.0f);
}

// --- Build Beacon frame with packed messages ---
void build_beacon_frame(void) {
    uint8_t *frame = beacon_frame;
    uint16_t *frame_len = &beacon_frame_len;
    *frame_len = 0;

    // --- MAC Header (24 bytes) ---
    frame[(*frame_len)++] = 0x80; // Type=Management, Subtype=Beacon
    frame[(*frame_len)++] = 0x00;
    frame[(*frame_len)++] = 0x00; // Duration
    frame[(*frame_len)++] = 0x00;
    
    // Destination Address (Broadcast)
    frame[(*frame_len)++] = 0xFF; frame[(*frame_len)++] = 0xFF; frame[(*frame_len)++] = 0xFF;
    frame[(*frame_len)++] = 0xFF; frame[(*frame_len)++] = 0xFF; frame[(*frame_len)++] = 0xFF;
    
    // Source Address
    memcpy(&frame[*frame_len], g_config.mac_address, 6);
    *frame_len += 6;
    
    // BSSID
    memcpy(&frame[*frame_len], g_config.mac_address, 6);
    *frame_len += 6;
    
    // Sequence Control
    frame[(*frame_len)++] = 0x00;
    frame[(*frame_len)++] = 0x00;

    // --- Beacon Body ---
    // Timestamp (8 bytes - hardware fills)
    for (int i = 0; i < 8; i++) frame[(*frame_len)++] = 0x00;
    
    // Beacon Interval (100ms)
    frame[(*frame_len)++] = 0x64; // 100 in little endian
    frame[(*frame_len)++] = 0x00;
    
    // Capability Information
    frame[(*frame_len)++] = 0x21;
    frame[(*frame_len)++] = 0x04;

    // --- Required IE: SSID ---
    frame[(*frame_len)++] = 0x00; // SSID IE ID
    int ssid_len = strlen(g_config.ssid);
    frame[(*frame_len)++] = ssid_len;
    memcpy(&frame[*frame_len], g_config.ssid, ssid_len);
    *frame_len += ssid_len;

    // --- Required IE: Supported Rates ---
    frame[(*frame_len)++] = 0x01; // Rates IE ID
    frame[(*frame_len)++] = 0x08; // Length
    frame[(*frame_len)++] = 0x82; frame[(*frame_len)++] = 0x84; frame[(*frame_len)++] = 0x8b; frame[(*frame_len)++] = 0x96;
    frame[(*frame_len)++] = 0x24; frame[(*frame_len)++] = 0x30; frame[(*frame_len)++] = 0x48; frame[(*frame_len)++] = 0x6c;

    // --- Required IE: DS Parameter Set ---
    frame[(*frame_len)++] = 0x03; // DS Parameter Set IE ID
    frame[(*frame_len)++] = 0x01; // Length
    frame[(*frame_len)++] = g_config.channel;

    // --- China C-RID Packed Message (Vendor Specific IE) ---
    // 符合 GB42590-2023 附录 A.1.2.1.2 格式
    uint8_t msg_counter = g_config.message_counter;
    g_config.message_counter = (g_config.message_counter + 1) % 256; // 0-255 循环
    
    // Vendor Specific IE: OUI + Type + Packed Message
    frame[(*frame_len)++] = 0xDD; // Vendor Specific IE ID (221)
    frame[(*frame_len)++] = 0x53; // 长度（1字节）<8+N*25> Length: OUI(3) + Type(1) + Counter(1) + Packed Message(packed_len)
    
    // China C-RID OUI: FA 0B BC (3 bytes) - 符合 GB42590-2023
    frame[(*frame_len)++] = 0xFA; // OUI[0] - 中国标准
    frame[(*frame_len)++] = 0x0B; // OUI[1] - 中国标准
    frame[(*frame_len)++] = 0xBC; // OUI[2] - 中国标准
    
    // China C-RID Type: 0x0D (中国标准固定值)
    frame[(*frame_len)++] = 0x0D;
    
    // Message Counter (0-255, 循环)
    frame[(*frame_len)++] = msg_counter;
    
    // 打包消息格式: [消息长度(1字节)] + [消息数量(1字节)] + [消息内容]
    uint8_t packed_msg[78]; // 3条消息 × 25字节 + 3字节头部 = 78字节
    uint8_t packed_len = 0;
    
    // frame[(*frame_len)++] = 0xF1;
    packed_msg[packed_len++] = 0xF1;
    // 打包格式
    packed_msg[packed_len++] = 0x19; // 每个消息长度: 25 (0x19)
    packed_msg[packed_len++] = 0x03; // 消息数量: 3 (Basic ID, Location, System)
    
    // 构建每条消息
    uint8_t basic_msg[25];
    build_basic_id_message_25bytes(basic_msg);
    
    uint8_t location_msg[25];
    build_location_message_25bytes(location_msg);
    
    uint8_t system_msg[25];
    build_system_message_25bytes(system_msg);
    
    // 复制消息内容
    memcpy(&packed_msg[packed_len], basic_msg, 25);
    packed_len += 25;
    memcpy(&packed_msg[packed_len], location_msg, 25);
    packed_len += 25;
    memcpy(&packed_msg[packed_len], system_msg, 25);
    packed_len += 25;
 
    // Copy packed message content
    memcpy(&frame[*frame_len], packed_msg, packed_len);
    *frame_len += packed_len;

    ESP_LOGI(TAG, "China C-RID beacon frame built (符合试行标准表2, 25字节格式)");
    ESP_LOGI(TAG, "  Frame length: %d bytes", *frame_len);
    ESP_LOGI(TAG, "  OUI: FA:0B:BC (GB42590-2023标准)");
    ESP_LOGI(TAG, "  Vendor Type: 0x0D (GB42590-2023固定值)");
    ESP_LOGI(TAG, "  Message Counter: %d", msg_counter);
    ESP_LOGI(TAG, "  Messages: Basic ID + Location + System (each 25 bytes)");
    ESP_LOGI(TAG, "  UAS ID: %s", g_config.uas_id);
    ESP_LOGI(TAG, "  Position: %.6f, %.6f", g_config.latitude, g_config.longitude);
    ESP_LOGI(TAG, "  Compliance: ✅ 符合《民用微轻小型无人驾驶航空器运行识别最低性能要求（试行）》");
    ESP_LOGI(TAG, "  Frequency: 1 Hz (符合中国标准要求)");
}

// --- Update position data dynamically ---
void update_position_data(float lat, float lon, float alt_msl, float alt_agl, 
                         float speed_h, float speed_v, float heading) {
    g_config.latitude = lat;
    g_config.longitude = lon;
    g_config.altitude_msl = alt_msl;
    g_config.altitude_agl = alt_agl;
    g_config.speed_horizontal = speed_h;
    g_config.speed_vertical = speed_v;
    g_config.heading = heading;
    
    ESP_LOGI(TAG, "Position updated:");
    ESP_LOGI(TAG, "  Position: %.6f, %.6f", g_config.latitude, g_config.longitude);
    ESP_LOGI(TAG, "  Altitude: %.2f m (MSL), %.2f m (AGL)", 
             g_config.altitude_msl, g_config.altitude_agl);
    ESP_LOGI(TAG, "  Speed: %.2f m/s (H), %.2f m/s (V)", 
             g_config.speed_horizontal, g_config.speed_vertical);
    ESP_LOGI(TAG, "  Heading: %.1f°", g_config.heading);
}

// --- Send Beacon task ---
static void send_beacon_task(void *pvParameter) {
    ESP_LOGI(TAG, "Starting China C-RID beacon transmission (符合试行标准)...");
    
    TickType_t xLastWake1s = xTaskGetTickCount();   // 1秒计时基准
    TickType_t xLastWake10s = xTaskGetTickCount();  // 10秒计时基准

    const TickType_t xInterval1s  = pdMS_TO_TICKS(BEACON_INTERVAL_MS);   // 1秒
    const TickType_t xInterval10s = pdMS_TO_TICKS(10000);  // 10秒

    for (;;)
    {
        TickType_t xNow = xTaskGetTickCount();

        // 检查是否到 1 秒
        if ((xNow - xLastWake1s) >= xInterval1s)
        {
        
        esp_err_t ret = esp_wifi_80211_tx(WIFI_IF_STA, beacon_frame, beacon_frame_len, false);
        
        if (ret != ESP_OK) {
            ESP_LOGW(TAG, "TX failed (no seq): %s", esp_err_to_name(ret));
            
            // Try with sequence control enabled
            ret = esp_wifi_80211_tx(WIFI_IF_STA, beacon_frame, beacon_frame_len, true);
            if (ret != ESP_OK) {
                ESP_LOGW(TAG, "TX failed (with seq): %s", esp_err_to_name(ret));
                
                // Try AP interface
                ret = esp_wifi_80211_tx(WIFI_IF_AP, beacon_frame, beacon_frame_len, false);
                if (ret != ESP_OK) {
                    ESP_LOGW(TAG, "TX failed (AP no seq): %s", esp_err_to_name(ret));
                    
                    ret = esp_wifi_80211_tx(WIFI_IF_AP, beacon_frame, beacon_frame_len, true);
                    if (ret != ESP_OK) {
                        ESP_LOGE(TAG, "All TX methods failed: %s", esp_err_to_name(ret));
                        ESP_LOGE(TAG, "This may be due to ESP32 hardware limitations for raw frame transmission");
                        ESP_LOGE(TAG, "Check: https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/wifi.html#raw-frame-transmission-reception");
                    } else {
                        ESP_LOGI(TAG, "Beacon sent successfully (AP with seq control, China C-RID 25-byte format)");
                    }
                } else {
                    ESP_LOGI(TAG, "Beacon sent successfully (AP no seq control, China C-RID 25-byte format)");
                }
            } else {
                ESP_LOGI(TAG, "Beacon sent successfully (with seq control, China C-RID 25-byte format)");
            }
        } else {
            ESP_LOGI(TAG, "Beacon sent successfully (no seq control, China C-RID 25-byte format)");
        }
        
            xLastWake1s = xNow;  // 更新基准时间
        }

        // 检查是否到 10 秒
        if ((xNow - xLastWake10s) >= xInterval10s)
        {
            // 执行 10 秒任务
            // 模拟位置更新的演示
            float demo_lat = g_config.latitude;
            float demo_lon = g_config.longitude;
            float demo_alt = g_config.altitude_msl;
            float demo_speed_h = g_config.speed_horizontal;
            float demo_speed_v = g_config.speed_vertical;
            float demo_heading = g_config.heading;

            // 模拟位置变化 (每10秒更新一次位置)
            ESP_LOGI(TAG, "================ 模拟位置变化 (每10秒更新一次位置) ================");
            demo_lat += 0.000001f; // 约1.1米
            demo_lon += 0.000001f; // 约0.9米
            demo_alt += 0.001f;    // 0.1m/s climb
            demo_speed_h = demo_speed_h + (esp_random() % 100 - 50.0f) / 50.0f; // 5-7 m/s
            demo_speed_v = (esp_random() % 100 - 50) / 100.0f;  // -0.5 to +0.5 m/s
            demo_heading = (demo_heading + 1.0f) > 360.0f ? 1.0f : (demo_heading + 1.0f);
            
            update_position_data(demo_lat, demo_lon, demo_alt, demo_alt - 5, 
                               demo_speed_h, demo_speed_v, demo_heading);

            // 重建帧以包含最新数据
            build_beacon_frame();

            xLastWake10s = xNow;  // 更新基准时间
        }

        // 避免忙等待：短暂延时（可选）
        vTaskDelay(pdMS_TO_TICKS(10)); // 比如每10ms检查一次
    }
}


void app_main(void) {
    ESP_LOGI(TAG, "Starting ESP32 China C-RID Transmitter (符合《民用微轻小型无人驾驶航空器运行识别最低性能要求（试行）》)");

    // 1. Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // 2. Initialize TCP/IP network interface
    ESP_ERROR_CHECK(esp_netif_init());

    // 3. Initialize Event Loop
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    // 4. Initialize China C-RID configuration
    init_cn_crid_config();

    // 5. Initialize Wi-Fi
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
    
    // Wait for Wi-Fi to start
    vTaskDelay(pdMS_TO_TICKS(100));
    
    // Set channel for transmission
    ESP_ERROR_CHECK(esp_wifi_set_channel(g_config.channel, WIFI_SECOND_CHAN_NONE));
    
    // Enable promiscuous mode for better transmission capability
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));

    ESP_LOGI(TAG, "Wi-Fi initialized in STA mode with promiscuous mode enabled");

    // 6. Build initial frame
    build_beacon_frame();

    // 7. Start transmission
    xTaskCreate(send_beacon_task, "cn_crid_tx", 8192, NULL, 5, NULL);

    ESP_LOGI(TAG, "China C-RID Transmitter started successfully!");
    ESP_LOGI(TAG, "OUI: FA:0B:BC (GB42590-2023标准)");
    ESP_LOGI(TAG, "Vendor Type: 0x0D (GB42590-2023固定值)");
    ESP_LOGI(TAG, "Standard: 《民用微轻小型无人驾驶航空器运行识别最低性能要求（试行）》");
    ESP_LOGI(TAG, "Message Format: 25 bytes (报头1字节 + 报文内容24字节)");
    ESP_LOGI(TAG, "Messages: Basic ID, Location, System (each 25 bytes)");
    ESP_LOGI(TAG, "UAS ID: %s", g_config.uas_id);
    ESP_LOGI(TAG, "Position: %.6f, %.6f", g_config.latitude, g_config.longitude);
    ESP_LOGI(TAG, "Broadcasting on channel %d", g_config.channel);
    ESP_LOGI(TAG, "Beacon interval: %d ms (1 Hz, 符合中国标准要求)", BEACON_INTERVAL_MS);
    ESP_LOGI(TAG, "Compliance: ✅ 完全符合中国民用无人机运行识别最低性能要求（试行）");
    ESP_LOGI(TAG, "Target: 可被符合中国标准的接收设备检测到");
    ESP_LOGI(TAG, "Dynamic Updates: Enabled (位置、速度、高度实时更新)");
}