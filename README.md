# ESP32 中国民用无人机远程识别（C-RID）模拟发射器

基于 ESP32 的中国民用无人机运行识别（China Remote ID）Wi-Fi Beacon 模拟发射器，符合 **GB42590-2023**、**IB-TM-2024-01** 和《民用微轻小型无人驾驶航空器运行识别最低性能要求（试行）》。

## 功能概述

- 通过 ESP32 发送符合中国标准的 Wi-Fi Beacon 帧，模拟无人机广播身份和位置信息
- 打包 **5 条**标准报文（Basic ID / Location / Self-ID / System / Operator ID），每条 25 字节，不含认证报文
- 使用中国标准 OUI `FA:0B:BC` 和 Vendor Type `0x0D`（GB42590-2023）
- 以 **1 Hz** 频率广播
- 模拟无人机在越秀山附近作圆形巡游运动，动态更新位置、高度、速度和航向
- `message_counter` 每条 Beacon 递增，0-255 循环回绕

## 报文格式

| 报文类型 | 报文编号 | 内容 |
|---------|---------|------|
| Basic ID | `0x0` | UAS ID（无人机唯一标识）、ID 类型、无人机类型 |
| Location | `0x1` | 经纬度、高度、速度、航向、时间戳 |
| Self-ID | `0x3` | 无人机型号（如 ESP32S3） |
| System | `0x4` | 操作员位置、运行区域、分类等级 |
| Operator ID | `0x5` | 操作员 ID（飞手标识） |

> 注：GB42590 和 IB-TM-2024-01 标准不要求认证报文（Auth）。

## 标识字段说明

| 字段 | 格式 | 示例 | 所在报文 |
|------|------|------|---------|
| UAS ID（唯一标识） | `ESP32-CRID-XXXX` | `ESP32-CRID-3456` | Basic ID |
| 无人机型号 | `ESP32S3` | `ESP32S3` | Self-ID |
| 操作员 ID | `ESP32-CRID-OP-XXXX` | `ESP32-CRID-OP-3456` | Operator ID |
| SSID | `ESP32-CRID-XXXX` | `ESP32-CRID-3456` | Wi-Fi Beacon |

> `XXXX` 为设备 MAC 地址最后 4 位（后 2 字节），自动从硬件获取。

## 硬件要求

- **ESP32** 或 **ESP32-S3** 开发板
- USB 数据线

## 环境配置

1. 安装 ESP-IDF（推荐 v5.x 或 v6.x）：
   ```bash
   # 参考官方安装指南
   https://docs.espressif.com/projects/esp-idf/zh_CN/latest/esp32/get-started/
   ```

2. 激活 ESP-IDF 环境：
   ```bash
   . $IDF_PATH/export.sh
   ```

3. 克隆项目：
   ```bash
   git clone <repo-url>
   cd crid-sim
   ```

## 编译与烧录

### 方式一：使用 idf.py 命令

```bash
# 设置目标芯片（ESP32 或 ESP32-S3）
idf.py set-target esp32

# 编译
idf.py build

# 烧录并监控
idf.py -p /dev/ttyUSB0 flash monitor
```

### 方式二：使用脚本

项目提供了 `flash_and_monitor.sh` 脚本，支持通过环境变量配置：

```bash
# 可通过环境变量覆盖默认值：
export IDF_PATH=/path/to/esp-idf
export ESP_PORT=/dev/tty.usbmodemXXXX
export ESP_CHIP=esp32s3   # 或 esp32

chmod +x flash_and_monitor.sh
./flash_and_monitor.sh
```

## 配置说明

可在 `main/crid_config.c` 的 `crid_config_init_default()` 函数中修改以下参数：

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `uas_id` | 无人机唯一标识 | `ESP32-CRID-XXXX`（MAC 后 4 位） |
| `drone_name` | 无人机型号（Self-ID） | `ESP32S3` |
| `operator_id` | 操作员 ID | `ESP32-CRID-OP-XXXX` |
| `id_type` | ID 类型（1 = 序列号） | `1` |
| `ua_type` | 无人机类型（2 = 多旋翼） | `2` |
| `latitude` / `longitude` | 初始位置 | 越秀山（23.14287, 113.26026） |
| `altitude_msl` | 海拔高度（米） | `50.0` |
| `channel` | Wi-Fi 信道 | `6` |
| `patrol_radius_lat/lon` | 巡游半径 | ~5 米 |
| `patrol_speed` | 巡游速度参数 | `0.2` |

## 运行效果

烧录后通过串口监控可看到如下日志输出：

```
I (xxxx) CN_C-RID_CFG: China C-RID configuration initialized
I (xxxx) CN_C-RID_CFG:   MAC: 24:0A:C4:12:34:56
I (xxxx) CN_C-RID_CFG:   UAS ID: ESP32-CRID-3456
I (xxxx) CN_C-RID_CFG:   Drone Model (Self-ID): ESP32S3
I (xxxx) CN_C-RID_CFG:   Operator ID: ESP32-CRID-OP-3456
I (xxxx) CN_C-RID_CFG:   ID Type: 1 (Serial Number)
I (xxxx) CN_C-RID_CFG:   UA Type: 2 (Helicopter/Multirotor)
I (xxxx) CN_C-RID_CFG:   Position: 23.142870, 113.260260
I (xxxx) ESP32_CRID_STD: Transmitter started successfully!
I (xxxx) ESP32_CRID_STD:   Channel: 6, Interval: 1000ms
I (xxxx) ESP32_CRID_STD:   OUI: FA:0B:BC, Vendor Type: 0x0D (GB42590-2023)
```

## 验证方式

可使用以下工具验证 Beacon 帧：

- **Wireshark**：抓取 Wi-Fi 包，过滤 OUI `FA:0B:BC`
- **符合中国标准的接收设备**：可检测到广播的 C-RID 信息
- **手机 Wi-Fi 扫描**：可看到 SSID `ESP32-CRID-XXXX` 的 Beacon

## 项目结构

```
crid-sim/
├── CMakeLists.txt              # 顶层 CMake 配置
├── sdkconfig.defaults          # SDK 默认配置
├── flash_and_monitor.sh        # 烧录脚本（支持环境变量配置）
├── README.md
└── main/
    ├── CMakeLists.txt          # 组件 CMake 配置
    ├── crid-sim.c              # 主入口
    ├── crid_config.h/c         # 配置定义与初始化
    ├── crid_messages.h/c       # 报文构建（Basic ID / Location / Self-ID / System / Operator ID）
    ├── crid_wifi.h/c           # Wi-Fi 初始化和帧发送
    └── crid_patrol.h/c         # 巡游位置模拟
```

## 参考标准

- GB42590-2023《民用无人驾驶航空器系统安全要求》
- IB-TM-2024-01
- 《民用微轻小型无人驾驶航空器运行识别最低性能要求（试行）》

## License

MIT
