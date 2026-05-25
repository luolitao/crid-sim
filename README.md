# C-RID Simulator (中国民用无人机远程识别模拟器)

基于 ESP32 的中国民航局 C-RID (Civil Remote ID) 标准模拟器，符合《民用微轻小型无人驾驶航空器运行识别最低性能要求（试行）》和 GB42590-2023 标准。

## 项目简介

本项目实现了符合中国民航局标准的无人机远程识别 (Remote ID) 信标广播功能，通过 ESP32 发送 WiFi Beacon 帧，包含无人机的身份信息、位置信息和系统信息。

## 主要特性

- ✅ **符合中国标准**: 遵循 GB42590-2023 和中国民航局试运行识别标准
- ✅ **三种消息类型**:
  - Basic ID (基本身份报文) - 25 字节
  - Location (位置向量报文) - 25 字节  
  - System (系统报文) - 25 字节
- ✅ **打包传输**: 使用 Vendor Specific IE (OUI: FA:0B:BC) 打包多条消息
- ✅ **自动巡游模拟**: 模拟无人机在指定区域进行 8 字形巡航飞行
- ✅ **1Hz 广播频率**: 符合中国标准要求的每秒一次广播

## 硬件要求

- ESP32 开发板 (推荐 ESP32-S3)
- USB 数据线
- 已安装 ESP-IDF 开发环境的电脑

## 软件要求

- ESP-IDF v5.0 或更高版本
- CMake 3.16+
- Python 3.7+

## 编译与烧录

### 1. 配置项目

```bash
cd /workspace
idf.py set-target esp32s3  # 根据你的硬件设置目标芯片
```

### 2. 编译项目

```bash
idf.py build
```

### 3. 烧录到设备

```bash
idf.py -p PORT flash monitor
```

将 `PORT` 替换为你的 ESP32 串口设备路径：
- Linux: `/dev/ttyUSB0` 或 `/dev/ttyACM0`
- macOS: `/dev/cu.usbserial-*`
- Windows: `COM3` 等

## 技术规格

### 消息格式

每条消息遵循 25 字节固定长度格式：

| 字段 | 长度 (字节) | 说明 |
|------|-----------|------|
| 报头 | 1 | 消息类型 (高 4 位) + 接口版本 (低 4 位) |
| 数据 | 23 | 具体消息内容 |
| 预留 | 1 | 预留字节 |

### OUI 标识

- **OUI**: `FA:0B:BC` (中国 C-RID 标准)
- **Vendor Type**: `0x0D` (GB42590-2023 固定值)
- **消息计数器**: 0-255 循环

### 默认配置

- **UAS ID**: `CAAC-ESP32-CN-001`
- **ID 类型**: 2 (CAA Registration ID)
- **无人机类型**: 2 (直升机/多旋翼)
- **工作信道**: 6
- **SSID**: `CN-CRID-ESP`
- **初始位置**: 23.14287°N, 113.26026°E (广州越秀山附近)

## 巡游模式

项目内置了 8 字形巡航模拟功能：

```c
latitude = base_latitude + patrol_radius_lat * sin(patrol_speed * time_counter)
longitude = base_longitude + patrol_radius_lon * sin(2 * patrol_speed * time_counter)
```

- 巡游半径：约 5.5 米 (纬度方向) × 4.4 米 (经度方向)
- 巡游速度参数：0.2 rad/s

## 合规性声明

本项目实现符合以下标准要求：

1. 《民用微轻小型无人驾驶航空器运行识别最低性能要求（试行）》
2. GB42590-2023《民用无人驾驶航空器系统安全要求》
3. ASTM F3411-22a (参考)

## 目录结构

```
crid-sim/
├── CMakeLists.txt              # 项目构建配置
├── README.md                   # 项目说明文档
├── sdkconfig.defaults          # SDK 默认配置
├── esp_idf_project_configuration.json
├── main/
│   ├── CMakeLists.txt          # 主组件构建配置
│   └── crid-sim.c              # 主要源代码
└── .vscode/                    # VS Code 配置
```

## 注意事项

⚠️ **法律提醒**: 
- 本代码仅用于学习和研究目的
- 在实际环境中使用 Remote ID 功能需遵守当地法律法规
- 未经授权的无线电发射可能违反相关法律法规

## 参考资料

- [中国民航局 UAV OS](https://www.caac.gov.cn/)
- [GB42590-2023 标准文档]
- [ESP-IDF 编程指南](https://docs.espressif.com/projects/esp-idf/)

## 许可证

本项目采用 MIT 许可证。详见 LICENSE 文件。

## 联系方式

如有问题或建议，请提交 Issue 或 Pull Request。
