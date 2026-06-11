

# ESP32 中国民用无人机远程识别（C-RID）模拟发射器

基于 ESP32/ESP32-S3 芯片开发的中国民用无人机运行识别（China Remote ID）Wi-Fi Beacon 模拟发射器。本项目专为无线电仿真、低空探测雷达开发及合规性测试设计，完美符合中国现行最新行业标准。

---

## 🚀 功能概述

* **严格符合最新国家标准**：
* **GB42590-2023**《民用无人驾驶航空器系统安全要求》
* **IB-TM-2024-01** 以及《民用微轻小型无人驾驶航空器运行识别最低性能要求（试行）》


* **全报文覆盖（无认证）**：完美打包中国标准要求的 **5 条** 核心标准报文，每条固定 25 字节（注：国内标准暂不要求认证报文 Auth）。
* **自动化硬件标识绑定**：系统自动读取 ESP32 芯片的物理 MAC 地址，并提取最后 4 位（2 字节）十六进制数作为无线 SSID、UAS ID 和操作员 ID 的唯一后缀（如 `ESP32-CRID-3456`），防止同空域多设备冲突。
* **内置动态轨迹仿真（Patrol Mode）**：内置巡游算法，模拟无人机在特定中心点（默认广州越秀山）附近做圆形巡游运动，实时动态更新经纬度、高度、速度和航向，提供逼真的动态仿真信号流。
* **防丢包递增校验**：消息计数器（Message Counter）随每条 Beacon 发送自动递增，并在 `0 ~ 255` 之间循环回绕。

---

## 📊 协议核心参数与报文格式

### 1. 射频与底层参数

| 参数 | 默认设定值 | 标准说明 |
| --- | --- | --- |
| **OUI（组织唯一标识符）** | `FA:0B:BC` | 中国 C-RID 专属厂商识别码 |
| **Vendor Type** | `0x0D` | 符合 GB42590-2023 规范定义 |
| **Wi-Fi 信道** | Channel 6（2.437 GHz） | 默认公共广播信道 |
| **广播频率** | 1 Hz | 每秒向外广播 1 次 |

### 2. 报文数据映射表

| 报文类型 | 报文编号 | 核心内容 |
| --- | --- | --- |
| **Basic ID** | `0x0` | UAS ID（无人机唯一标识）、ID 类型、无人机分类类型 |
| **Location** | `0x1` | 动态经纬度、气压/地理高度、水平/垂直速度、航向、时间戳 |
| **Self-ID** | `0x3` | 无人机型号文本描述（默认：`ESP32S3`） |
| **System** | `0x4` | 操作员（飞手）实时位置、运行区域、分类等级 |
| **Operator ID** | `0x5` | 操作员登记 ID（飞手个人标识） |

---

## 📂 项目结构

```text
crid-sim/
├── CMakeLists.txt              # 顶层 CMake 构建配置
├── sdkconfig.defaults          # SDK 默认宏定义与性能配置预设
├── flash_and_monitor.sh        # 一键烧录与串口监控 Shell 脚本
├── README.md                   # 项目说明文档
└── main/                       # 核心业务组件
    ├── CMakeLists.txt          # 组件 CMake 构建脚本
    ├── crid-sim.c              # 程序主入口，负责初始化和任务调度
    ├── crid_config.h/c         # 配置定义与参数初始化（坐标、ID等）
    ├── crid_messages.h/c       # 5 种 C-RID 25字节核心报文的序列化封装
    ├── crid_wifi.h/c           # Wi-Fi 驱动初始化与底层 Beacon 原始帧注入
    └── crid_patrol.h/c         # 圆形轨迹巡游仿真算法

```

---

## 📖 使用手册（Quick Start）

### 1. 硬件准备

* **核心板**：一块 ESP32 或 ESP32-S3 开发板。
* **线材**：一根良好的 USB 数据通信线（连接电脑与开发板）。

### 2. 环境配置

1. 安装乐鑫官方开发框架 **ESP-IDF**（推荐使用稳定版 `v5.x` 或 `v6.x`），可参考 [ESP-IDF 官方快速入门指南](https://docs.espressif.com/projects/esp-idf/zh_CN/latest/esp32/get-started/)。
2. 打开终端，激活 ESP-IDF 编译环境：
```bash
. $IDF_PATH/export.sh

```


3. 克隆本项目到本地并进入目录：
```bash
git clone <your-repo-url>
cd crid-sim

```



### 3. 自定义仿真参数（可选）

如果您需要更改无人机的初始起飞位置、型号名称、信道或飞行范围，可直接用文本编辑器修改 `main/crid_config.c` 文件中的 `crid_config_init_default()` 函数：

```c
// 示例：可供修改的核心参数
uas_id              // 无人机唯一标识（默认自适应 MAC 后4位）
drone_name          // 无人机型号（Self-ID，默认 "ESP32S3"）
latitude/longitude  // 初始起飞点位置（默认广州越秀山：23.14287, 113.26026）
channel             // 广播信道（默认 6）
patrol_radius_lat   // 巡游半径控制

```

### 4. 编译、烧录与监控

#### 选项 A：使用标准终端命令（推荐）

```bash
# 1. 设置目标芯片（根据您的硬件选择 esp32 或 esp32s3）
idf.py set-target esp32s3

# 2. 编译并烧录固件（请将 /dev/ttyUSB0 替换为您的实际串口，Windows 下类似 COM3）
idf.py -p /dev/ttyUSB0 flash monitor

```

#### 选项 B：使用预设 Shell 脚本

如果您在 Linux/macOS 环境下，可以通过配置环境变量快速调用项目提供的自动化脚本：

```bash
export ESP_PORT=/dev/tty.usbmodemXXXX  # 替换为您的串口设备
export ESP_CHIP=esp32s3                # 替换为您的芯片型号 (esp32/esp32s3)

chmod +x flash_and_monitor.sh
./flash_and_monitor.sh

```

---

## 🔍 运行效果与验证方式

### 1. 串口日志流

成功烧录并启动后，连接电脑的串口终端会打印如下输出，代表模拟发射器已成功工作：

```text
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

### 2. 无线电信号验证方法

* **手机/电脑 Wi-Fi 扫描**：打开任意设备的无线网络扫描列表，您会在周围发现一个名为 `ESP32-CRID-XXXX`（XXXX 为硬件特征码）的特殊热点信号。
* **Wireshark 抓包工具**：使用支持监听模式（Monitor Mode）的网卡捕获空中无线包，设置过滤条件过滤厂商专属 OUI 标识：`wlan.tag.oui == fa:0b:bc`，即可详细查看解码后的 5 类国标定制字段。
* **专用国标接收机**：将设备放置在符合中国标准的低空安全 Remote ID 接收设备旁，接收终端能够直接在雷达地图上捕获到这架正在“绕越秀山飞行”的虚拟无人机。

---

## 📄 开源许可证

本项目基于 **[MIT License](https://www.google.com/search?q=LICENSE)** 协议开源。