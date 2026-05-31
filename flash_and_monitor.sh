#!/bin/bash
# ESP32 / ESP32-S3 烧录和监控脚本
#
# 使用前请设置以下环境变量（或直接修改脚本中的默认值）：
#   export IDF_PATH=/path/to/esp-idf
#   export ESP_PORT=/dev/tty.usbmodemXXXX
#   export ESP_CHIP=esp32s3    # 可选：esp32 / esp32s3
#
# 用法: ./flash_and_monitor.sh

set -e

# --- 配置（可通过环境变量覆盖） ---
IDF_PATH="${IDF_PATH:-$HOME/.espressif/v6.0.1/esp-idf}"
PORT="${ESP_PORT:-/dev/tty.usbmodem1101}"
CHIP="${ESP_CHIP:-esp32s3}"
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "========================================="
echo "ESP32 C-RID 烧录和监控工具"
echo "========================================="
echo "  芯片:      $CHIP"
echo "  端口:      $PORT"
echo "  项目目录:  $PROJECT_DIR"
echo ""

# 加载 ESP-IDF 环境
echo "1. 加载 ESP-IDF 环境..."
if [ ! -f "$IDF_PATH/export.sh" ]; then
    echo "❌ 未找到 IDF_PATH: $IDF_PATH"
    echo "   请设置 IDF_PATH 环境变量或修改脚本"
    exit 1
fi
source "$IDF_PATH/export.sh" > /dev/null 2>&1

# 编译项目
echo "2. 编译项目..."
cd "$PROJECT_DIR"
idf.py set-target "$CHIP" 2>/dev/null || true
idf.py build

if [ $? -ne 0 ]; then
    echo "❌ 编译失败！"
    exit 1
fi

echo "✅ 编译成功"
echo ""
echo "3. 准备烧录..."
echo "⚠️  如果使用 ESP32-S3 且无法自动进入下载模式，请："
echo "   a) 断开 USB 线"
echo "   b) 按住 BOOT 按钮不放"
echo "   c) 插入 USB 线"
echo "   d) 等待 2 秒后释放 BOOT 按钮"
echo "   e) 按下 RESET 按钮一次"
echo ""
read -rp "完成后按回车继续烧录..."

# 烧录
echo "4. 开始烧录..."
idf.py -p "$PORT" -b 115200 flash

if [ $? -ne 0 ]; then
    echo "❌ 烧录失败！"
    echo "💡 提示：请尝试更换 USB 线或 USB 端口"
    exit 1
fi

echo "✅ 烧录成功"
echo ""

# 启动监控
echo "5. 启动串口监控（按 Ctrl+] 退出）..."
sleep 2
idf.py -p "$PORT" monitor
