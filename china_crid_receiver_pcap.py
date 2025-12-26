#!/usr/bin/env python3
"""
中国 C-RID 信号探测器 (修正版 + pcap 记录功能)
支持解析中国标准的 C-RID 信号格式并记录 pcap 文件
"""

import sys
import struct
import time
from datetime import datetime
from collections import defaultdict
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Elt
import threading
import queue

class ChinaCRIDReceiverWithPCAP:
    def __init__(self):
        # C-RID 常量 (GB42590-2023)
        self.CRID_OUI = b'\xFA\x0B\xBC'
        self.CRID_VENDOR_TYPE = 0x0D
        
        # 消息类型映射
        self.msg_type_names = {
            0: "Basic ID",
            1: "Location/Vector", 
            2: "Authentication",
            3: "Self ID",
            4: "System",
            5: "Operator ID",
            0xF: "Packed Message"
        }
        
        # ID 类型映射 (符合试行标准)
        self.id_type_names = {
            0: "None", 
            1: "Serial Number", 
            2: "CAA Registration ID",  # 中国标准要求
            3: "UTM Assigned UUID", 
            4: "Specific Session ID"
        }
        
        # UA 类型映射 (符合试行标准)
        self.ua_type_names = {
            0: "None/Not declared", 
            1: "Aeroplane/Fixed wing", 
            2: "Helicopter/Multirotor",
            3: "Gyroplane", 
            4: "Hybrid Lift", 
            5: "Ornithopter", 
            6: "Glider", 
            7: "Kite",
            8: "Free Balloon", 
            9: "Captive Balloon", 
            10: "Airship", 
            11: "Free Fall/Parachute",
            12: "Rocket", 
            13: "Tethered Powered Aircraft", 
            14: "Ground Obstacle", 
            15: "Other"
        }
        
        # 状态类型映射
        self.status_names = {
            0: "Undeclared", 
            1: "Ground", 
            2: "Airborne", 
            3: "Emergency", 
            4: "Remote ID System Failure"
        }
        
        # 分类类型映射
        self.classification_names = {
            0: "Undeclared", 
            1: "EU", 
            2: "Other"
        }
        
        # EU 类别映射
        self.eu_category_names = {
            0: "Undeclared", 1: "Class 0", 2: "Class 1", 3: "Class 2", 
            4: "Class 3", 5: "Class 4", 6: "Class 5", 7: "Class 6"
        }
        
        # EU 级别映射
        self.eu_class_names = {
            0: "Undeclared", 1: "Class I", 2: "Class II", 3: "Class III", 
            4: "Class IV", 5: "Class V", 6: "Class VI", 7: "Class VII"
        }
        
        # 高度参考类型映射
        self.height_ref_names = {
            0: "Over Takeoff", 
            1: "Over Ground"
        }
        
        # 精度映射
        self.horiz_accuracy_names = [
            "Unknown", "<= 1m", "<= 2m", "<= 3m", "<= 4m", "<= 6m", 
            "<= 10m", "<= 15m", "<= 20m", "<= 25m", "<= 30m", "<= 35m", 
            "<= 40m", "<= 45m", "<= 50m", "N/A"
        ]
        
        self.vert_accuracy_names = [
            "Unknown", "<= 1m", "<= 2m", "<= 3m", "<= 4m", "<= 5m", 
            "<= 6m", "<= 7m", "<= 8m", "<= 9m", "<= 10m", "<= 15m", 
            "<= 20m", "<= 25m", "<= 30m", "N/A"
        ]
        
        self.speed_accuracy_names = [
            "Unknown", "<= 0.1m/s", "<= 0.2m/s", "<= 0.3m/s", "<= 0.4m/s", "<= 0.5m/s", 
            "<= 0.6m/s", "<= 0.7m/s", "<= 0.8m/s", "<= 0.9m/s", "<= 1.0m/s", 
            "<= 1.5m/s", "<= 2.0m/s", "<= 2.5m/s", "<= 3.0m/s", "N/A"
        ]
        
        # 统计信息
        self.stats = defaultdict(int)
        self.last_update = time.time()
        self.known_drones = {}  # 存储已知无人机信息
        self.last_detailed_report = time.time()
        
        # pcap 记录相关
        self.pcap_writer = None
        self.record_packets = True
        self.max_pcap_size = 50 * 1024 * 1024  # 50MB
        self.current_pcap_size = 0
        self.pcap_file_counter = 0
        self.pcap_queue = queue.Queue(maxsize=1000)  # 队列用于异步记录
        self.pcap_thread = None
        self.pcap_running = False
        
        # 初始化 pcap 记录
        self.init_pcap_recording()

    def init_pcap_recording(self):
        """初始化 pcap 记录"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        pcap_filename = f"crid_capture_{timestamp}.pcap"
        
        try:
            self.pcap_writer = PcapWriter(pcap_filename, append=False)
            self.current_pcap_size = 0
            self.pcap_file_counter = 0
            
            # 启动异步 pcap 记录线程
            self.pcap_running = True
            self.pcap_thread = threading.Thread(target=self.pcap_record_worker, daemon=True)
            self.pcap_thread.start()
            
            print(f"📝 [PCAP] 开始记录到文件: {pcap_filename}")
            print(f"📝 [PCAP] 文件大小限制: {self.max_pcap_size / (1024*1024):.0f}MB")
        except Exception as e:
            print(f"❌ [PCAP] 初始化失败: {e}")
            self.record_packets = False

    def pcap_record_worker(self):
        """异步 pcap 记录工作线程"""
        while self.pcap_running:
            try:
                packet = self.pcap_queue.get(timeout=1)
                if packet is None:  # 停止信号
                    break
                    
                if self.pcap_writer:
                    try:
                        self.pcap_writer.write(packet)
                        self.current_pcap_size += len(bytes(packet))
                        
                        # 检查是否需要轮换文件
                        if self.current_pcap_size >= self.max_pcap_size:
                            self.rotate_pcap_file()
                    except Exception as e:
                        print(f"❌ [PCAP] 写入错误: {e}")
                
                self.pcap_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                print(f"❌ [PCAP] 工作线程错误: {e}")

    def rotate_pcap_file(self):
        """轮换 pcap 文件"""
        if self.pcap_writer:
            self.pcap_writer.close()
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.pcap_file_counter += 1
        new_filename = f"crid_capture_{timestamp}_{self.pcap_file_counter:03d}.pcap"
        
        try:
            self.pcap_writer = PcapWriter(new_filename, append=False)
            self.current_pcap_size = 0
            print(f"📝 [PCAP] 轮换到新文件: {new_filename}")
        except Exception as e:
            print(f"❌ [PCAP] 轮换文件失败: {e}")
            self.record_packets = False

    def write_pcap_packet(self, packet):
        """写入 pcap 包 (异步)"""
        if self.record_packets and self.pcap_writer:
            try:
                self.pcap_queue.put_nowait(packet)
            except queue.Full:
                print("⚠️  [PCAP] 队列已满，丢弃包")

    def parse_basic_id_submessage(self, data_bytes):
        """解析 GB42590 Basic ID 子消息 (符合试行标准表3)"""
        if len(data_bytes) < 25:
            return None
            
        # 确保输入是字节类型
        if isinstance(data_bytes, list):
            data = bytes(data_bytes)
        else:
            data = data_bytes
            
        # 第1字节: [消息类型(高4位)] + [接口版本(低4位)] = 0x01 (Basic ID + Version 1)
        msg_type = (data[0] >> 4) & 0x0F
        interface_version = data[0] & 0x0F
        
        # 检查是否是 Basic ID 消息
        if msg_type != 0:
            return None
            
        # 第2字节: [ID类型(高4位)] + [UA类型(低4位)] - 符合试行标准表3
        id_ua_byte = data[1]
        id_type = (id_ua_byte >> 4) & 0x0F  # 高4位
        ua_type = id_ua_byte & 0x0F         # 低4位
        
        # 第3-22字节: UAS ID (20字节, ASCII字符, 不足填充空格)
        uas_id_bytes = data[2:22]  # 修正：从字节2开始，长度20
        try:
            uas_id = uas_id_bytes.rstrip(b'\x00 \x20').decode('ascii', errors='ignore')
        except AttributeError:
            # 如果 rstrip 失败，手动处理
            uas_id = uas_id_bytes.decode('ascii', errors='ignore').rstrip('\x00 \x20')
        
        # 第23-25字节: 预留
        reserved = data[22:25]
        
        return {
            'message_type': 'Basic ID',
            'interface_version': interface_version,
            'id_type': self.id_type_names.get(id_type, f"Unknown ({id_type})"),
            'ua_type': self.ua_type_names.get(ua_type, f"Unknown ({ua_type})"),
            'uas_id': uas_id,
            'id_type_raw': id_type,
            'ua_type_raw': ua_type,
            'china_compliant': id_type == 2,  # CAA Registration ID (中国标准要求)
            'reserved_bytes': reserved
        }

    def parse_location_submessage(self, data_bytes):
        """解析 GB42590 Location 消息 (符合试行标准表4)"""
        if len(data_bytes) < 39:
            return None
            
        # 确保输入是字节类型
        if isinstance(data_bytes, list):
            data = bytes(data_bytes)
        else:
            data = data_bytes
            
        # 第1字节: [消息类型(高4位)] + [接口版本(低4位)] = 0x11 (Location + Version 1)
        msg_type = (data[0] >> 4) & 0x0F
        interface_version = data[0] & 0x0F
        
        # 检查是否是 Location 消息
        if msg_type != 1:
            return None
            
        # 第2字节: [状态(高4位)] + [方向高4位(低4位)]
        flags_byte = data[1]
        status = (flags_byte >> 4) & 0x0F
        direction_high = flags_byte & 0x0F
        
        # 第3-4字节: 方向 (0.1度单位, little endian)
        direction_raw = struct.unpack('<H', data[2:4])[0]
        direction = direction_raw / 10.0
        
        # 第5字节: 水平速度 (0.1m/s单位)
        speed_h = data[4] / 10.0
        
        # 第6字节: 垂直速度 (0.1m/s单位, signed, little endian)
        speed_v = struct.unpack('<b', data[5:6])[0] / 10.0
        
        # 第7-14字节: 纬度 (1E-7度单位, little endian)
        lat = struct.unpack('<d', data[6:14])[0]
        
        # 第15-22字节: 经度 (1E-7度单位, little endian)
        lon = struct.unpack('<d', data[14:22])[0]
        
        # 第23-26字节: 气压高度 (cm, little endian)
        alt_baro_scaled = struct.unpack('<f', data[22:26])[0]
        altitude_baro = alt_baro_scaled / 100.0  # 转换为米
        
        # 第27-30字节: 地理高度 (cm, little endian)
        alt_geo_scaled = struct.unpack('<f', data[26:30])[0]
        altitude_geo = alt_geo_scaled / 100.0  # 转换为米
        
        # 第31-34字节: 相对地面高度 (cm, little endian)
        height_scaled = struct.unpack('<f', data[30:34])[0]
        height = height_scaled / 100.0  # 转换为米
        
        # 第35字节: 高度参考类型
        height_type = data[34]
        
        # 第36-39字节: 精度信息
        horiz_accuracy = data[35]
        vert_accuracy = data[36]
        baro_accuracy = data[37]
        speed_accuracy = data[38]
        
        return {
            'message_type': 'Location/Vector',
            'interface_version': interface_version,
            'status': self.status_names.get(status, f"Unknown ({status})"),
            'status_raw': status,
            'direction': direction,
            'speed_horizontal': speed_h,
            'speed_vertical': speed_v,
            'latitude': lat,
            'longitude': lon,
            'altitude_baro': altitude_baro,
            'altitude_geo': altitude_geo,
            'height': height,
            'height_type': self.height_ref_names.get(height_type, f"Unknown ({height_type})"),
            'horiz_accuracy': self.horiz_accuracy_names[horiz_accuracy] if horiz_accuracy <= 15 else "Invalid",
            'vert_accuracy': self.vert_accuracy_names[vert_accuracy] if vert_accuracy <= 15 else "Invalid",
            'speed_accuracy': self.speed_accuracy_names[speed_accuracy] if speed_accuracy <= 15 else "Invalid",
            'accurate_enough': (horiz_accuracy <= 4 and vert_accuracy <= 4),  # 中国精度要求
            'flags': flags_byte
        }

    def parse_system_submessage(self, data_bytes):
        """解析 GB42590 System 消息 (符合试行标准表6)"""
        if len(data_bytes) < 39:
            return None
            
        # 确保输入是字节类型
        if isinstance(data_bytes, list):
            data = bytes(data_bytes)
        else:
            data = data_bytes
            
        # 第1字节: [消息类型(高4位)] + [接口版本(低4位)] = 0x41 (System + Version 1)
        msg_type = (data[0] >> 4) & 0x0F
        interface_version = data[0] & 0x0F
        
        # 检查是否是 System 消息
        if msg_type != 4:
            return None
            
        # 第2字节: [坐标系类型(高1位)] + [等级分类归属区域(中3位)] + [控制站位置类型(低2位)] - 符合试行标准表6
        sys_flags = data[1]
        coordinate_system = (sys_flags >> 7) & 0x01
        classification_region = (sys_flags >> 4) & 0x07
        operator_location_type = sys_flags & 0x03
        
        # 第3-10字节: 控制站纬度 (1E-7度单位, little endian)
        operator_lat = struct.unpack('<d', data[2:10])[0]
        
        # 第11-18字节: 控制站经度 (1E-7度单位, little endian)
        operator_lon = struct.unpack('<d', data[10:18])[0]
        
        # 第19-20字节: 运行区域计数 (little endian)
        area_count = struct.unpack('<H', data[18:20])[0]
        
        # 第21字节: 运行区域半径
        area_radius = data[20] * 10  # 半径值 * 10
        
        # 第22-25字节: 运行区域高度上限 (little endian, cm)
        area_ceiling_scaled = struct.unpack('<f', data[22:26])[0]
        area_ceiling = area_ceiling_scaled / 100.0  # 转换为米
        
        # 第26-29字节: 运行区域高度下限 (little endian, cm)
        area_floor_scaled = struct.unpack('<f', data[26:30])[0]
        area_floor = area_floor_scaled / 100.0  # 转换为米
        
        # 第30字节: [EU类别(高4位)] + [EU级别(低4位)]
        category_class_byte = data[30]
        category_eu = (category_class_byte >> 4) & 0x0F
        class_eu = category_class_byte & 0x0F
        
        # 第31-34字节: 操作员地理高度 (little endian, cm)
        operator_alt_scaled = struct.unpack('<f', data[31:35])[0]
        operator_altitude = operator_alt_scaled / 100.0  # 转换为米
        
        # 第35-38字节: 时间戳 (little endian, seconds since epoch)
        timestamp = struct.unpack('<I', data[35:39])[0]
        
        return {
            'message_type': 'System',
            'interface_version': interface_version,
            'coordinate_system': coordinate_system,
            'classification_region': classification_region,
            'operator_location_type': operator_location_type,
            'operator_latitude': operator_lat,
            'operator_longitude': operator_lon,
            'area_count': area_count,
            'area_radius': area_radius,
            'area_ceiling': area_ceiling,
            'area_floor': area_floor,
            'category_eu': self.eu_category_names.get(category_eu, f"Unknown ({category_eu})"),
            'class_eu': self.eu_class_names.get(class_eu, f"Unknown ({class_eu})"),
            'operator_altitude': operator_altitude,
            'timestamp': timestamp,
            'china_compliant': classification_region == 2  # 中国区域代码 (2)
        }

    def parse_opendroneid_message(self, msg_data):
        """解析 OpenDroneID 消息"""
        if len(msg_data) == 0:
            return None
            
        if isinstance(msg_data, list):
            data = bytes(msg_data)
        else:
            data = msg_data
            
        if len(data) == 0:
            return None
            
        msg_type = (data[0] >> 4) & 0x0F  # 高4位是消息类型
        
        if msg_type == 0:  # Basic ID
            return self.parse_basic_id_submessage(data)
        elif msg_type == 1:  # Location
            return self.parse_location_submessage(data)
        elif msg_type == 4:  # System
            return self.parse_system_submessage(data)
        else:
            return {
                'message_type': f'Unknown Type {msg_type}',
                'raw_data': data.hex()
            }

    def find_crid_in_frame(self, raw_bytes):
        """在原始帧中查找中国 C-RID 消息"""
        # 查找 GB42590 OUI (FA 0B BC)
        for i in range(len(raw_bytes) - 10):
            if (raw_bytes[i:i+3] == self.CRID_OUI and 
                i + 4 < len(raw_bytes) and 
                raw_bytes[i+3] == self.CRID_VENDOR_TYPE):
                
                oui_pos = i
                msg_counter = raw_bytes[oui_pos + 4]  # 消息计数器
                
                # 从消息计数器后面开始解析
                offset = oui_pos + 5
                messages = []
                
                # 检查是否是打包消息格式 (符合试行标准 3.1.5)
                if offset + 2 < len(raw_bytes):
                    # 首先检查是否是打包格式
                    packed_msg_len = raw_bytes[offset]
                    msg_count = raw_bytes[offset + 1]
                    
                    if packed_msg_len == 0x19 and msg_count > 0:  # 25字节格式
                        offset += 2  # 跳过长度和计数字段
                        
                        # 解析打包的消息
                        for msg_idx in range(min(msg_count, 10)):  # 最多解析10条消息
                            if offset + 25 <= len(raw_bytes):
                                msg_data = raw_bytes[offset:offset + 25]
                                parsed_msg = self.parse_opendroneid_message(msg_data)
                                if parsed_msg:
                                    parsed_msg['counter'] = msg_counter
                                    messages.append(parsed_msg)
                                offset += 25
                            else:
                                break
                    else:
                        # 解析单个消息 (旧格式)
                        while offset < len(raw_bytes) - 2:
                            if offset >= len(raw_bytes):
                                break
                                
                            sub_msg_type = raw_bytes[offset] >> 4  # 高4位是消息类型
                            msg_length = 25  # 中国标准要求25字节格式
                            
                            if offset + msg_length <= len(raw_bytes):
                                msg_data = raw_bytes[offset:offset + msg_length]
                                parsed_msg = self.parse_opendroneid_message(msg_data)
                                if parsed_msg:
                                    parsed_msg['counter'] = msg_counter
                                    messages.append(parsed_msg)
                                offset += msg_length
                            else:
                                break
                
                return messages if messages else None
        
        return None

    def update_drone_info(self, mac, messages):
        """更新无人机信息"""
        if mac not in self.known_drones:
            self.known_drones[mac] = {
                'first_seen': datetime.now(),
                'last_seen': datetime.now(),
                'messages': {},
                'position_history': []  # 位置历史
            }
        
        self.known_drones[mac]['last_seen'] = datetime.now()
        
        for msg in messages:
            self.known_drones[mac]['messages'][msg['message_type']] = msg
            
            # 如果是位置消息，添加到位置历史
            if msg['message_type'] == 'Location/Vector':
                self.known_drones[mac]['position_history'].append({
                    'timestamp': datetime.now(),
                    'latitude': msg['latitude'],
                    'longitude': msg['longitude'],
                    'altitude': msg['altitude_baro'],
                    'speed_h': msg['speed_horizontal'],
                    'speed_v': msg['speed_vertical']
                })

    def print_detailed_crid_data(self, messages, source_mac):
        """打印详细的 C-RID 数据"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        
        print(f"\n{'='*120}")
        print(f"  🚁 中国无人机远程识别信号检测 [{timestamp}]")
        print(f"  📡 源 MAC: {source_mac}")
        print(f"  📋 GB42590-2023 + 试行标准 (25字节格式)")
        print(f"  🇨🇳 中国民用无人驾驶航空器系统安全要求")
        print(f"{'='*120}")
        
        has_china_compliant = False
        for msg in messages:
            if msg['message_type'] == 'Basic ID':
                print(f"  🆔 无人机身份信息 (符合试行标准表3):")
                print(f"    🆔 UAS ID: '{msg['uas_id']}'")
                print(f"    🏷️  ID 类型: {msg['id_type']} ({msg['id_type_raw']})")
                print(f"    🚁 机型: {msg['ua_type']} ({msg['ua_type_raw']})")
                
                is_china_compliant = msg['china_compliant']
                print(f"    🇨🇳 中国标准合规: {'✅ 是' if is_china_compliant else '❌ 否'}")
                if is_china_compliant:
                    has_china_compliant = True
            
            elif msg['message_type'] == 'Location/Vector':
                print(f"  📍 位置向量信息 (符合试行标准表4):")
                print(f"    🌍 纬度:  {msg['latitude']:.7f}°")
                print(f"    🌍 经度:  {msg['longitude']:.7f}°")
                print(f"    📏 高度:  {msg['altitude_baro']:.2f}m (气压), {msg['altitude_geo']:.2f}m (地理)")
                print(f"    📏 相对高度: {msg['height']:.2f}m")
                print(f"    🛬 飞行状态: {msg['status']} ({msg['status_raw']})")
                
                print(f"  ⚡ 速度信息:")
                print(f"    🧭 航向: {msg['direction']:.1f}°")
                print(f"    🚀 水平速度: {msg['speed_horizontal']:.2f} m/s")
                print(f"    🚀 垂直速度: {msg['speed_vertical']:.2f} m/s")
                
                print(f"  🎯 精度信息:")
                print(f"    🎯 水平精度: {msg['horiz_accuracy']}")
                print(f"    🎯 垂直精度: {msg['vert_accuracy']}")
                print(f"    🎯 速度精度: {msg['speed_accuracy']}")
                
                is_accurate = msg['accurate_enough']
                print(f"    🇨🇳 中国精度合规: {'✅ 是' if is_accurate else '❌ 否'}")
            
            elif msg['message_type'] == 'System':
                print(f"  🏭 系统信息 (符合试行标准表6):")
                print(f"    🧑 控制站位置类型: {msg['operator_location_type']}")
                print(f"    🧑 控制站位置: {msg['operator_latitude']:.7f}°, {msg['operator_longitude']:.7f}°")
                print(f"    🧑 控制站高度: {msg['operator_altitude']:.2f}m")
                print(f"    🏷️  分类归属区域: {msg['classification_region']} (2=中国)")
                
                if msg['classification_region'] == 2:  # 中国区域
                    print(f"    🇨🇳 中国区域合规: ✅")
                
                print(f"    🗺️  区域信息: {msg['area_count']} 个区域, 半径 {msg['area_radius']}m")
                print(f"    🗺️  区域范围: {msg['area_floor']:.2f}m - {msg['area_ceiling']:.2f}m")
                
                if msg['category_eu'] and msg['class_eu']:
                    print(f"    🇪🇺 EU 分类: {msg['category_eu']}, {msg['class_eu']}")
        
        print(f"  📦 消息计数器: {messages[0]['counter'] if messages else 'N/A'}")
        print(f"  📋 消息类型: {[msg['message_type'] for msg in messages]}")
        print(f"  📝 消息数量: {len(messages)}")
        print(f"{'='*120}\n")

    def print_summary(self):
        """打印统计摘要"""
        now = time.time()
        if now - self.last_update >= 10:  # 每10秒打印一次
            print(f"\n📊 [统计] 总包: {self.stats['total_packets']}, "
                  f"管理包: {self.stats['management_packets']}, "
                  f"C-RID包: {self.stats['crid_packets']}, "
                  f"已知无人机: {len(self.known_drones)}, "
                  f"PCAP记录: {'✅' if self.record_packets else '❌'}")
            
            # 显示各消息类型统计
            msg_stats = {}
            china_compliant_count = 0
            for mac, drone_info in self.known_drones.items():
                for msg_type in drone_info['messages'].keys():
                    msg_stats[msg_type] = msg_stats.get(msg_type, 0) + 1
                
                # 检查 Basic ID 合规性
                basic_msg = drone_info['messages'].get('Basic ID')
                if basic_msg and basic_msg.get('china_compliant', False):
                    china_compliant_count += 1
            
            if msg_stats:
                print("  📦 消息类型分布:")
                for msg_type, count in msg_stats.items():
                    print(f"    {msg_type}: {count}")
            
            if len(self.known_drones) > 0:
                print(f"  🇨🇳 中国标准合规: {china_compliant_count}/{len(self.known_drones)} 台")
            
            # 显示 pcap 状态
            print(f"  📝 PCAP: 已记录 {self.stats['pcap_packets']} 个包, "
                  f"当前文件大小: {self.current_pcap_size / 1024:.1f}KB")
            
            self.last_update = now

    def print_comprehensive_summary(self):
        """打印综合无人机摘要信息"""
        if len(self.known_drones) > 0:
            print(f"\n{'='*140}")
            print(f"  🚁 已检测到的无人机综合摘要 ({len(self.known_drones)} 台)")
            print(f"  📋 GB42590-2023 + 试行标准合规性评估")
            print(f"{'='*140}")
            
            china_compliant_count = 0
            for mac, drone_info in self.known_drones.items():
                basic_msg = drone_info['messages'].get('Basic ID')
                location_msg = drone_info['messages'].get('Location/Vector')
                system_msg = drone_info['messages'].get('System')
                
                is_china_compliant = basic_msg and basic_msg.get('china_compliant', False)
                if is_china_compliant:
                    china_compliant_count += 1
                
                print(f"  📡 MAC地址: {mac}")
                print(f"    🕐 首次检测: {drone_info['first_seen'].strftime('%H:%M:%S')}")
                print(f"    🕐 最后检测: {drone_info['last_seen'].strftime('%H:%M:%S')}")
                
                if basic_msg:
                    print(f"    🆔 UAS ID: {basic_msg['uas_id']}")
                    print(f"    🚁 机型: {basic_msg['ua_type']}")
                    print(f"    🇨🇳 中国标准: {'✅' if is_china_compliant else '❌'}")
                
                if location_msg:
                    print(f"    📍 位置: {location_msg['latitude']:.5f}, {location_msg['longitude']:.5f}")
                    print(f"    📏 高度: {location_msg['altitude_baro']:.2f}m")
                    print(f"    ⚡ 速度: {location_msg['speed_horizontal']:.2f}m/s (H), {location_msg['speed_vertical']:.2f}m/s (V)")
                    print(f"    🧭 航向: {location_msg['direction']:.1f}°")
                    print(f"    🎯 精度: {location_msg['horiz_accuracy']}, {location_msg['vert_accuracy']}")
                    print(f"    🇨🇳 精度合规: {'✅' if location_msg['accurate_enough'] else '❌'}")
                
                if system_msg:
                    print(f"    🧑 操作员: {system_msg['operator_latitude']:.5f}, {system_msg['operator_longitude']:.5f}")
                    print(f"    🧑 高度: {system_msg['operator_altitude']:.2f}m")
                    print(f"    🏷️  分类: {system_msg['classification_region']} (2=中国)")
                    print(f"    🗺️  区域: {system_msg['area_count']} 个, 半径 {system_msg['area_radius']}m")
                
                print(f"    📦 消息类型: {list(drone_info['messages'].keys())}")
                print(f"    📍 位置记录: {len(drone_info['position_history'])} 条")
                
                if len(drone_info['position_history']) > 1:
                    # 计算移动距离
                    first_pos = drone_info['position_history'][0]
                    last_pos = drone_info['position_history'][-1]
                    lat_diff = abs(last_pos['latitude'] - first_pos['latitude'])
                    lon_diff = abs(last_pos['longitude'] - first_pos['longitude'])
                    dist_km = (lat_diff * 111.32 + lon_diff * 85.39)  # 粗略估算
                    print(f"    🚀 移动距离: ~{dist_km:.2f} km")
                
                print()
            
            print(f"  🇨🇳 中国标准合规: {china_compliant_count}/{len(self.known_drones)} 台")
            print(f"  📝 PCAP 文件: 已记录 {self.stats['pcap_packets']} 个包")
            print(f"{'='*140}\n")

    def packet_handler(self, packet):
        """处理单个 Wi-Fi 数据包"""
        self.stats['total_packets'] += 1
        
        # 记录到 pcap 文件 (异步)
        self.write_pcap_packet(packet)
        self.stats['pcap_packets'] += 1
        
        if hasattr(packet, 'type') and packet.type == 0:  # Management frame
            self.stats['management_packets'] += 1
            
            src_mac = packet.addr2 if hasattr(packet, 'addr2') else 'Unknown'
            
            # 获取原始帧数据
            raw_bytes = bytes(packet)
            
            # 查找中国 C-RID 消息
            crid_messages = self.find_crid_in_frame(raw_bytes)
            
            if crid_messages:
                self.stats['crid_packets'] += 1
                
                # 更新无人机信息
                self.update_drone_info(src_mac, crid_messages)
                
                # 打印详细信息
                self.print_detailed_crid_data(crid_messages, src_mac)
        
        # 打印统计摘要
        self.print_summary()

def main():
    if len(sys.argv) < 2:
        print("用法: sudo python3 china_crid_receiver_pcap.py <interface>")
        print("示例: sudo python3 china_crid_receiver_pcap.py wlan1")
        print("\n确保接口设置为监控模式:")
        print("  sudo ip link set <interface> down")
        print("  sudo iw <interface> set monitor control")
        print("  sudo ip link set <interface> up")
        print("  sudo iw <interface> set channel 6")
        sys.exit(1)
    
    interface = sys.argv[1]
    print(f"🚀 中国 C-RID 信号探测器 (修正版 + PCAP记录)")
    print(f"📡 接口: {interface}")
    print(f"📋 检测 GB42590-2023 + 试行标准 C-RID 信号")
    print(f"🎯 显示详细位置、速度、高度信息")
    print(f"📝 同时记录 pcap 抓包文件")
    print(f"🔄 每10秒显示统计摘要")
    print(f"🛑 按 Ctrl+C 停止探测\n")
    
    receiver = ChinaCRIDReceiverWithPCAP()
    
    try:
        sniff(iface=interface, 
              prn=receiver.packet_handler, 
              store=0,
              filter="type mgt subtype beacon or type mgt subtype probe-req or type mgt subtype probe-resp")
    except KeyboardInterrupt:
        print(f"\n\n🛑 探测已停止")
        
        # 停止 pcap 记录
        receiver.pcap_running = False
        if receiver.pcap_queue:
            receiver.pcap_queue.put(None)  # 发送停止信号
        if receiver.pcap_writer:
            receiver.pcap_writer.close()
            print(f"📝 PCAP 文件已关闭")
        
        # 显示最终综合摘要
        receiver.print_comprehensive_summary()
        
        print(f"\n📊 最终统计:")
        print(f"  📦 总包数: {receiver.stats['total_packets']}")
        print(f"  📦 管理包: {receiver.stats['management_packets']}")
        print(f"  🚁 C-RID包: {receiver.stats['crid_packets']}")
        print(f"  🚁 已知无人机: {len(receiver.known_drones)}")
        print(f"  📝 PCAP记录: {receiver.stats['pcap_packets']} 个包")
        print(f"  📝 PCAP文件: {len(os.listdir('.'))} 个 .pcap 文件在当前目录")
        
        # 列出生成的 pcap 文件
        import os
        pcap_files = [f for f in os.listdir('.') if f.startswith('crid_capture_') and f.endswith('.pcap')]
        if pcap_files:
            print(f"  📝 PCAP文件列表:")
            for pcap_file in sorted(pcap_files):
                size_mb = os.path.getsize(pcap_file) / (1024*1024)
                print(f"    {pcap_file} ({size_mb:.2f} MB)")

if __name__ == "__main__":
    main()