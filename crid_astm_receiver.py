#!/usr/bin/env python3
"""
C-RID 无人机远程识别信号探测器 (ASTM F3411-22a Table 5 兼容)
支持 GB42590-2023 中国标准，基于 ASTM F3411-22a Table 5
增加 pcap 抓包记录功能
"""

import sys
import struct
import time
from datetime import datetime
from collections import defaultdict
import os
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Elt

class CRIDASTMReceiver:
    def __init__(self):
        # C-RID 常量
        self.CRID_OUI = b'\xFA\x0B\xBC'  # GB42590-2023 OUI
        self.CRID_VENDOR_TYPE = 0x0D     # GB42590-2023 固定值
        
        # ASTM F3411-22a Table 5 ID Type 映射
        self.id_type_names = {
            0: "None/Undeclared",
            1: "Serial Number",
            2: "CAA Registration ID",  # 中国标准要求
            3: "UTM Assigned UUID",
            4: "Specific Session ID"
        }
        
        # ASTM F3411-22a Table 5 UA Type 映射
        self.ua_type_names = {
            0: "None/Not declared",
            1: "Aeroplane/Fixed wing",
            2: "Helicopter/Multirotor",  # 最常见类型
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
        
        # ASTM F3411-22a Table 7 Status 映射
        self.status_names = {
            0: "Undeclared",
            1: "Ground",
            2: "Airborne",  # 中国标准要求
            3: "Emergency",
            4: "Remote ID System Failure"
        }
        
        # ASTM F3411-22a Table 7 Classification Type 映射
        self.classification_names = {
            0: "Undeclared",
            1: "EU",  # 中国标准接受
            2: "Other"
        }
        
        # EU Category 映射
        self.eu_category_names = {
            0: "Undeclared", 1: "Class 0", 2: "Class 1", 3: "Class 2", 
            4: "Class 3", 5: "Class 4", 6: "Class 5", 7: "Class 6"
        }
        
        # EU Class 映射
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
        self.max_pcap_size = 100 * 1024 * 1024  # 100MB
        self.current_pcap_size = 0
        self.pcap_file_counter = 0

    def init_pcap_recording(self, base_filename="crid_capture"):
        """初始化 pcap 记录"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        pcap_filename = f"{base_filename}_{timestamp}.pcap"
        
        self.pcap_writer = PcapWriter(pcap_filename, append=True)
        self.current_pcap_size = 0
        self.pcap_file_counter = 0
        
        print(f"📝 开始记录 pcap 文件: {pcap_filename}")
        return pcap_filename
    
    def rotate_pcap_file(self, base_filename="crid_capture"):
        """轮换 pcap 文件"""
        if self.pcap_writer:
            self.pcap_writer.close()
        
        self.pcap_file_counter += 1
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        new_filename = f"{base_filename}_{timestamp}_{self.pcap_file_counter:03d}.pcap"
        
        self.pcap_writer = PcapWriter(new_filename, append=True)
        self.current_pcap_size = 0
        
        print(f"📝 轮换到新的 pcap 文件: {new_filename}")
        return new_filename
    
    def parse_basic_id_message(self, data_bytes):
        """解析 ASTM F3411-22a Table 5 Basic ID 消息"""
        if len(data_bytes) < 25:
            return None
            
        # 确保输入是字节类型
        if isinstance(data_bytes, list):
            data = bytes(data_bytes)
        else:
            data = data_bytes
            
        # 第一个字节: Message Type (4 bits) + Protocol Version (4 bits)
        msg_type = data[0] & 0x0F
        protocol_version = data[0] >> 4
        
        # 检查是否是 Basic ID 消息
        if msg_type != 0:
            return None
            
        id_type = data[1]
        ua_type = data[2]
        
        # 提取 UAS ID (20 字节)
        uas_id_bytes = data[3:23]
        uas_id = uas_id_bytes.rstrip(b'\x00 \x20').decode('ascii', errors='ignore')
        
        return {
            'message_type': 'Basic ID',
            'protocol_version': protocol_version,
            'id_type': self.id_type_names.get(id_type, f"Unknown ({id_type})"),
            'ua_type': self.ua_type_names.get(ua_type, f"Unknown ({ua_type})"),
            'uas_id': uas_id,
            'id_type_raw': id_type,
            'ua_type_raw': ua_type,
            'china_compliant': id_type == 2  # CAA Registration ID (中国标准要求)
        }
    
    def parse_location_message(self, data_bytes):
        """解析 ASTM F3411-22a Table 7 Location 消息"""
        if len(data_bytes) < 39:
            return None
            
        # 确保输入是字节类型
        if isinstance(data_bytes, list):
            data = bytes(data_bytes)
        else:
            data = data_bytes
            
        # 第一个字节: Message Type (4 bits) + Protocol Version (4 bits)
        msg_type = data[0] & 0x0F
        protocol_version = data[0] >> 4
        
        # 检查是否是 Location 消息
        if msg_type != 1:
            return None
            
        # 状态 (4 bits) + 方向高 4 位
        status_direction = data[1]
        status = status_direction >> 4
        direction_high = status_direction & 0x0F
        
        # 方向 (16 位，0.1度单位)
        direction_low = data[2]
        direction = ((direction_high << 8) | direction_low) / 10.0
        
        # 水平速度 (0.1m/s单位)
        speed_h = data[3] / 10.0
        
        # 垂直速度 (0.1m/s单位, signed)
        speed_v = struct.unpack('<b', data[4:5])[0] / 10.0
        
        # 纬度 (1E-7度单位, little endian)
        lat = struct.unpack('<d', data[5:13])[0]
        
        # 经度 (1E-7度单位, little endian)
        lon = struct.unpack('<d', data[13:21])[0]
        
        # 气压高度 (cm, little endian)
        alt_baro = struct.unpack('<f', data[21:25])[0] / 100.0  # 转换为米
        
        # 地理高度 (cm, little endian)
        alt_geo = struct.unpack('<f', data[25:29])[0] / 100.0  # 转换为米
        
        # 相对地面高度 (cm, little endian)
        height = struct.unpack('<f', data[29:33])[0] / 100.0  # 转换为米
        
        # 高度参考类型
        height_type = data[33]
        
        # 精度信息
        horiz_accuracy = data[34]
        vert_accuracy = data[35]
        baro_accuracy = data[36]
        speed_accuracy = data[37]
        ts_accuracy = data[38]
        
        return {
            'message_type': 'Location',
            'protocol_version': protocol_version,
            'status': self.status_names.get(status, f"Unknown ({status})"),
            'direction': direction,
            'speed_horizontal': speed_h,
            'speed_vertical': speed_v,
            'latitude': lat,
            'longitude': lon,
            'altitude_baro': alt_baro,
            'altitude_geo': alt_geo,
            'height': height,
            'height_type': self.height_ref_names.get(height_type, f"Unknown ({height_type})"),
            'horiz_accuracy': self.get_accuracy_str(horiz_accuracy, self.horiz_accuracy_names),
            'vert_accuracy': self.get_accuracy_str(vert_accuracy, self.vert_accuracy_names),
            'speed_accuracy': self.get_accuracy_str(speed_accuracy, self.speed_accuracy_names),
            'status_raw': status,
            'accurate_enough': (horiz_accuracy <= 4 and vert_accuracy <= 4)  # 中国精度要求
        }
    
    def parse_system_message(self, data_bytes):
        """解析 ASTM F3411-22a Table 8 System 消息"""
        if len(data_bytes) < 39:
            return None
            
        # 确保输入是字节类型
        if isinstance(data_bytes, list):
            data = bytes(data_bytes)
        else:
            data = data_bytes
            
        # 第一个字节: Message Type (4 bits) + Protocol Version (4 bits)
        msg_type = data[0] & 0x0F
        protocol_version = data[0] >> 4
        
        # 检查是否是 System 消息
        if msg_type != 4:
            return None
            
        # 操作员位置类型 (4 bits) + 分类类型 (4 bits)
        op_loc_class = data[1]
        operator_location_type = op_loc_class >> 4
        classification_type = op_loc_class & 0x0F
        
        # 操作员纬度 (1E-7度单位, little endian)
        operator_lat = struct.unpack('<d', data[2:10])[0]
        
        # 操作员经度 (1E-7度单位, little endian)
        operator_lon = struct.unpack('<d', data[10:18])[0]
        
        # 区域计数 (2 bytes, little endian)
        area_count = struct.unpack('<H', data[18:20])[0]
        
        # 区域半径 (2 bytes, little endian)
        area_radius = struct.unpack('<H', data[20:22])[0]
        
        # 区域上限 (4 bytes, little endian)
        area_ceiling = struct.unpack('<f', data[22:26])[0] / 100.0  # 转换为米
        
        # 区域下限 (4 bytes, little endian)
        area_floor = struct.unpack('<f', data[26:30])[0] / 100.0  # 转换为米
        
        # EU 类别 (4 bits) + EU 级别 (4 bits)
        category_class = data[30]
        category_eu = category_class >> 4
        class_eu = category_class & 0x0F
        
        # 操作员地理高度 (4 bytes, little endian)
        operator_alt = struct.unpack('<f', data[31:35])[0] / 100.0  # 转换为米
        
        # 时间戳 (4 bytes, little endian)
        timestamp = struct.unpack('<I', data[35:39])[0]
        
        return {
            'message_type': 'System',
            'protocol_version': protocol_version,
            'operator_location_type': operator_location_type,
            'classification_type': self.classification_names.get(classification_type, f"Unknown ({classification_type})"),
            'operator_latitude': operator_lat,
            'operator_longitude': operator_lon,
            'area_count': area_count,
            'area_radius': area_radius,
            'area_ceiling': area_ceiling,
            'area_floor': area_floor,
            'category_eu': self.eu_category_names.get(category_eu, f"Unknown ({category_eu})"),
            'class_eu': self.eu_class_names.get(class_eu, f"Unknown ({class_eu})"),
            'operator_altitude': operator_alt,
            'timestamp': timestamp,
            'classification_type_raw': classification_type,
            'china_compliant': classification_type == 1  # EU Classification (中国标准接受)
        }
    
    def get_accuracy_str(self, value, accuracy_list):
        if value <= 15:
            return accuracy_list[value]
        return "Invalid"
    
    def parse_crid_message(self, raw_bytes):
        """解析 GB42590-2023 C-RID 消息"""
        # 检查是否包含 GB42590 OUI 和固定 Vendor Type
        for i in range(len(raw_bytes) - 10):
            if (raw_bytes[i:i+3] == self.CRID_OUI and 
                i + 4 < len(raw_bytes) and 
                raw_bytes[i+3] == self.CRID_VENDOR_TYPE):
                
                oui_pos = i
                msg_counter = raw_bytes[oui_pos + 4]  # 消息计数器
                
                # 从消息计数器后面开始解析子消息
                offset = oui_pos + 5
                messages = []
                
                while offset < len(raw_bytes) - 2:
                    if offset >= len(raw_bytes):
                        break
                        
                    sub_msg_type = raw_bytes[offset]
                    offset += 1
                    
                    if sub_msg_type == 0x00:  # Basic ID
                        remaining_bytes = len(raw_bytes) - offset
                        if remaining_bytes >= 24:
                            basic_data = raw_bytes[offset:offset + 24]
                            parsed_msg = self.parse_basic_id_message(basic_data)
                            if parsed_msg:
                                parsed_msg['counter'] = msg_counter
                                messages.append(parsed_msg)
                            offset += 24
                    elif sub_msg_type == 0x01:  # Location
                        remaining_bytes = len(raw_bytes) - offset
                        if remaining_bytes >= 38:
                            location_data = raw_bytes[offset:offset + 38]
                            parsed_msg = self.parse_location_message(location_data)
                            if parsed_msg:
                                parsed_msg['counter'] = msg_counter
                                messages.append(parsed_msg)
                            offset += 38
                    elif sub_msg_type == 0x04:  # System
                        remaining_bytes = len(raw_bytes) - offset
                        if remaining_bytes >= 38:
                            system_data = raw_bytes[offset:offset + 38]
                            parsed_msg = self.parse_system_message(system_data)
                            if parsed_msg:
                                parsed_msg['counter'] = msg_counter
                                messages.append(parsed_msg)
                            offset += 38
                    else:
                        # 跳过未知消息类型
                        break
                
                return messages if messages else None
        
        return None
    
    def update_drone_info(self, mac, messages):
        """更新无人机信息"""
        if mac not in self.known_drones:
            self.known_drones[mac] = {
                'first_seen': datetime.now(),
                'last_seen': datetime.now(),
                'messages': {}
            }
        
        self.known_drones[mac]['last_seen'] = datetime.now()
        
        for msg in messages:
            self.known_drones[mac]['messages'][msg['message_type']] = msg
    
    def print_detailed_crid_data(self, messages, source_mac):
        """打印详细的 C-RID 数据"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        
        print(f"\n{'='*120}")
        print(f"  🚁 中国无人机远程识别信号检测 [{timestamp}]")
        print(f"  📡 源 MAC: {source_mac}")
        print(f"  📋 ASTM F3411-22a Table 5/7/8 + GB42590-2023 标准")
        print(f"  🇨🇳 中国民航局标准兼容")
        print(f"{'='*120}")
        
        has_china_compliant = False
        for msg in messages:
            if msg['message_type'] == 'Basic ID':
                print(f"  🆔 无人机身份信息 (ASTM F3411-22a Table 5):")
                print(f"    🆔 UAS ID: '{msg['uas_id']}'")
                print(f"    🏷️  ID 类型: {msg['id_type']} ({msg['id_type_raw']})")
                print(f"    🚁 机型: {msg['ua_type']} ({msg['ua_type_raw']})")
                
                is_china_compliant = msg['china_compliant']
                print(f"    🇨🇳 中国标准合规: {'✅ 是' if is_china_compliant else '❌ 否'}")
                if is_china_compliant:
                    has_china_compliant = True
            
            elif msg['message_type'] == 'Location':
                print(f"  📍 位置信息 (ASTM F3411-22a Table 7):")
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
                print(f"  🏭 系统信息 (ASTM F3411-22a Table 8):")
                print(f"    🧑 操作员位置类型: {msg['operator_location_type']}")
                print(f"    🧑 操作员位置: {msg['operator_latitude']:.7f}°, {msg['operator_longitude']:.7f}°")
                print(f"    🧑 操作员高度: {msg['operator_altitude']:.2f}m")
                print(f"    🏷️  分类类型: {msg['classification_type']} ({msg['classification_type_raw']})")
                
                if msg['classification_type_raw'] == 1:  # EU 分类
                    print(f"    🇪🇺 EU 类别: {msg['category_eu']}")
                    print(f"    🇪🇺 EU 级别: {msg['class_eu']}")
                
                print(f"    🗺️  区域信息: {msg['area_count']} 个区域, 半径 {msg['area_radius']}m")
                print(f"    🗺️  区域范围: {msg['area_floor']:.2f}m - {msg['area_ceiling']:.2f}m")
                print(f"    🇨🇳 中国分类合规: {'✅ 是' if msg['china_compliant'] else '❌ 否'}")
        
        print(f"  📦 消息计数器: {messages[0]['counter'] if messages else 'N/A'}")
        print(f"  📋 消息类型: {[msg['message_type'] for msg in messages]}")
        print(f"{'='*120}\n")
    
    def print_summary(self):
        """打印统计摘要"""
        now = time.time()
        if now - self.last_detailed_report >= 30:  # 每30秒打印一次摘要
            if len(self.known_drones) > 0:
                print(f"\n{'='*100}")
                print(f"  🚁 已检测到的无人机摘要 ({len(self.known_drones)} 台)")
                print(f"  📋 ASTM F3411-22a + GB42590-2023 兼容性统计")
                print(f"{'='*100}")
                
                china_compliant_count = 0
                for mac, drone_info in self.known_drones.items():
                    basic_msg = drone_info['messages'].get('Basic ID')
                    location_msg = drone_info['messages'].get('Location')
                    
                    is_china_compliant = basic_msg and basic_msg.get('china_compliant', False)
                    if is_china_compliant:
                        china_compliant_count += 1
                    
                    print(f"  MAC: {mac}")
                    print(f"    首次检测: {drone_info['first_seen'].strftime('%H:%M:%S')}")
                    print(f"    最后检测: {drone_info['last_seen'].strftime('%H:%M:%S')}")
                    
                    if basic_msg:
                        print(f"    UAS ID: {basic_msg['uas_id']}")
                        print(f"    机型: {basic_msg['ua_type']}")
                        print(f"    中国标准: {'✅' if is_china_compliant else '❌'}")
                    
                    if location_msg:
                        print(f"    位置: {location_msg['latitude']:.5f}, {location_msg['longitude']:.5f}")
                        print(f"    高度: {location_msg['altitude_baro']:.2f}m")
                        print(f"    速度: {location_msg['speed_horizontal']:.2f}m/s")
                    
                    print(f"    消息类型: {list(drone_info['messages'].keys())}")
                    print()
                
                print(f"  🇨🇳 中国标准合规: {china_compliant_count}/{len(self.known_drones)} 台")
            else:
                print(f"\n[统计] 总包: {self.stats['total_packets']}, "
                      f"管理包: {self.stats['management_packets']}, "
                      f"C-RID包: {self.stats['cr_id_packets']}, "
                      f"已知无人机: {len(self.known_drones)}")
            
            self.last_detailed_report = now
    
    def packet_handler(self, packet):
        """处理单个 Wi-Fi 数据包"""
        self.stats['total_packets'] += 1
        
        if hasattr(packet, 'type') and packet.type == 0:  # Management frame
            self.stats['management_packets'] += 1
            
            src_mac = packet.addr2 if hasattr(packet, 'addr2') else 'Unknown'
            
            # 记录到 pcap 文件
            if self.record_packets and self.pcap_writer:
                try:
                    self.pcap_writer.write(packet)
                    self.current_pcap_size += len(bytes(packet))
                    
                    # 检查是否需要轮换文件
                    if self.current_pcap_size >= self.max_pcap_size:
                        self.rotate_pcap_file()
                except Exception as e:
                    print(f"PCAP write error: {e}")
            
            # 获取原始帧数据
            raw_bytes = bytes(packet)
            
            # 查找 GB42590 C-RID 消息
            crid_messages = self.parse_crid_message(raw_bytes)
            
            if crid_messages:
                self.stats['cr_id_packets'] += 1
                
                # 更新无人机信息
                self.update_drone_info(src_mac, crid_messages)
                
                # 打印详细信息
                self.print_detailed_crid_data(crid_messages, src_mac)
        
        # 打印统计摘要
        self.print_summary()

    def start_capture(self, interface, record_pcap=True):
        """开始捕获数据包"""
        print(f"🚀 C-RID 无人机远程识别信号探测器 (ASTM F3411-22a Table 5 兼容)")
        print(f"📡 接口: {interface}")
        print(f"📋 检测 ASTM F3411-22a + GB42590-2023 标准信号")
        print(f"🎯 显示详细位置、速度、高度信息")
        print(f"🔄 每30秒显示统计摘要")
        
        if record_pcap:
            pcap_filename = self.init_pcap_recording("crid_capture")
            print(f"📝 同时记录 pcap 抓包文件: {pcap_filename}")
            print(f"📝 文件大小限制: {self.max_pcap_size / (1024*1024):.0f}MB")
        else:
            print(f"📝 不记录 pcap 文件")
        
        print(f"🛑 按 Ctrl+C 停止探测\n")
        
        try:
            sniff(iface=interface, 
                  prn=self.packet_handler, 
                  store=0,
                  filter="type mgt subtype beacon or type mgt subtype probe-req or type mgt subtype probe-resp")
        except KeyboardInterrupt:
            print(f"\n\n🛑 探测已停止")
            
            # 关闭 pcap 文件
            if self.pcap_writer:
                self.pcap_writer.close()
                print(f"📝 pcap 文件已关闭")
            
            # 显示最终摘要
            if len(self.known_drones) > 0:
                print(f"\n{'='*100}")
                print(f"  🚁 最终无人机检测摘要")
                print(f"{'='*100}")
                
                china_compliant_count = 0
                for mac, drone_info in self.known_drones.items():
                    basic_msg = drone_info['messages'].get('Basic ID')
                    is_china_compliant = basic_msg and basic_msg.get('china_compliant', False)
                    if is_china_compliant:
                        china_compliant_count += 1
                    
                    print(f"  MAC: {mac}")
                    print(f"    UAS ID: {basic_msg['uas_id'] if basic_msg else 'N/A'}")
                    print(f"    位置: {drone_info['messages'].get('Location', {}).get('latitude', 'N/A'):.5f}, "
                          f"{drone_info['messages'].get('Location', {}).get('longitude', 'N/A'):.5f}")
                    print(f"    最后检测: {drone_info['last_seen'].strftime('%Y-%m-%d %H:%M:%S')}")
                    print()
                
                print(f"  🇨🇳 中国标准合规: {china_compliant_count}/{len(self.known_drones)} 台")
            
            print(f"\n📊 最终统计:")
            print(f"  📦 总包数: {self.stats['total_packets']}")
            print(f"  📦 管理包: {self.stats['management_packets']}")
            print(f"  🚁 C-RID包: {self.stats['cr_id_packets']}")
            print(f"  🚁 已知无人机: {len(self.known_drones)}")

def main():
    if len(sys.argv) < 2:
        print("用法: sudo python3 crid_astm_receiver.py <interface> [record_pcap]")
        print("示例: sudo python3 crid_astm_receiver.py wlan1")
        print("示例: sudo python3 crid_astm_receiver.py wlan1 1  # 同时记录 pcap")
        print("\n确保接口设置为监控模式:")
        print("  sudo ip link set <interface> down")
        print("  sudo iw <interface> set monitor control")
        print("  sudo ip link set <interface> up")
        print("  sudo iw <interface> set channel 6")
        sys.exit(1)
    
    interface = sys.argv[1]
    record_pcap = len(sys.argv) > 2 and sys.argv[2] == '1'
    
    receiver = CRIDASTMReceiver()
    receiver.start_capture(interface, record_pcap)

if __name__ == "__main__":
    main()
