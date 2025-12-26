#!/usr/bin/env python3
"""
Remote ID 探测器（支持 System 消息）
✅ Basic ID / Location / System 全解析
✅ 修复所有 C-RID Packed 格式问题
✅ 实测通过 ESP32 C-RID
"""

import sys
import struct
import time
import os
from datetime import datetime
from collections import defaultdict
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Elt
import threading
import queue

class RemoteIDReceiver:
    def __init__(self):
        self.ASTM_OUI = b'\x06\x05\x04'
        self.CHINA_OUI = b'\xFA\x0B\xBC'
        
        self.CR_ID_TYPES = {
            0: "None", 1: "Serial Number", 2: "CAA Registration ID",
            3: "UTM Assigned UUID", 4: "Specific Session ID"
        }
        self.CR_UA_TYPES = {
            0: "None/Not declared", 1: "Aeroplane/Fixed wing",
            2: "Helicopter/Multirotor", 3: "Gyroplane", 4: "Hybrid Lift",
            5: "Ornithopter", 6: "Glider", 7: "Kite", 8: "Free Balloon",
            9: "Captive Balloon", 10: "Airship", 11: "Free Fall/Parachute",
            12: "Rocket", 13: "Tethered Powered", 14: "Ground Obstacle", 15: "Other"
        }
        self.STATUS_NAMES = {
            0: "Undeclared", 1: "Ground", 2: "Airborne",
            3: "Emergency", 4: "Remote ID System Failure"
        }
        self.HOR_ACC = ["Unknown", "<=1m", "<=2m", "<=3m", "<=4m", "<=6m", "<=10m", "<=15m", "<=20m", "<=25m", "<=30m", "<=35m", "<=40m", "<=45m", "<=50m", ">50m"]
        self.VER_ACC = ["Unknown", "<=1m", "<=2m", "<=3m", "<=4m", "<=5m", "<=6m", "<=7m", "<=8m", "<=9m", "<=10m", "<=15m", "<=20m", "<=25m", "<=30m", ">30m"]
        self.COORD_SYS = {0: "WGS84", 1: "Other"}
        self.CLASS_REGION = {0: "Undeclared", 1: "EU", 2: "China", 3: "USA", 4: "Other"}
        self.OP_LOC_TYPE = {0: "Takeoff", 1: "LiveGNSS", 2: "Fixed", 3: "Operator"}
        
        self.stats = defaultdict(int)
        self.known_drones = {}
        self.last_update = time.time()
        
        # PCAP
        self.pcap_writer = None
        self.record_packets = True
        self.max_pcap_size = 50 * 1024 * 1024
        self.current_pcap_size = 0
        self.pcap_file_counter = 0
        self.pcap_queue = queue.Queue(maxsize=1000)
        self.pcap_thread = None
        self.pcap_running = False
        self.pcap_lock = threading.Lock()
        
        self.init_pcap()

    def init_pcap(self):
        try:
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"remoteid_capture_{ts}.pcap"
            self.pcap_writer = PcapWriter(filename, append=False, sync=True)
            self.pcap_running = True
            self.pcap_thread = threading.Thread(target=self.pcap_worker, daemon=False)
            self.pcap_thread.start()
            print(f"📝 [PCAP] Recording to: {filename}")
        except Exception as e:
            print(f"❌ [PCAP] Failed: {e}")
            self.record_packets = False

    def pcap_worker(self):
        while self.pcap_running:
            try:
                pkt = self.pcap_queue.get(timeout=0.5)
                if pkt is None: break
                with self.pcap_lock:
                    if self.pcap_writer:
                        self.pcap_writer.write(pkt)
                        self.current_pcap_size += len(bytes(pkt))
                        if self.current_pcap_size >= self.max_pcap_size:
                            self.rotate_pcap()
                self.pcap_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                print(f"❌ [PCAP] Error: {e}")
        while not self.pcap_queue.empty():
            try:
                p = self.pcap_queue.get(timeout=0.1)
                if p is not None:
                    with self.pcap_lock:
                        if self.pcap_writer:
                            self.pcap_writer.write(p)
                self.pcap_queue.task_done()
            except: break

    def rotate_pcap(self):
        with self.pcap_lock:
            if self.pcap_writer:
                self.pcap_writer.close()
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            self.pcap_file_counter += 1
            new_name = f"remoteid_capture_{ts}_{self.pcap_file_counter:03d}.pcap"
            try:
                self.pcap_writer = PcapWriter(new_name, append=False, sync=True)
                self.current_pcap_size = 0
                print(f"📝 [PCAP] Rotated to: {new_name}")
            except Exception as e:
                print(f"❌ [PCAP] Rotate failed: {e}")
                self.record_packets = False

    def write_pcap(self, pkt):
        if self.record_packets and self.pcap_running:
            try:
                self.pcap_queue.put_nowait(pkt)
            except queue.Full:
                pass

    # ==================== C-RID Packed 消息解析器 ====================
    def parse_crid_packed_basic_id(self, data):
        """解析 25B Basic ID"""
        if len(data) < 25:
            return None
        id_ua_byte = data[1]  # 第1字节
        id_type = (id_ua_byte >> 4) & 0x0F
        ua_type = id_ua_byte & 0x0F
        uas_id_bytes = data[2:22]
        try:
            uas_id = uas_id_bytes.decode('ascii').rstrip('\x00 \x20')
        except:
            uas_id = uas_id_bytes.hex()
        has_quote = uas_id.startswith('"') or uas_id.startswith("'")
        return {
            'standard': 'China C-RID (GB42590-2023)',
            'message_type': 'Basic ID',
            'id_type': self.CR_ID_TYPES.get(id_type, f"Unknown ({id_type})"),
            'ua_type': self.CR_UA_TYPES.get(ua_type, f"Unknown ({ua_type})"),
            'uas_id': uas_id,
            'id_type_raw': id_type,
            'ua_type_raw': ua_type,
            'china_compliant': (id_type == 2),
            'warning': 'UAS ID starts with quote (device bug?)' if has_quote else None
        }

    def parse_crid_packed_location(self, data):
        """解析 25B Location"""
        if len(data) < 25:
            return None
        flags = data[1]
        status = (flags >> 4) & 0x0F
        direction_high = flags & 0x0F
        direction_low = data[2]
        direction_raw = (direction_high << 8) | direction_low
        direction = (direction_raw * 360.0) / 65535.0 if direction_raw != 0xFFFF else "Unknown"
        speed_h = data[3] * 0.25 if data[3] != 255 else "Unknown"
        speed_v = (data[4] - 128) * 0.5 if data[4] != 255 else "Unknown"
        lat_raw = struct.unpack('<i', data[5:9])[0]
        lat = lat_raw / 10000000.0 if lat_raw != 0x7FFFFFFF else "Unknown"
        lon_raw = struct.unpack('<i', data[9:13])[0]
        lon = lon_raw / 10000000.0 if lon_raw != 0x7FFFFFFF else "Unknown"
        alt_raw = struct.unpack('<H', data[13:15])[0]
        altitude = alt_raw * 0.5 - 1000.0 if alt_raw != 0xFFFF else "Unknown"
        horiz_acc = data[15]
        vert_acc = data[16]
        return {
            'standard': 'China C-RID (GB42590-2023)',
            'message_type': 'Location',
            'status': self.STATUS_NAMES.get(status, f"Unknown ({status})"),
            'direction_deg': direction,
            'speed_horizontal_m_s': speed_h,
            'speed_vertical_m_s': speed_v,
            'latitude': lat,
            'longitude': lon,
            'altitude_m': altitude,
            'horiz_accuracy': self.HOR_ACC[horiz_acc] if horiz_acc <= 15 else "Invalid",
            'vert_accuracy': self.VER_ACC[vert_acc] if vert_acc <= 15 else "Invalid"
        }

    def parse_crid_packed_system(self, data):
        """✅ 新增：解析 25B System 消息"""
        if len(data) < 25:
            return None
        flags = data[1]
        coord_sys = (flags >> 7) & 0x01
        class_region = (flags >> 4) & 0x07
        op_loc_type = (flags >> 2) & 0x03
        # 操作员纬度 (double, little-endian)
        try:
            op_lat = struct.unpack('<i', data[2:6])[0] / 10000000.0 
        except:
            op_lat = "Invalid"
        # 操作员经度 (double, little-endian)
        try:
            op_lon = struct.unpack('<i', data[6:10])[0] / 10000000.0 
        except:
            op_lon = "Invalid"
        # 运行区域计数 (uint16, little-endian)
        area_count = struct.unpack('<H', data[10:12])[0]
        # 运行区域半径 (meters)
        area_radius = data[12]
        return {
            'standard': 'China C-RID (GB42590-2023)',
            'message_type': 'System',
            'coordinate_system': self.COORD_SYS.get(coord_sys, f"Unknown ({coord_sys})"),
            'classification_region': self.CLASS_REGION.get(class_region, f"Unknown ({class_region})"),
            'operator_location_type': self.OP_LOC_TYPE.get(op_loc_type, f"Unknown ({op_loc_type})"),
            'operator_latitude': op_lat,
            'operator_longitude': op_lon,
            'area_count': area_count,
            'area_radius_m': area_radius,
            'china_region': (class_region == 2)
        }

    def find_crid_in_frame(self, raw_bytes):
        """解析 C-RID Packed 格式"""
        idx = 0
        while idx <= len(raw_bytes) - 5:
            if raw_bytes[idx:idx+3] == self.CHINA_OUI and raw_bytes[idx+3] == 0x0D:
                msg_counter = raw_bytes[idx+4]
                payload = raw_bytes[idx+5:]
                messages = []
                
                # 检测 Packed 格式 (0xF1)
                if len(payload) >= 3 and (payload[0] >> 4) == 0xF:
                    if payload[1] == 0x19 and 1 <= payload[2] <= 10:
                        msg_count = payload[2]
                        offset = 3
                        for _ in range(msg_count):
                            if offset + 25 > len(payload):
                                break
                            msg_data = payload[offset:offset+25]
                            msg_type = (msg_data[0] >> 4) & 0x0F
                            if msg_type == 0:
                                parsed = self.parse_crid_packed_basic_id(msg_data)
                            elif msg_type == 1:
                                parsed = self.parse_crid_packed_location(msg_data)
                            elif msg_type == 4:
                                parsed = self.parse_crid_packed_system(msg_data)
                            else:
                                parsed = {
                                    'standard': 'China C-RID (GB42590-2023)',
                                    'message_type': f'Unknown ({msg_type})',
                                    'raw_hex': msg_data.hex()
                                }
                            if parsed:
                                parsed['counter'] = msg_counter
                                messages.append(parsed)
                            offset += 25
                
                if messages:
                    return messages
            idx += 1
        return None

    # ==================== ASTM 解析器（简化） ====================
    def parse_astm_message(self, data):
        if len(data) < 25: return None
        msg_type = (data[0] >> 4) & 0x0F
        if data[1] != 0xFD: return None
        payload = data[2:25]
        if msg_type == 0:
            uas = payload[1:21].rstrip(b'\x00')
            try: uas = uas.decode('utf-8').strip()
            except: uas = uas.hex()
            return {'standard': 'ASTM F3411-22a', 'message_type': 'Basic ID', 'uas_id': uas}
        return None

    def find_astm_in_frame(self, raw_bytes):
        idx = 0
        while idx <= len(raw_bytes) - (3 + 25):
            if raw_bytes[idx:idx+3] == self.ASTM_OUI:
                offset = idx + 3
                msgs = []
                while offset + 25 <= len(raw_bytes):
                    msg_data = raw_bytes[offset:offset+25]
                    parsed = self.parse_astm_message(msg_data)
                    if parsed:
                        msgs.append(parsed)
                    offset += 25
                if msgs:
                    return msgs
            idx += 1
        return None

    # ==================== 主处理 ====================
    def update_drone(self, mac, messages):
        if mac not in self.known_drones:
            self.known_drones[mac] = {'first_seen': datetime.now(), 'last_seen': datetime.now(), 'messages': {}}
        self.known_drones[mac]['last_seen'] = datetime.now()
        for msg in messages:
            key = f"{msg['message_type']}_{msg.get('counter', '')}"
            self.known_drones[mac]['messages'][key] = msg

    def print_messages(self, messages, src_mac):
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        standards = sorted(set(msg['standard'] for msg in messages))
        print(f"\n{'='*100}")
        print(f"  🌍 Remote ID Detected [{ts}]")
        print(f"  📡 MAC: {src_mac}")
        print(f"  📋 Standards: {', '.join(standards)}")
        print(f"{'='*100}")
        for msg in messages:
            if msg['message_type'] == 'Basic ID':
                print(f"  🆔 [{msg['standard']}] UAS ID: '{msg['uas_id']}'")
                if 'ua_type' in msg:
                    print(f"    🚁 Type: {msg['ua_type']} (Raw: {msg['ua_type_raw']})")
                if msg['standard'] == 'China C-RID (GB42590-2023)':
                    compliant = '✅' if msg.get('china_compliant') else '❌'
                    print(f"    🇨🇳 China Compliant: {compliant} (ID Type: {msg['id_type_raw']})")
                if msg.get('warning'):
                    print(f"    ⚠️  {msg['warning']}")
            elif msg['message_type'] == 'Location':
                lat = msg['latitude']
                lon = msg['longitude']
                alt = msg['altitude_m']
                if isinstance(lat, float) and isinstance(lon, float):
                    print(f"  📍 [{msg['standard']}] {lat:.6f}, {lon:.6f} | Alt: {alt}m")
                else:
                    print(f"  📍 [{msg['standard']}] Location: {lat}, {lon} | Alt: {alt}m")
            elif msg['message_type'] == 'System':
                op_lat = msg['operator_latitude']
                op_lon = msg['operator_longitude']
                print(f"  🏭 [{msg['standard']}] Operator: {op_lat:.6f}, {op_lon:.6f}")
                print(f"    🗺️  Region: {msg['classification_region']} {'🇨🇳' if msg.get('china_region') else ''}")
                print(f"    📍 Type: {msg['operator_location_type']} | Area: {msg['area_count']} zones, {msg['area_radius_m']}m radius")
        print(f"  📦 Total Messages: {len(messages)}")
        print(f"{'='*100}\n")

    def packet_handler(self, pkt):
        self.stats['total'] += 1
        self.write_pcap(pkt)
        self.stats['pcap'] += 1

        if hasattr(pkt, 'type') and pkt.type == 0:
            src_mac = getattr(pkt, 'addr2', 'Unknown')
            raw = bytes(pkt)
            
            astm_msgs = self.find_astm_in_frame(raw)
            if astm_msgs:
                self.stats['astm'] += 1
                self.update_drone(src_mac, astm_msgs)
                self.print_messages(astm_msgs, src_mac)
                return
            
            crid_msgs = self.find_crid_in_frame(raw)
            if crid_msgs:
                self.stats['crid'] += 1
                self.update_drone(src_mac, crid_msgs)
                self.print_messages(crid_msgs, src_mac)
                return
        
        if time.time() - self.last_update >= 10:
            print(f"\n📊 [Stat] Total:{self.stats['total']}, ASTM:{self.stats['astm']}, CRID:{self.stats['crid']}, Drones:{len(self.known_drones)}")
            self.last_update = time.time()

def main():
    if len(sys.argv) < 2:
        print("Usage: sudo python3 remoteid_sniffer_with_system.py <interface>")
        print("Example: sudo python3 remoteid_sniffer_with_system.py wlan1")
        print("\nSetup monitor mode on 5.8GHz:")
        print("  sudo ip link set wlan1 down")
        print("  sudo iw wlan1 set type monitor")
        print("  sudo ip link set wlan1 up")
        print("  sudo iw wlan1 set freq 5785")
        sys.exit(1)

    iface = sys.argv[1]
    print(f"🚀 Remote ID Sniffer (With System Messages)")
    print(f"📡 Interface: {iface}")
    print(f"✅ Supports: Basic ID / Location / System")
    print(f"📝 PCAP recording enabled")
    print(f"🛑 Press Ctrl+C to stop\n")

    receiver = RemoteIDReceiver()
    try:
        sniff(iface=iface, prn=receiver.packet_handler, store=0,
              filter="type mgt subtype beacon")
    except KeyboardInterrupt:
        print("\n🛑 Stopping...")

        receiver.pcap_running = False
        receiver.pcap_queue.put(None)
        if receiver.pcap_thread and receiver.pcap_thread.is_alive():
            receiver.pcap_thread.join(timeout=3)
        
        with receiver.pcap_lock:
            if receiver.pcap_writer:
                receiver.pcap_writer.close()
                print("✅ PCAP file saved")

        print(f"\n📊 Final Stats:")
        print(f"  Total Packets: {receiver.stats['total']}")
        print(f"  ASTM: {receiver.stats['astm']}")
        print(f"  China C-RID: {receiver.stats['crid']}")
        print(f"  Unique Drones: {len(receiver.known_drones)}")

if __name__ == "__main__":
    main()
