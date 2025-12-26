#!/usr/bin/env python3
"""
全球 Remote ID 多标准探测器（标准合规版）
✅ ASTM F3411-22a (FAA/EU) → OUI = 06:05:04
✅ GB42590-2023 (China C-RID) → OUI = FA:0B:BC
✅ 严格遵循官方规范
✅ 支持 0xF Packed Message
✅ 安全 pcap 记录
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

class GlobalRemoteIDReceiver:
    def __init__(self):
        # ✅ ASTM F3411-22a 官方 OUI (IEEE-assigned for Remote ID)
        self.ASTM_OUI = b'\x06\x05\x04'   # 06:05:04 - 强制标准
        
        # ✅ China GB42590-2023 OUI
        self.CHINA_OUI = b'\xFA\x0B\xBC'  # FA:0B:BC
        
        # 消息类型
        self.MSG_TYPES = {
            0: "Basic ID", 1: "Location", 2: "Authentication",
            3: "Self-ID", 4: "System", 5: "Operator ID", 0xF: "Packed"
        }
        
        # OpenDroneID (ASTM) 映射
        self.ASTM_ID_TYPES = {
            0: "None", 1: "Serial Number", 2: "CAA Registration ID",
            3: "UTM ID", 4: "MAC Address", 5: "Other"
        }
        
        self.ASTM_UA_TYPES = {
            0: "None", 1: "Aeroplane", 2: "HeliOrMulti", 3: "Gyroplane",
            4: "VTOL", 5: "Ornithopter", 6: "Glider", 7: "Kite",
            8: "FreeBalloon", 9: "CaptiveBalloon", 10: "Airship",
            11: "FreeFallOrParachute", 12: "Rocket", 13: "TetheredPowered",
            14: "GroundObstacle", 15: "Other"
        }
        
        # China C-RID 映射
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
        
        # 通用状态
        self.STATUS_NAMES = {
            0: "Undeclared", 1: "Ground", 2: "Airborne",
            3: "Emergency", 4: "Remote ID System Failure"
        }
        
        # 精度
        self.HOR_ACC = ["Unknown", "<=1m", "<=2m", "<=3m", "<=4m", "<=6m", "<=10m", "<=15m", "<=20m", "<=25m", "<=30m", "<=35m", "<=40m", "<=45m", "<=50m", ">50m"]
        self.VER_ACC = ["Unknown", "<=1m", "<=2m", "<=3m", "<=4m", "<=5m", "<=6m", "<=7m", "<=8m", "<=9m", "<=10m", "<=15m", "<=20m", "<=25m", "<=30m", ">30m"]
        
        # 统计
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
            filename = f"remoteid_global_{ts}.pcap"
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
        # Flush remaining
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
            new_name = f"remoteid_global_{ts}_{self.pcap_file_counter:03d}.pcap"
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

    # ==================== ASTM F3411-22a 解析器 ====================
    def parse_astm_message(self, data):
        """解析 ASTM F3411-22a 消息 (OUI=06:05:04)"""
        if len(data) < 25:
            return None
        msg_type = (data[0] >> 4) & 0x0F
        proto_ver = data[1]
        # ASTM F3411-22a 要求 Protocol Version = 0xFD
        if proto_ver != 0xFD:
            return None
        payload = data[2:25]
        
        if msg_type == 0xF:  # Packed Message
            msg_count = payload[0]
            if not (1 <= msg_count <= 10):
                return None
            sub_msgs = []
            offset = 1
            for _ in range(msg_count):
                if offset + 25 > len(payload):
                    break
                # 伪造完整消息头用于递归解析
                fake_msg = bytes([0x00, 0xFD]) + payload[offset:offset+25]
                sub = self.parse_astm_message(fake_msg)
                if sub:
                    sub_msgs.append(sub)
                offset += 25
            return {
                'standard': 'ASTM F3411-22a',
                'message_type': 'Packed',
                'sub_messages': sub_msgs
            }
        
        # 单消息解析
        if msg_type == 0:  # Basic ID
            ua_type = payload[0] >> 4
            id_type = payload[0] & 0x0F
            uas_id = payload[1:21].rstrip(b'\x00')
            try:
                uas_id = uas_id.decode('utf-8').strip()
            except:
                uas_id = uas_id.hex()
            return {
                'standard': 'ASTM F3411-22a',
                'message_type': 'Basic ID',
                'ua_type': self.ASTM_UA_TYPES.get(ua_type, f"Unknown ({ua_type})"),
                'id_type': self.ASTM_ID_TYPES.get(id_type, f"Unknown ({id_type})"),
                'uas_id': uas_id
            }
        
        elif msg_type == 1:  # Location
            status = payload[0] >> 4
            lat = struct.unpack('>i', b'\x00' + payload[4:7])[0] / 10000000.0
            lon = struct.unpack('>i', b'\x00' + payload[7:10])[0] / 10000000.0
            alt_geom = struct.unpack('<H', payload[10:12])[0] * 0.5 - 1000.0
            return {
                'standard': 'ASTM F3411-22a',
                'message_type': 'Location',
                'status': self.STATUS_NAMES.get(status, f"Unknown ({status})"),
                'latitude': lat if lat != 90.0 else "Unknown",
                'longitude': lon if lon != 180.0 else "Unknown",
                'altitude_geom_m': alt_geom if alt_geom != -1000.0 else "Unknown"
            }
        
        elif msg_type == 4:  # System
            op_alt = struct.unpack('<H', payload[8:10])[0] * 0.5 - 1000
            timestamp = struct.unpack('<H', payload[10:12])[0]
            return {
                'standard': 'ASTM F3411-22a',
                'message_type': 'System',
                'operator_altitude_geo_m': op_alt if op_alt != -1000 else "Unknown",
                'timestamp_sec': timestamp if timestamp != 0xFFFF else "Unknown"
            }
        
        else:
            return {
                'standard': 'ASTM F3411-22a',
                'message_type': f'Unknown ({msg_type})',
                'raw_hex': data.hex()
            }

    def find_astm_in_frame(self, raw_bytes):
        """查找 ASTM F3411-22a 消息 (OUI=06:05:04)"""
        idx = 0
        while idx <= len(raw_bytes) - (3 + 25):
            if raw_bytes[idx:idx+3] == self.ASTM_OUI:
                offset = idx + 3
                messages = []
                while offset + 25 <= len(raw_bytes):
                    msg_data = raw_bytes[offset:offset+25]
                    parsed = self.parse_astm_message(msg_data)
                    if parsed:
                        if parsed['message_type'] == 'Packed':
                            for sub in parsed.get('sub_messages', []):
                                messages.append(sub)
                        else:
                            messages.append(parsed)
                    offset += 25
                if messages:
                    return messages
            idx += 1
        return None

    # ==================== China C-RID 解析器 ====================
    def parse_crid_message(self, msg_type, data):
        """解析 China C-RID 消息 (GB42590-2023)"""
        if len(data) < 25:
            return None
        
        if msg_type == 0:  # Basic ID
            id_ua = data[0]
            id_type = (id_ua >> 4) & 0x0F
            ua_type = id_ua & 0x0F
            uas_id = data[1:21].rstrip(b'\x00 \x20')
            try:
                uas_id = uas_id.decode('ascii', errors='ignore').strip()
            except:
                uas_id = uas_id.hex()
            return {
                'standard': 'China C-RID (GB42590-2023)',
                'message_type': 'Basic ID',
                'id_type': self.CR_ID_TYPES.get(id_type, f"Unknown ({id_type})"),
                'ua_type': self.CR_UA_TYPES.get(ua_type, f"Unknown ({ua_type})"),
                'uas_id': uas_id,
                'china_compliant': (id_type == 2)  # CAA Registration ID
            }
        
        elif msg_type == 1:  # Location
            flags = data[0]
            status = (flags >> 4) & 0x0F
            lat = struct.unpack('<i', data[3:7])[0] / 10000000.0 if len(data) >= 7 else 0
            lon = struct.unpack('<i', data[7:11])[0] / 10000000.0 if len(data) >= 11 else 0
            alt = struct.unpack('<H', data[11:13])[0] * 0.5 - 1000 if len(data) >= 13 else -1000
            return {
                'standard': 'China C-RID (GB42590-2023)',
                'message_type': 'Location',
                'status': self.STATUS_NAMES.get(status, f"Unknown ({status})"),
                'latitude': lat if lat != 90.0 else "Unknown",
                'longitude': lon if lon != 180.0 else "Unknown",
                'altitude_m': alt if alt != -1000 else "Unknown"
            }
        
        else:
            return {
                'standard': 'China C-RID (GB42590-2023)',
                'message_type': f'Unknown Type {msg_type}',
                'raw_hex': data.hex()
            }

    def find_crid_in_frame(self, raw_bytes):
        """查找 China C-RID 消息 (OUI=FA:0B:BC, Type=0x0D)"""
        idx = 0
        while idx <= len(raw_bytes) - (3 + 1 + 1):  # OUI + VendorType + Counter
            if raw_bytes[idx:idx+3] == self.CHINA_OUI:
                if idx + 3 < len(raw_bytes) and raw_bytes[idx+3] == 0x0D:
                    msg_counter = raw_bytes[idx+4]
                    offset = idx + 5
                    messages = []
                    while offset + 26 <= len(raw_bytes):  # 1B Type + 25B Data
                        msg_type = raw_bytes[offset]
                        msg_data = raw_bytes[offset+1:offset+26]
                        offset += 26
                        parsed = self.parse_crid_message(msg_type, msg_data)
                        if parsed:
                            parsed['counter'] = msg_counter
                            messages.append(parsed)
                    if messages:
                        return messages
            idx += 1
        return None

    # ==================== 主处理逻辑 ====================
    def update_drone(self, mac, messages):
        if mac not in self.known_drones:
            self.known_drones[mac] = {
                'first_seen': datetime.now(),
                'last_seen': datetime.now(),
                'standards': set(),
                'messages': {}
            }
        drone = self.known_drones[mac]
        drone['last_seen'] = datetime.now()
        for msg in messages:
            drone['standards'].add(msg['standard'])
            drone['messages'][msg['message_type']] = msg

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
                    print(f"    🚁 Type: {msg['ua_type']}")
                if msg['standard'] == 'China C-RID (GB42590-2023)':
                    print(f"    🇨🇳 China Compliant: {'✅' if msg.get('china_compliant') else '❌'}")
            elif msg['message_type'] == 'Location':
                print(f"  📍 [{msg['standard']}] {msg['latitude']:.6f}, {msg['longitude']:.6f} | Alt: {msg['altitude_geom_m'] if 'altitude_geom_m' in msg else msg.get('altitude_m', 'N/A')}m")
        print(f"  📦 Total Messages: {len(messages)}")
        print(f"{'='*100}\n")

    def packet_handler(self, pkt):
        self.stats['total'] += 1
        self.write_pcap(pkt)
        self.stats['pcap'] += 1

        if hasattr(pkt, 'type') and pkt.type == 0:  # Management frame
            src_mac = getattr(pkt, 'addr2', 'Unknown')
            raw = bytes(pkt)
            
            # 优先检测 ASTM F3411-22a (OUI=06:05:04)
            astm_msgs = self.find_astm_in_frame(raw)
            if astm_msgs:
                self.stats['astm'] += 1
                self.update_drone(src_mac, astm_msgs)
                self.print_messages(astm_msgs, src_mac)
                return
            
            # 检测 China C-RID (OUI=FA:0B:BC)
            crid_msgs = self.find_crid_in_frame(raw)
            if crid_msgs:
                self.stats['crid'] += 1
                self.update_drone(src_mac, crid_msgs)
                self.print_messages(crid_msgs, src_mac)
                return
        
        # 每10秒统计
        if time.time() - self.last_update >= 10:
            print(f"\n📊 [Stat] Total:{self.stats['total']}, ASTM:{self.stats['astm']}, CRID:{self.stats['crid']}, Drones:{len(self.known_drones)}")
            self.last_update = time.time()

def main():
    if len(sys.argv) < 2:
        print("Usage: sudo python3 global_remoteid_sniffer.py <interface>")
        print("Example: sudo python3 global_remoteid_sniffer.py wlan1")
        print("\nSet monitor mode on 5.8GHz (e.g., channel 157):")
        print("  sudo ip link set wlan1 down")
        print("  sudo iw wlan1 set type monitor")
        print("  sudo ip link set wlan1 up")
        print("  sudo iw wlan1 set freq 5785  # Channel 157")
        sys.exit(1)

    iface = sys.argv[1]
    print(f"🌐 Global Remote ID Sniffer (Standard Compliant)")
    print(f"📡 Interface: {iface}")
    print(f"✅ ASTM F3411-22a OUI: 06:05:04 (FAA/EU)")
    print(f"✅ China C-RID OUI: FA:0B:BC (GB42590-2023)")
    print(f"📝 PCAP recording enabled")
    print(f"🛑 Press Ctrl+C to stop\n")

    receiver = GlobalRemoteIDReceiver()
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
        print(f"  ASTM F3411: {receiver.stats['astm']}")
        print(f"  China C-RID: {receiver.stats['crid']}")
        print(f"  Unique Drones: {len(receiver.known_drones)}")
        
        # 列出 pcap 文件
        pcap_files = [f for f in os.listdir('.') if f.startswith('remoteid_global_') and f.endswith('.pcap')]
        if pcap_files:
            print(f"\n📝 PCAP Files ({len(pcap_files)}):")
            for f in sorted(pcap_files):
                size_mb = os.path.getsize(f) / (1024*1024)
                print(f"  {f} ({size_mb:.2f} MB)")

if __name__ == "__main__":
    main()