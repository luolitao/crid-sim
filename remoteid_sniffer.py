#!/usr/bin/env python3
# remoteid_sniffer.py - Full ASTM F3411-22a / OpenDroneID Binary Parser

from scapy.all import *
import time
import sys
import struct
import math

# --- 配置 ---
PCAP_FILE = "remoteid_capture.pcap"
INTERFACE = sys.argv[1] if len(sys.argv) > 1 else "wlan1"

# OpenDroneID OUIs (IEEE-assigned)
OPEN_DRONE_ID_OUI = b'\x00\x12\x17'  # Official OpenDroneID OUI
# Some vendors may use others; you can add more if needed

writer = PcapWriter(PCAP_FILE, append=True, sync=True)

# Message Types (from OpenDroneID spec)
MSG_TYPES = {
    0: "Basic ID",
    1: "Location",
    2: "Authentication",
    3: "Self-ID",
    4: "System",
    5: "Operator ID",
    6: "Message Pack",  # Contains multiple messages
}

def decode_basic_id(payload, out):
    """Message Type 0"""
    if len(payload) < 21: return
    uatype = payload[0] >> 4
    idtype = payload[0] & 0x0F
    uas_id = payload[1:21].rstrip(b'\x00')
    
    ua_types = {0: "None", 1: "Aeroplane", 2: "HeliOrMulti", 3: "Gyroplane", 4: "VTOL", 5: "Ornithopter",
                6: "Glider", 7: "Kite", 8: "FreeBalloon", 9: "CaptiveBalloon", 10: "Airship", 11: "FreeFallOrParachute",
                12: "Rocket", 13: "TetheredPowered", 14: "GroundObstacle", 15: "Other"}
    id_types = {0: "None", 1: "SerialNumber", 2: "CAAReg", 3: "UTM ID", 4: "MAC Address", 5: "Other"}
    
    out["UAS Type"] = ua_types.get(uatype, f"Reserved ({uatype})")
    out["ID Type"] = id_types.get(idtype, f"Reserved ({idtype})")
    try:
        out["UAS ID"] = uas_id.decode('utf-8').strip()
    except:
        out["UAS ID (hex)"] = uas_id.hex()

def decode_location(payload, out):
    """Message Type 1"""
    if len(payload) < 25: return
    status = payload[0] >> 4
    flags = payload[0] & 0x0F
    direction = payload[1]
    speed_h = payload[2]
    speed_v = payload[3]
    lat = struct.unpack('>i', b'\x00' + payload[4:7])[0] / 10000000.0
    lon = struct.unpack('>i', b'\x00' + payload[7:10])[0] / 10000000.0
    alt_geom = struct.unpack('<H', payload[10:12])[0] * 0.5 - 1000.0  # Geometric altitude (m)
    alt_pres = struct.unpack('<H', payload[12:14])[0] * 0.5 - 1000.0  # Pressure altitude (m)
    vvel = (payload[14] - 128) * 0.5  # Vertical velocity (m/s)
    hacc = payload[15] * 10.0  # Horizontal accuracy (m)
    vac = payload[16] * 10.0   # Vertical accuracy (m)
    hdg_acc = payload[17] * 10.0  # Horizontal velocity accuracy (m/s)
    vvel_acc = payload[18] * 10.0 # Vertical velocity accuracy (m/s)

    status_map = {0: "Undeclared", 1: "Ground", 2: "Airborne", 3: "Emergency", 4: "Remote ID System Failure"}
    out["Status"] = status_map.get(status, f"Reserved ({status})")
    out["Direction (deg)"] = (direction * 360) / 255 if direction != 255 else "Unknown"
    out["Speed Horizontal (m/s)"] = speed_h * 0.25 if speed_h != 255 else "Unknown"
    out["Speed Vertical (m/s)"] = vvel if payload[14] != 255 else "Unknown"
    out["Latitude"] = lat if lat != 90.0 and lat != -90.0 else "Unknown"
    out["Longitude"] = lon if lon != 180.0 and lon != -180.0 else "Unknown"
    out["Geometric Altitude (m)"] = alt_geom if alt_geom != -1000.0 else "Unknown"
    out["Pressure Altitude (m)"] = alt_pres if alt_pres != -1000.0 else "Unknown"
    out["Horiz Accuracy (m)"] = hacc if payload[15] != 255 else "Unknown"
    out["Vert Accuracy (m)"] = vac if payload[16] != 255 else "Unknown"

def decode_self_id(payload, out):
    """Message Type 3"""
    if len(payload) < 22: return
    desc_type = payload[0]
    text = payload[1:22].rstrip(b'\x00')
    desc_types = {0: "Text", 1: "Emergency", 2: "Extended Status"}
    out["Self-ID Type"] = desc_types.get(desc_type, f"Reserved ({desc_type})")
    try:
        out["Self-ID Description"] = text.decode('utf-8').strip()
    except:
        out["Self-ID Description (hex)"] = text.hex()

def decode_system(payload, out):
    """Message Type 4"""
    if len(payload) < 22: return
    operator_location_type = payload[0] >> 4
    classification_type = payload[0] & 0x0F
    area_count = payload[1]
    area_radius = payload[2] * 10  # meters
    area_ceiling = struct.unpack('<H', payload[3:5])[0] * 10 - 1000  # meters
    area_floor = struct.unpack('<H', payload[5:7])[0] * 10 - 1000    # meters
    category_eu = payload[7] >> 2
    class_eu = payload[7] & 0x03
    operator_altitude_geo = struct.unpack('<H', payload[8:10])[0] * 0.5 - 1000  # m
    timestamp = struct.unpack('<H', payload[10:12])[0]

    op_loc_types = {0: "Takeoff", 1: "LiveGNSS", 2: "Fixed", 3: "Operator"}
    class_types = {0: "Undeclared", 1: "EU Class 0", 2: "EU Class 1", 3: "EU Class 2",
                   4: "EU Class 3", 5: "EU Class 4", 6: "EU Class 5", 7: "EU Class 6",
                   8: "Other"}
    out["Operator Location Type"] = op_loc_types.get(operator_location_type, f"Reserved ({operator_location_type})")
    out["Classification Type"] = class_types.get(classification_type, f"Reserved ({classification_type})")
    out["Operator Geo Altitude (m)"] = operator_altitude_geo if operator_altitude_geo != -1000 else "Unknown"
    # Timestamp: 0-65535 = seconds since UTC midnight
    if timestamp != 0xFFFF:
        out["Time of Applicability (UTC seconds)"] = timestamp
        hours = timestamp // 3600
        mins = (timestamp % 3600) // 60
        secs = timestamp % 60
        out["Time (HH:MM:SS)"] = f"{hours:02d}:{mins:02d}:{secs:02d}"

def decode_operator_id(payload, out):
    """Message Type 5"""
    if len(payload) < 21: return
    op_id_type = payload[0]
    op_id = payload[1:21].rstrip(b'\x00')
    op_types = {0: "CAA", 1: "UTM", 2: "Serial Number", 3: "Reserved", 4: "MAC Address", 5: "Other"}
    out["Operator ID Type"] = op_types.get(op_id_type, f"Reserved ({op_id_type})")
    try:
        out["Operator ID"] = op_id.decode('utf-8').strip()
    except:
        out["Operator ID (hex)"] = op_id.hex()

def parse_opendroneid_message(msg_type, data):
    """解析单条 OpenDroneID 消息"""
    out = {"Message Type": MSG_TYPES.get(msg_type, f"Unknown ({msg_type})")}
    if msg_type == 0:
        decode_basic_id(data, out)
    elif msg_type == 1:
        decode_location(data, out)
    elif msg_type == 3:
        decode_self_id(data, out)
    elif msg_type == 4:
        decode_system(data, out)
    elif msg_type == 5:
        decode_operator_id(data, out)
    elif msg_type == 2:
        out["Note"] = "Authentication message (not parsed)"
    elif msg_type == 6:
        out["Note"] = "Message Pack - contains multiple messages (recursive parsing needed)"
        # 高级功能：递归解析 Message Pack
        out["Raw Payload"] = data.hex()
    else:
        out["Raw Payload"] = data.hex()
    return out

def parse_opendroneid_binary(payload):
    """解析整个 OpenDroneID 二进制载荷（可能含多条消息）"""
    results = []
    offset = 0
    while offset + 25 <= len(payload):
        msg_type = payload[offset]
        # 第二个字节：protocol version (should be 0xFD for OpenDroneID)
        proto_ver = payload[offset + 1]
        if proto_ver != 0xFD:
            # 可能不是标准 OpenDroneID
            break
        msg_data = payload[offset + 2:offset + 25]
        results.append(parse_opendroneid_binary_message(msg_type, msg_data))
        offset += 25
    return results

def parse_opendroneid_binary_message(msg_type, data):
    return parse_opendroneid_message(msg_type, data)

def is_remoteid_beacon(pkt):
    if not pkt.haslayer(Dot11Beacon):
        return False, None
    elt = pkt.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 221 and len(elt.info) >= 3:
            oui = elt.info[:3]
            if oui == OPEN_DRONE_ID_OUI:
                return True, elt.info[3:]
        elt = elt.payload
    return False, None

def packet_handler(pkt):
    is_rid, payload = is_remoteid_beacon(pkt)
    if is_rid:
        print(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] 🛰️ Remote ID Beacon (OpenDroneID) Detected!")
        writer.write(pkt)

        # 尝试解析为 OpenDroneID 二进制消息
        if len(payload) >= 25 and payload[1] == 0xFD:  # Check protocol version
            messages = []
            offset = 0
            while offset + 25 <= len(payload):
                msg_type = payload[offset]
                proto_ver = payload[offset + 1]
                if proto_ver != 0xFD:
                    break
                msg_data = payload[offset + 2:offset + 25]
                msg_parsed = parse_opendroneid_message(msg_type, msg_data)
                messages.append(msg_parsed)
                offset += 25

            for i, msg in enumerate(messages):
                print(f"\n--- Message {i+1}: {msg['Message Type']} ---")
                for k, v in msg.items():
                    if k != "Message Type":
                        print(f"  {k}: {v}")
        else:
            # Fallback to raw hex or JSON
            try:
                text = payload.decode('utf-8')
                if text.startswith('{'):
                    import json
                    print(json.dumps(json.loads(text), indent=2))
                else:
                    print(f"[!] Non-binary payload: {text}")
            except:
                print(f"[!] Unknown payload (hex): {payload.hex()}")

def main():
    print(f"[*] Sniffing Remote ID on {INTERFACE} (monitor mode, 5.8GHz)")
    print("[*] OpenDroneID OUI: 00-12-17")
    print("[*] Press Ctrl+C to stop.")
    try:
        sniff(iface=INTERFACE, prn=packet_handler, store=0)
    except KeyboardInterrupt:
        print("\n[!] Stopped.")
    finally:
        writer.close()
        print(f"[+] Saved to {PCAP_FILE}")

if __name__ == "__main__":
    main()