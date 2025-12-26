#!/usr/bin/env python3
"""
Remote ID 探测器（单文件修复版）
✅ 解决 database is locked 问题（WAL + 重试机制）
✅ 实时地图 + 轨迹回放
✅ 警报通知 + CSV 导出
✅ 适合树莓派长时间运行
"""

import sys
import struct
import time
import os
import json
import csv
import sqlite3
import threading
import queue
import random
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from collections import defaultdict
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Elt

# Web 相关
from flask import Flask, render_template, jsonify, request, send_file
from flask_cors import CORS

# 全局配置
CONFIG_FILE = "config.json"
DB_FILE = "remoteid.db"
EXPORT_DIR = "exports"
os.makedirs(EXPORT_DIR, exist_ok=True)

# 加载配置
def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    return {
        "alerts": {
            "enable": True,
            "email": {"enable": False},
            "local_alert": {"enable": True, "sound": True, "desktop_notification": True},
            "rules": {"non_compliant": True, "emergency": True, "unknown_region": True}
        }
    }

CONFIG = load_config()

# 全局变量
DATA_QUEUE = queue.Queue()
DRONE_DATA = {}
ALERT_HISTORY = set()

# ==================== 安全数据库操作 ====================
def safe_db_execute(query, params=(), fetch=False, max_retries=5):
    """安全执行数据库操作（带 WAL + 重试）"""
    for attempt in range(max_retries):
        conn = None
        try:
            # 关键：启用 WAL 模式 + 10秒超时
            conn = sqlite3.connect(DB_FILE, timeout=10.0, isolation_level=None)
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            c = conn.cursor()
            
            c.execute(query, params)
            if fetch:
                result = c.fetchall()
                conn.close()
                return result
            else:
                conn.commit()
                conn.close()
                return True
                
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e) and attempt < max_retries - 1:
                # 随机退避（0.01-0.1秒）
                time.sleep(random.uniform(0.01, 0.1))
                continue
            else:
                if conn:
                    conn.close()
                raise
        except Exception as e:
            if conn:
                conn.close()
            raise

# ==================== 数据库初始化 ====================
def init_db():
    # 首次连接时启用 WAL
    conn = sqlite3.connect(DB_FILE, timeout=10.0)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    c = conn.cursor()
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS drones (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT NOT NULL UNIQUE,
            first_seen TEXT,
            last_seen TEXT,
            uas_id TEXT,
            ua_type TEXT,
            latitude REAL,
            longitude REAL,
            altitude REAL,
            operator_lat REAL,
            operator_lon REAL,
            region TEXT,
            china_compliant INTEGER,
            raw_data TEXT
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS positions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT NOT NULL,
            timestamp TEXT,
            latitude REAL,
            longitude REAL,
            altitude REAL,
            speed REAL,
            direction REAL
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT,
            alert_type TEXT,
            message TEXT,
            timestamp TEXT
        )
    ''')
    
    conn.commit()
    conn.close()

# ==================== 警报系统 ====================
def trigger_alert(mac, alert_type, message):
    if (mac, alert_type) in ALERT_HISTORY:
        return
    
    ALERT_HISTORY.add((mac, alert_type))
    
    # 安全写入警报
    try:
        safe_db_execute(
            'INSERT INTO alerts (mac, alert_type, message, timestamp) VALUES (?, ?, ?, ?)',
            (mac, alert_type, message, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        )
    except Exception as e:
        print(f"❌ Alert DB Error: {e}")
    
    print(f"🚨 ALERT [{alert_type}] {message}")
    
    # 本地警报
    if CONFIG['alerts']['local_alert']['enable']:
        if CONFIG['alerts']['local_alert']['sound']:
            os.system("aplay /usr/share/sounds/alsa/Front_Center.wav >/dev/null 2>&1 &")
        if CONFIG['alerts']['local_alert']['desktop_notification']:
            os.system(f'notify-send "Remote ID Alert" "{message}" >/dev/null 2>&1 &')

# ==================== 数据处理 ====================
def process_drone_data(mac, messages):
    if not CONFIG['alerts']['enable']:
        return
        
    basic = messages.get('Basic ID', {})
    location = messages.get('Location', {})
    
    # 非合规无人机
    if CONFIG['alerts']['rules']['non_compliant'] and not basic.get('china_compliant', True):
        trigger_alert(mac, "NON_COMPLIANT", f"Non-compliant drone: {basic.get('uas_id', mac)}")
    
    # 紧急状态
    if CONFIG['alerts']['rules']['emergency'] and location.get('status') == "Emergency":
        trigger_alert(mac, "EMERGENCY", f"Emergency status: {basic.get('uas_id', mac)}")

def save_position_history(mac, location_data):
    if location_data.get('latitude') is not None and location_data.get('longitude') is not None:
        try:
            safe_db_execute('''
                INSERT INTO positions (mac, timestamp, latitude, longitude, altitude, speed, direction)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                mac,
                datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                location_data['latitude'],
                location_data['longitude'],
                location_data.get('altitude_m'),
                location_data.get('speed_horizontal_m_s'),
                location_data.get('direction_deg')
            ))
        except Exception as e:
            print(f"❌ Position DB Error: {e}")

# ==================== 数据库写入线程 ====================
def db_writer():
    while True:
        try:
            data = DATA_QUEUE.get(timeout=1)
            if data is None:
                break
            
            mac = data['mac']
            messages = data['messages']
            basic = messages.get('Basic ID', {})
            location = messages.get('Location', {})
            system = messages.get('System', {})
            
            # 安全写入主数据
            try:
                safe_db_execute('''
                    INSERT OR REPLACE INTO drones 
                    (mac, first_seen, last_seen, uas_id, ua_type, latitude, longitude, altitude, 
                     operator_lat, operator_lon, region, china_compliant, raw_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    mac,
                    data['first_seen'].strftime('%Y-%m-%d %H:%M:%S'),
                    data['last_seen'].strftime('%Y-%m-%d %H:%M:%S'),
                    basic.get('uas_id', ''),
                    basic.get('ua_type', ''),
                    location.get('latitude'),
                    location.get('longitude'),
                    location.get('altitude_m'),
                    system.get('operator_latitude'),
                    system.get('operator_longitude'),
                    system.get('classification_region', ''),
                    1 if basic.get('china_compliant', False) else 0,
                    json.dumps(messages)
                ))
            except Exception as e:
                print(f"❌ Drone DB Error: {e}")
            
            # 保存位置历史
            if 'Location' in messages:
                save_position_history(mac, messages['Location'])
            
            # 警报检查
            process_drone_data(mac, messages)
            
            DATA_QUEUE.task_done()
            
        except queue.Empty:
            continue
        except Exception as e:
            print(f"❌ DB Writer Error: {e}")

# ==================== Web 服务器 ====================
app = Flask(__name__)
CORS(app)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/drones')
def get_drones():
    try:
        now = time.time()
        active_drones = {}
        for mac, info in DRONE_DATA.items():
            if now - info['last_seen'].timestamp() < 300:
                active_drones[mac] = {
                    'mac': mac,
                    'last_seen': info['last_seen'].strftime('%Y-%m-%d %H:%M:%S'),
                    'messages': info['messages']
                }
        return jsonify(active_drones)
    except Exception as e:
        print(f"❌ Drones API Error: {e}")
        return jsonify({})

@app.route('/api/trajectory/<mac>')
def get_trajectory(mac):
    try:
        since = (datetime.now() - timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S')
        rows = safe_db_execute('''
            SELECT timestamp, latitude, longitude, altitude, speed, direction
            FROM positions 
            WHERE mac = ? AND timestamp > ?
            ORDER BY timestamp
        ''', (mac, since), fetch=True)
        
        trajectory = []
        for row in rows:
            trajectory.append({
                'timestamp': row[0],
                'latitude': row[1],
                'longitude': row[2],
                'altitude': row[3],
                'speed': row[4],
                'direction': row[5]
            })
        return jsonify(trajectory)
    except Exception as e:
        print(f"❌ Trajectory API Error: {e}")
        return jsonify([])

@app.route('/api/export/csv')
def export_csv():
    try:
        mac = request.args.get('mac')
        hours = int(request.args.get('hours', 24))
        filename = f"export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        filepath = os.path.join(EXPORT_DIR, filename)
        
        since = (datetime.now() - timedelta(hours=hours)).strftime('%Y-%m-%d %H:%M:%S')
        
        if mac:
            rows = safe_db_execute('''
                SELECT d.mac, d.uas_id, d.ua_type, p.timestamp, p.latitude, p.longitude, p.altitude, p.speed
                FROM drones d
                JOIN positions p ON d.mac = p.mac
                WHERE d.mac = ? AND p.timestamp > ?
                ORDER BY p.timestamp
            ''', (mac, since), fetch=True)
        else:
            rows = safe_db_execute('''
                SELECT d.mac, d.uas_id, d.ua_type, p.timestamp, p.latitude, p.longitude, p.altitude, p.speed
                FROM drones d
                JOIN positions p ON d.mac = p.mac
                WHERE p.timestamp > ?
                ORDER BY p.timestamp
            ''', (since,), fetch=True)
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['MAC', 'UAS ID', 'UA Type', 'Timestamp', 'Latitude', 'Longitude', 'Altitude (m)', 'Speed (m/s)'])
            for row in rows:
                writer.writerow(row)
        
        return send_file(filepath, as_attachment=True)
    except Exception as e:
        print(f"❌ Export API Error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/alerts')
def get_alerts():
    try:
        rows = safe_db_execute('''
            SELECT alert_type, message, timestamp 
            FROM alerts 
            ORDER BY timestamp DESC 
            LIMIT 20
        ''', fetch=True)
        
        alerts = []
        for row in rows:
            alerts.append({
                'type': row[0],
                'message': row[1],
                'timestamp': row[2]
            })
        return jsonify(alerts)
    except Exception as e:
        print(f"❌ Alerts API Error: {e}")
        return jsonify([])

# ==================== Remote ID 接收器 ====================
class RemoteIDReceiver:
    def __init__(self):
        self.CHINA_OUI = b'\xFA\x0B\xBC'
        self.CR_ID_TYPES = {0: "None", 1: "Serial Number", 2: "CAA Registration ID", 3: "UTM Assigned UUID", 4: "Specific Session ID"}
        self.CR_UA_TYPES = {0: "None/Not declared", 1: "Aeroplane/Fixed wing", 2: "Helicopter/Multirotor", 3: "Gyroplane", 4: "Hybrid Lift", 5: "Ornithopter", 6: "Glider", 7: "Kite", 8: "Free Balloon", 9: "Captive Balloon", 10: "Airship", 11: "Free Fall/Parachute", 12: "Rocket", 13: "Tethered Powered", 14: "Ground Obstacle", 15: "Other"}
        self.STATUS_NAMES = {0: "Undeclared", 1: "Ground", 2: "Airborne", 3: "Emergency", 4: "Remote ID System Failure"}
        self.CLASS_REGION = {0: "Undeclared", 1: "EU", 2: "China", 3: "USA", 4: "Other"}
        self.stats = defaultdict(int)

    def parse_crid_packed_basic_id(self, data):
        if len(data) < 25: return None
        id_ua_byte = data[1]
        id_type = (id_ua_byte >> 4) & 0x0F
        ua_type = id_ua_byte & 0x0F
        uas_id_bytes = data[2:22]
        try: uas_id = uas_id_bytes.decode('ascii').rstrip('\x00 \x20')
        except: uas_id = uas_id_bytes.hex()
        return {
            'message_type': 'Basic ID',
            'id_type': self.CR_ID_TYPES.get(id_type, f"Unknown ({id_type})"),
            'ua_type': self.CR_UA_TYPES.get(ua_type, f"Unknown ({ua_type})"),
            'uas_id': uas_id,
            'china_compliant': (id_type == 2)
        }

    def parse_crid_packed_location(self, data):
        if len(data) < 25: return None
        flags = data[1]
        status = (flags >> 4) & 0x0F
        lat_raw = struct.unpack('<i', data[5:9])[0]
        lat = lat_raw / 10000000.0 if lat_raw != 0x7FFFFFFF else None
        lon_raw = struct.unpack('<i', data[9:13])[0]
        lon = lon_raw / 10000000.0 if lon_raw != 0x7FFFFFFF else None
        alt_raw = struct.unpack('<H', data[13:15])[0]
        altitude = alt_raw * 0.5 - 1000.0 if alt_raw != 0xFFFF else None
        speed_h = data[3] * 0.25 if data[3] != 255 else None
        direction_high = flags & 0x0F
        direction_low = data[2]
        direction_raw = (direction_high << 8) | direction_low
        direction = (direction_raw * 360.0) / 65535.0 if direction_raw != 0xFFFF else None
        return {
            'message_type': 'Location',
            'status': self.STATUS_NAMES.get(status, f"Unknown ({status})"),
            'latitude': lat,
            'longitude': lon,
            'altitude_m': altitude,
            'speed_horizontal_m_s': speed_h,
            'direction_deg': direction
        }

    def parse_crid_packed_system(self, data):
        if len(data) < 25: return None
        flags = data[1]
        class_region = (flags >> 4) & 0x07
        try: op_lat = struct.unpack('<d', data[2:10])[0]
        except: op_lat = None
        try: op_lon = struct.unpack('<d', data[10:18])[0]
        except: op_lon = None
        return {
            'message_type': 'System',
            'classification_region': self.CLASS_REGION.get(class_region, f"Unknown ({class_region})"),
            'operator_latitude': op_lat,
            'operator_longitude': op_lon,
            'china_region': (class_region == 2)
        }

    def find_crid_in_frame(self, raw_bytes):
        idx = 0
        while idx <= len(raw_bytes) - 5:
            if raw_bytes[idx:idx+3] == self.CHINA_OUI and raw_bytes[idx+3] == 0x0D:
                payload = raw_bytes[idx+5:]
                messages = []
                if len(payload) >= 3 and (payload[0] >> 4) == 0xF:
                    if payload[1] == 0x19 and 1 <= payload[2] <= 10:
                        offset = 3
                        for _ in range(payload[2]):
                            if offset + 25 > len(payload): break
                            msg_data = payload[offset:offset+25]
                            msg_type = (msg_data[0] >> 4) & 0x0F
                            if msg_type == 0:
                                parsed = self.parse_crid_packed_basic_id(msg_data)
                            elif msg_type == 1:
                                parsed = self.parse_crid_packed_location(msg_data)
                            elif msg_type == 4:
                                parsed = self.parse_crid_packed_system(msg_data)
                            else:
                                parsed = {'message_type': f'Unknown ({msg_type})'}
                            if parsed:
                                messages.append(parsed)
                            offset += 25
                if messages:
                    return messages
            idx += 1
        return None

    def update_drone_data(self, mac, messages):
        global DRONE_DATA
        if mac not in DRONE_DATA:
            DRONE_DATA[mac] = {
                'first_seen': datetime.now(),
                'last_seen': datetime.now(),
                'messages': {}
            }
        drone = DRONE_DATA[mac]
        drone['last_seen'] = datetime.now()
        for msg in messages:
            drone['messages'][msg['message_type']] = msg
        
        DATA_QUEUE.put({
            'mac': mac,
            'first_seen': drone['first_seen'],
            'last_seen': drone['last_seen'],
            'messages': drone['messages']
        })

    def packet_handler(self, pkt):
        if hasattr(pkt, 'type') and pkt.type == 0:
            src_mac = getattr(pkt, 'addr2', 'Unknown')
            raw = bytes(pkt)
            crid_msgs = self.find_crid_in_frame(raw)
            if crid_msgs:
                self.stats['crid'] += 1
                self.update_drone_data(src_mac, crid_msgs)

# ==================== 主程序 ====================
def create_templates():
    """创建 Web 模板（单文件部署）"""
    os.makedirs("templates", exist_ok=True)
    with open("templates/index.html", "w") as f:
        f.write("""<!DOCTYPE html>
<html>
<head>
    <title>Remote ID Monitor Pro</title>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        #map { height: 600px; width: 100%; }
        .info-panel { max-height: 300px; overflow-y: auto; }
        .alert-item { border-left: 4px solid #dc3545; padding-left: 10px; margin: 5px 0; }
        .timeline-control { background: white; padding: 10px; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
    </style>
</head>
<body>
    <div class="container-fluid">
        <h1 class="mt-3">🛰️ Remote ID Monitor Pro</h1>
        
        <div class="row">
            <div class="col-md-8">
                <div id="map"></div>
                
                <div class="timeline-control mt-2">
                    <div class="row">
                        <div class="col-md-6">
                            <label>轨迹回放 (最近1小时)</label>
                            <input type="range" id="timelineSlider" min="0" max="100" value="100" class="form-range">
                        </div>
                        <div class="col-md-6 text-end">
                            <button id="playBtn" class="btn btn-primary btn-sm">▶ 播放</button>
                            <button id="exportBtn" class="btn btn-success btn-sm">📤 导出 CSV</button>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="col-md-4">
                <div class="card">
                    <div class="card-header">
                        <ul class="nav nav-tabs card-header-tabs">
                            <li class="nav-item">
                                <a class="nav-link active" href="#drones-tab">无人机</a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link" href="#alerts-tab">警报</a>
                            </li>
                        </ul>
                    </div>
                    <div class="card-body info-panel">
                        <div id="dronesList"></div>
                        <div id="alertsList" style="display:none;"></div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        const map = L.map('map').setView([23.14287, 113.26026], 12);
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
        }).addTo(map);

        let droneMarkers = {};
        let droneTrajectories = {};
        let selectedDrone = null;
        let isPlaying = false;
        let playInterval = null;

        document.querySelectorAll('.nav-link').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
                link.classList.add('active');
                document.getElementById('dronesList').style.display = link.textContent.includes('无人机') ? 'block' : 'none';
                document.getElementById('alertsList').style.display = link.textContent.includes('警报') ? 'block' : 'none';
            });
        });

        function fetchDrones() {
            fetch('/api/drones')
                .then(response => response.json())
                .then(data => {
                    updateDronesUI(data);
                    updateMapMarkers(data);
                })
                .catch(console.error);
        }

        function fetchAlerts() {
            fetch('/api/alerts')
                .then(response => response.json())
                .then(alerts => {
                    const alertsDiv = document.getElementById('alertsList');
                    alertsDiv.innerHTML = alerts.map(a => 
                        `<div class="alert-item">
                            <small>[${a.timestamp}]</small><br>
                            <strong>${a.type}</strong>: ${a.message}
                        </div>`
                    ).join('');
                })
                .catch(console.error);
        }

        function updateDronesUI(drones) {
            const dronesDiv = document.getElementById('dronesList');
            let html = '';
            for (const mac in drones) {
                const drone = drones[mac];
                const basic = drone.messages['Basic ID'] || {};
                const location = drone.messages['Location'] || {};
                const system = drone.messages['System'] || {};
                
                html += `
                    <div class="card mb-2">
                        <div class="card-body p-2" style="cursor:pointer;" onclick="selectDrone('${mac}')">
                            <div><strong>${basic.uas_id || mac}</strong></div>
                            <div>类型: ${basic.ua_type || 'N/A'}</div>
                            <div>高度: ${location.altitude_m || 'N/A'}m</div>
                            <div>区域: ${system.classification_region || 'N/A'} ${system.china_region ? '🇨🇳' : ''}</div>
                            <div class="text-muted small">${drone.last_seen}</div>
                        </div>
                    </div>
                `;
            }
            dronesDiv.innerHTML = html || '<div class="text-muted">无无人机数据</div>';
        }

        function updateMapMarkers(drones) {
            const currentMacs = Object.keys(drones);
            for (const mac in droneMarkers) {
                if (!currentMacs.includes(mac)) {
                    map.removeLayer(droneMarkers[mac]);
                    delete droneMarkers[mac];
                }
            }

            for (const mac in drones) {
                const drone = drones[mac];
                const location = drone.messages['Location'] || {};
                if (location.latitude && location.longitude) {
                    const popupContent = `<b>${basic.uas_id || drone.mac}</b><br>类型: ${basic.ua_type || 'N/A'}<br>高度: ${location.altitude_m || 'N/A'}m<br>区域: ${system.classification_region || 'N/A'}${system.china_region ? ' 🇨🇳' : ''}<br><button onclick="showTrajectory('${drone.mac}')">显示轨迹</button>`;
                    const basic = drone.messages['Basic ID'] || {};
                    const system = drone.messages['System'] || {};
                    if (droneMarkers[mac]) {
                        droneMarkers[mac].setLatLng([location.latitude, location.longitude]);
                        droneMarkers[mac].setPopupContent(popupContent);
                    } else {
                        droneMarkers[mac] = L.marker([location.latitude, location.longitude])
                            .bindPopup(popupContent)
                            .addTo(map);
                    }
                }
            }
        }

        function showTrajectory(mac) {
            selectedDrone = mac;
            fetch(`/api/trajectory/${mac}`)
                .then(response => response.json())
                .then(trajectory => {
                    droneTrajectories[mac] = trajectory;
                    const slider = document.getElementById('timelineSlider');
                    slider.max = Math.max(1, trajectory.length - 1);
                    slider.value = trajectory.length - 1;
                    slider.oninput = () => {
                        const progress = slider.value / (trajectory.length - 1 || 1);
                        drawTrajectory(trajectory, progress);
                    };
                    drawTrajectory(trajectory, 1.0);
                })
                .catch(console.error);
        }

        function drawTrajectory(trajectory, progress) {
            if (window.currentTrajectory) map.removeLayer(window.currentTrajectory);
            if (window.trajectoryMarker) map.removeLayer(window.trajectoryMarker);
            
            if (trajectory.length === 0) return;
            const index = Math.floor(trajectory.length * progress);
            const points = trajectory.slice(0, index + 1).map(p => [p.latitude, p.longitude]);
            
            if (points.length > 0) {
                window.currentTrajectory = L.polyline(points, {color: 'blue'}).addTo(map);
                const lastPoint = points[points.length - 1];
                window.trajectoryMarker = L.marker(lastPoint, {
                    icon: L.divIcon({html: '<div style="background:red;width:10px;height:10px;border-radius:50%"></div>'})
                }).addTo(map);
            }
        }

        document.getElementById('playBtn').onclick = function() {
            if (!selectedDrone || !droneTrajectories[selectedDrone]) {
                alert('请选择一个无人机并加载轨迹');
                return;
            }
            
            if (isPlaying) {
                clearInterval(playInterval);
                isPlaying = false;
                this.textContent = '▶ 播放';
            } else {
                const trajectory = droneTrajectories[selectedDrone];
                let index = 0;
                isPlaying = true;
                this.textContent = '⏸ 暂停';
                
                playInterval = setInterval(() => {
                    if (index >= trajectory.length) {
                        clearInterval(playInterval);
                        isPlaying = false;
                        this.textContent = '▶ 播放';
                        return;
                    }
                    document.getElementById('timelineSlider').value = index;
                    drawTrajectory(trajectory, index / (trajectory.length - 1 || 1));
                    index++;
                }, 500);
            }
        };

        document.getElementById('exportBtn').onclick = function() {
            let url = '/api/export/csv';
            if (selectedDrone) url += `?mac=${selectedDrone}`;
            window.open(url, '_blank');
        };

        fetchDrones();
        fetchAlerts();
        setInterval(() => { fetchDrones(); fetchAlerts(); }, 5000);

        function selectDrone(mac) { selectedDrone = mac; }
    </script>
</body>
</html>""")

def start_sniffer(interface):
    receiver = RemoteIDReceiver()
    print(f"📡 Starting sniffer on {interface}")
    try:
        sniff(iface=interface, prn=receiver.packet_handler, store=0,
              filter="type mgt subtype beacon")
    except Exception as e:
        print(f"❌ Sniffer error: {e}")

def start_webui():
    print("🌐 Starting Web UI at http://<your-ip>:5000")
    app.run(host='0.0.0.0', port=5000, debug=False)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: sudo python3 remoteid_sniffer_fixed.py <interface>")
        sys.exit(1)

    interface = sys.argv[1]
    
    # 创建 Web 模板
    create_templates()
    
    # 初始化数据库（启用 WAL）
    init_db()
    
    # 启动数据库写入线程
    db_thread = threading.Thread(target=db_writer, daemon=True)
    db_thread.start()
    
    # 启动抓包线程
    sniffer_thread = threading.Thread(target=start_sniffer, args=(interface,), daemon=True)
    sniffer_thread.start()
    
    # 启动 Web UI
    start_webui()
