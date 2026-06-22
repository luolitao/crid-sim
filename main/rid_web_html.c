#include "rid_web_html.h"
#include "rid_config.h"
#include "rid_manager.h"

#define FIRMWARE_VERSION "v1.0.0-" __DATE__ " " __TIME__

#define SEND_CHUNK(str) httpd_resp_send_chunk(req, str, HTTPD_RESP_USE_STRLEN)

esp_err_t send_root_html(httpd_req_t *req) {
    // 将原 root_get_handler 中从 SEND_CHUNK 开始到结束的 HTML 生成代码移到这里
    // 但需要保留对 req 的引用和 SEND_CHUNK 宏
    // 注意：系统信息获取和全局配置初始化也移到这里
    // 最后返回 ESP_OK

    rid_sys_info_t sys_info;
    rid_get_sys_info(&sys_info);
    rid_dynamic_config_t cfg;
    rid_get_config_snapshot(&cfg);

    SEND_CHUNK("<!doctype html><html><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>C-RID Control</title>"
        "<style>body{font-family:sans-serif;max-width:960px;margin:40px auto;padding:0 16px;line-height:1.5}"
        "input,select{width:100%;padding:8px;font-size:14px;box-sizing:border-box;margin-bottom:10px}"
        "button{padding:10px 15px;font-size:14px;background:#007bff;color:#fff;border:none;border-radius:4px;cursor:pointer}"
        "button:disabled{background:#ccc} .box{background:#f5f5f5;padding:15px;border-radius:8px;margin-bottom:15px}"
        "table{width:100%;border-collapse:collapse} th,td{padding:6px;border-bottom:1px solid #ddd;text-align:left;font-size:13px}"
        "th{width:40%;color:#555} .status{margin-top:10px;font-weight:bold;font-size:14px}"
        ".instance-card{border:1px solid #ddd;padding:10px;margin:10px 0;border-radius:5px;background:#fff}"
        ".instance-card h4{margin:0 0 10px 0} .btn-danger{background:#dc3545} .btn-success{background:#28a745}"
        ".btn-warning{background:#ffc107;color:#000}</style></head><body>"
        "<h1>C-RID Simulator Control</h1>");

    // 系统信息
    SEND_CHUNK("<div class=\"box\"><h3>System Information</h3><table>");
    char buf[256];
    int days = sys_info.uptime_sec / 86400;
    int hours = (sys_info.uptime_sec % 86400) / 3600;
    int mins = (sys_info.uptime_sec % 3600) / 60;
    int secs = sys_info.uptime_sec % 60;
    snprintf(buf, sizeof(buf), "<tr><th>Chip / Flash</th><td>%s / %sMB</td></tr>", sys_info.chip_model, sys_info.flash_size);
    SEND_CHUNK(buf);
    snprintf(buf, sizeof(buf), "<tr><th>MAC Address</th><td>%s</td></tr>", sys_info.mac_addr);
    SEND_CHUNK(buf);
    snprintf(buf, sizeof(buf), "<tr><th>Uptime</th><td>%dd %dh %dm %ds</td></tr>", days, hours, mins, secs);
    SEND_CHUNK(buf);
    SEND_CHUNK("<tr><th>System Time</th><td>");
    SEND_CHUNK(sys_info.sys_time);
    SEND_CHUNK("</td></tr>");
    snprintf(buf, sizeof(buf), "<tr><th>Free Heap</th><td>%u bytes</td></tr>", (unsigned int)sys_info.free_heap);
    SEND_CHUNK(buf);
    snprintf(buf, sizeof(buf), "<tr><th>Partition</th><td>%s</td></tr>", sys_info.partition_name);
    SEND_CHUNK(buf);
    snprintf(buf, sizeof(buf), "<tr><th>Firmware</th><td>%s</td></tr>", FIRMWARE_VERSION);
    SEND_CHUNK(buf);
    SEND_CHUNK("</table></div>");

    // 全局配置
    SEND_CHUNK("<div class=\"box\"><h3>Global Flight Configuration</h3>"
        "<form id=\"configForm\">"
        "<label>Latitude</label><input type=\"number\" step=\"0.000001\" id=\"lat\" required>"
        "<label>Longitude</label><input type=\"number\" step=\"0.000001\" id=\"lon\" required>"
        "<label>Flight Mode</label>"
        "<select id=\"mode\">"
        "<option value=\"0\">Circle</option>"
        "<option value=\"1\">PingPong</option>"
        "<option value=\"2\">S-Search</option>"
        "</select>"
        "<button type=\"submit\">Save & Apply</button>"
        "</form>"
        "<p id=\"cfgStatus\" class=\"status\"></p></div>");

    // 实例管理
    SEND_CHUNK("<div class=\"box\"><h3>Drone Instances</h3>"
        "<div id=\"instances-list\"></div>"
        "<button id=\"add-instance\" class=\"btn-success\">Add Instance</button>"
        "</div>");

    // OTA
    SEND_CHUNK("<div class=\"box\"><h3>Firmware Update</h3>"
        "<form id=\"otaForm\">"
        "<input type=\"file\" id=\"firmwareFile\" accept=\".bin\" required>"
        "<button type=\"submit\" id=\"otaBtn\">Upload & OTA</button>"
        "</form>"
        "<p id=\"otaStatus\" class=\"status\"></p></div>");

    // JavaScript
    SEND_CHUNK("<script>"
        "document.getElementById('lat').value = '");
    snprintf(buf, sizeof(buf), "%.6f", cfg.init_lat);
    SEND_CHUNK(buf);
    SEND_CHUNK("'; document.getElementById('lon').value = '");
    snprintf(buf, sizeof(buf), "%.6f", cfg.init_lon);
    SEND_CHUNK(buf);
    SEND_CHUNK("'; document.getElementById('mode').value = '");
    snprintf(buf, sizeof(buf), "%d", cfg.flight_mode);
    SEND_CHUNK(buf);
    SEND_CHUNK("';\n"
        "document.getElementById('configForm').addEventListener('submit', async function(e) {\n"
        "  e.preventDefault();\n"
        "  const lat = document.getElementById('lat').value;\n"
        "  const lon = document.getElementById('lon').value;\n"
        "  const mode = document.getElementById('mode').value;\n"
        "  const st = document.getElementById('cfgStatus');\n"
        "  st.innerText = 'Saving...'; st.style.color='blue';\n"
        "  try {\n"
        "    const res = await fetch('/config', {method:'POST', headers:{'Content-Type':'text/plain'}, body: lat+','+lon+','+mode});\n"
        "    st.innerText = await res.text();\n"
        "    st.style.color = res.ok ? 'green' : 'red';\n"
        "  } catch(err) { st.innerText = 'Error: ' + err; st.style.color='red'; }\n"
        "});\n");

    // 实例管理 JS（使用 ?id= 方式）
    SEND_CHUNK(
        "async function loadInstances() {\n"
        "  try {\n"
        "    const res = await fetch('/api/instances');\n"
        "    if (!res.ok) throw new Error('HTTP '+res.status);\n"
        "    const data = await res.json();\n"
        "    const container = document.getElementById('instances-list');\n"
        "    container.innerHTML = '';\n"
        "    if (data.length === 0) { container.innerHTML = '<p>No instances. Add one below.</p>'; return; }\n"
        "    data.forEach(inst => {\n"
        "      const card = document.createElement('div');\n"
        "      card.className = 'instance-card';\n"
        "      card.dataset.id = inst.id;\n"
        "      card.innerHTML = `\n"
        "        <h4>Instance ${inst.id} (${inst.active ? '🟢 Active' : '🔴 Stopped'})</h4>\n"
        "        <div style=\"display:grid;grid-template-columns:1fr 1fr;gap:10px;\">\n"
        "          <div><label>Standard</label><select class=\"std-select\">\n"
        "            <option value=\"0\" ${inst.standard==0?'selected':''}>GB42590</option>\n"
        "            <option value=\"1\" ${inst.standard==1?'selected':''}>GB46750</option>\n"
        "            <option value=\"2\" ${inst.standard==2?'selected':''}>ASTM</option>\n"
        "          </select></div>\n"
        "          <div><label>UAS ID</label><input class=\"uas-id\" value=\"${inst.uas_id}\" maxlength=\"20\"></div>\n"
        "          <div><label>Latitude</label><input class=\"lat\" type=\"number\" step=\"0.000001\" value=\"${inst.latitude}\"></div>\n"
        "          <div><label>Longitude</label><input class=\"lon\" type=\"number\" step=\"0.000001\" value=\"${inst.longitude}\"></div>\n"
        "          <div><label>Altitude (MSL)</label><input class=\"alt\" type=\"number\" step=\"0.5\" value=\"${inst.altitude_msl}\"></div>\n"
        "          <div><label>Flight Mode</label><select class=\"mode-select\">\n"
        "            <option value=\"0\" ${inst.flight_mode==0?'selected':''}>Circle</option>\n"
        "            <option value=\"1\" ${inst.flight_mode==1?'selected':''}>PingPong</option>\n"
        "            <option value=\"2\" ${inst.flight_mode==2?'selected':''}>S-Search</option>\n"
        "          </select></div>\n"
        "        </div>\n"
        "        <div style=\"margin-top:10px;\">\n"
        "          <button class=\"btn-success start-btn\" ${inst.active?'disabled':''}>Start</button>\n"
        "          <button class=\"btn-warning stop-btn\" ${!inst.active?'disabled':''}>Stop</button>\n"
        "          <button class=\"btn-primary save-btn\">Save</button>\n"
        "          <button class=\"btn-danger delete-btn\">Delete</button>\n"
        "        </div>\n"
        "      `;\n"
        "      container.appendChild(card);\n"
        "    });\n"
        "    document.querySelectorAll('.start-btn').forEach(btn => {\n"
        "      btn.addEventListener('click', async function() {\n"
        "        const id = this.closest('.instance-card').dataset.id;\n"
        "        const res = await fetch(`/api/instance/start?id=${id}`, {method:'POST'});\n"
        "        if (res.ok) loadInstances(); else alert('Failed');\n"
        "      });\n"
        "    });\n"
        "    document.querySelectorAll('.stop-btn').forEach(btn => {\n"
        "      btn.addEventListener('click', async function() {\n"
        "        const id = this.closest('.instance-card').dataset.id;\n"
        "        const res = await fetch(`/api/instance/stop?id=${id}`, {method:'POST'});\n"
        "        if (res.ok) loadInstances(); else alert('Failed');\n"
        "      });\n"
        "    });\n"
        "    document.querySelectorAll('.delete-btn').forEach(btn => {\n"
        "      btn.addEventListener('click', async function() {\n"
        "        if (!confirm('Delete instance?')) return;\n"
        "        const id = this.closest('.instance-card').dataset.id;\n"
        "        const res = await fetch(`/api/instance?id=${id}`, {method:'DELETE'});\n"
        "        if (res.ok) loadInstances(); else alert('Failed');\n"
        "      });\n"
        "    });\n"
        "    document.querySelectorAll('.save-btn').forEach(btn => {\n"
        "      btn.addEventListener('click', async function() {\n"
        "        const card = this.closest('.instance-card');\n"
        "        const id = card.dataset.id;\n"
        "        const data = {\n"
        "          uas_id: card.querySelector('.uas-id').value,\n"
        "          latitude: parseFloat(card.querySelector('.lat').value),\n"
        "          longitude: parseFloat(card.querySelector('.lon').value),\n"
        "          altitude_msl: parseFloat(card.querySelector('.alt').value),\n"
        "          altitude_agl: parseFloat(card.querySelector('.alt').value),\n"
        "          flight_mode: parseInt(card.querySelector('.mode-select').value)\n"
        "        };\n"
        "        const res = await fetch(`/api/instance?id=${id}`, {\n"
        "          method: 'PUT',\n"
        "          headers: {'Content-Type':'application/json'},\n"
        "          body: JSON.stringify(data)\n"
        "        });\n"
        "        if (res.ok) loadInstances(); else alert('Failed');\n"
        "      });\n"
        "    });\n"
        "  } catch(err) {\n"
        "    document.getElementById('instances-list').innerHTML = '<p>Error loading instances: '+err.message+'</p>';\n"
        "  }\n"
        "}\n"
        "document.getElementById('add-instance').addEventListener('click', async function() {\n"
        "  const data = {standard:0, uas_id:'ESP32-DRONE', latitude:23.14287, longitude:113.26026, altitude_msl:50, flight_mode:0};\n"
        "  const res = await fetch('/api/instance', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(data)});\n"
        "  if (res.ok) loadInstances(); else alert('Failed');\n"
        "});\n"
        "loadInstances();\n");

    // OTA JS
    SEND_CHUNK("document.getElementById('otaForm').addEventListener('submit', async function(e) {\n"
        "  e.preventDefault();\n"
        "  const file = document.getElementById('firmwareFile').files[0];\n"
        "  if (!file) return;\n"
        "  const st = document.getElementById('otaStatus');\n"
        "  const btn = document.getElementById('otaBtn');\n"
        "  st.innerText = 'Uploading ' + file.name + '...'; st.style.color='blue'; btn.disabled=true;\n"
        "  try {\n"
        "    const res = await fetch('/ota', {method:'POST', headers:{'Content-Type':'application/octet-stream'}, body:file});\n"
        "    st.innerText = await res.text();\n"
        "    st.style.color = res.ok ? 'green' : 'red';\n"
        "    if(!res.ok) btn.disabled=false;\n"
        "  } catch(err) { st.innerText = 'Error: ' + err; st.style.color='red'; btn.disabled=false; }\n"
        "});\n");

    SEND_CHUNK("</script></body></html>");
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}