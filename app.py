from flask import Flask, render_template, request, send_file, jsonify
import os, csv, time, platform, subprocess, ipaddress, re, socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from datetime import datetime

# --- Flask setup ---
app = Flask(__name__)

LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

# Global variables for ARP spoofing detection
arp_monitor_running = False
arp_monitor_thread = None
suspicious_devices = {}  # Format: {mac: {'reason': 'ARP Spoofing', 'timestamp': '...', 'target_ip': '...'}}
router_ip_manual = None
router_mac_manual = None

# --- Vendor lookup ---
try:
    from mac_vendor_lookup import MacLookup
    mac_lookup = MacLookup()
    try:
        mac_lookup.load_vendors()
    except Exception:
        pass

    def get_vendor(mac: str) -> str:
        try:
            if mac.upper() == "FF:FF:FF:FF:FF:FF":
                return "Broadcast / Unknown"
            return mac_lookup.lookup(mac)
        except Exception:
            return "Unknown"
except Exception:
    mac_lookup = None
    def get_vendor(mac: str) -> str:
        if mac.upper() == "FF:FF:FF:FF:FF:FF":
            return "Broadcast / Unknown"
        return "Unknown"

# --- Platform ping ---
IS_WINDOWS = platform.system().lower().startswith("windows")
def ping_one(ip_str):
    try:
        if IS_WINDOWS:
            cmd = ["ping", "-n", "1", "-w", "500", str(ip_str)]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", str(ip_str)]
        return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    except Exception:
        return False

# --- Scapy scan ---
def scan_with_scapy(target):
    try:
        from scapy.all import arping
    except ImportError:
        raise RuntimeError("Scapy not installed")

    ans, _ = arping(target, timeout=2, verbose=False)
    devices = []
    for _, rcv in ans:
        ip = getattr(rcv, "psrc", None)
        mac = getattr(rcv, "hwsrc", None)
        if ip and mac:
            mac_norm = mac.lower().replace("-", ":")
            devices.append({'ip': ip, 'mac': mac_norm, 'vendor': get_vendor(mac_norm)})
    return devices

# --- Ping + ARP fallback ---
def scan_with_ping_arp(target, max_workers=60):
    net = ipaddress.ip_network(target, strict=False)
    ips = list(net.hosts())
    with ThreadPoolExecutor(max_workers=min(max_workers, len(ips))) as ex:
        futures = {ex.submit(ping_one, ip): ip for ip in ips}
        for _ in as_completed(futures):
            pass

    try:
        arp_out = subprocess.check_output("arp -a", shell=True, text=True, stderr=subprocess.DEVNULL)
    except Exception:
        try:
            arp_out = subprocess.check_output("ip neigh", shell=True, text=True, stderr=subprocess.DEVNULL)
        except Exception:
            arp_out = ""

    devices = []
    for line in arp_out.splitlines():
        m_win = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F\-\:]{14,17})\s+\w+", line)
        m_ip_neigh = re.search(r"(\d+\.\d+\.\d+\.\d+).*(lladdr|at)\s+([0-9a-fA-F\:\-]{14,17})", line)
        m_paren = re.search(r"\((\d+\.\d+\.\d+\.\d+)\).* at ([0-9a-fA-F\:\-]{14,17})", line)
        ip = mac = None
        if m_win:
            ip = m_win.group(1).strip()
            mac = m_win.group(2).strip().lower().replace("-", ":")
        elif m_ip_neigh:
            ip = m_ip_neigh.group(1).strip()
            mac = m_ip_neigh.group(3).strip().lower().replace("-", ":")
        elif m_paren:
            ip = m_paren.group(1).strip()
            mac = m_paren.group(2).strip().lower().replace("-", ":")
        if ip and mac:
            try:
                if ipaddress.ip_address(ip) in net:
                    devices.append({'ip': ip, 'mac': mac, 'vendor': get_vendor(mac)})
            except:
                continue

    # deduplicate by IP
    uniq = {}
    for d in devices:
        uniq[d['ip']] = {'ip': d['ip'], 'mac': d['mac'], 'vendor': d.get('vendor', 'Unknown')}
    return list(uniq.values())

# --- ARP Spoofing Detection ---
def detect_arp_spoofing():
    """Monitor for ARP spoofing attacks"""
    global suspicious_devices, arp_monitor_running, router_ip_manual, router_mac_manual
    
    try:
        from scapy.all import ARP, Ether, srp, sniff
    except ImportError:
        print("Scapy not available for ARP spoofing detection")
        arp_monitor_running = False
        return
    
    # Use manually provided router info or auto-detect
    if router_ip_manual and router_mac_manual:
        router_ip = router_ip_manual
        router_mac = router_mac_manual
        print(f"Using MANUAL router configuration: {router_ip} (MAC: {router_mac})")
    else:
        # Auto-detect router information
        def get_router_info():
            try:
                if IS_WINDOWS:
                    # Windows - get default gateway
                    result = subprocess.run(["ipconfig"], capture_output=True, text=True)
                    for line in result.stdout.split('\n'):
                        if "Default Gateway" in line and "." in line:
                            ip = line.split(":")[1].strip()
                            if ip and ip != "":
                                # Get MAC for the gateway
                                try:
                                    arp_result = subprocess.check_output(f"arp -a {ip}", shell=True, capture_output=True, text=True)
                                    for arp_line in arp_result.stdout.splitlines():
                                        if ip in arp_line:
                                            mac_match = re.search(r"([0-9a-fA-F-]{2,}[:-]){5,}[0-9a-fA-F-]{2,}", arp_line)
                                            if mac_match:
                                                return ip, mac_match.group(0).lower().replace("-", ":")
                                except:
                                    pass
                else:
                    # Linux/Mac - get default gateway
                    result = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True)
                    if result.returncode == 0:
                        ip = result.stdout.split()[2]
                        # Get MAC for the gateway
                        try:
                            result = subprocess.run(f"arp -n {ip}", shell=True, capture_output=True, text=True)
                            mac_match = re.search(r"([0-9a-fA-F:]{2,}[:]){5,}[0-9a-fA-F:]{2,}", result.stdout)
                            if mac_match:
                                return ip, mac_match.group(0).lower()
                        except:
                            pass
            except Exception as e:
                print(f"Error getting router info: {e}")
            
            # Fallback - common router IPs
            common_routers = ["192.168.1.1", "192.168.0.1", "10.0.0.1", "192.168.1.254", "192.168.0.254"]
            for router_ip in common_routers:
                try:
                    if IS_WINDOWS:
                        result = subprocess.run(f"arp -a {router_ip}", shell=True, capture_output=True, text=True)
                    else:
                        result = subprocess.run(f"arp -n {router_ip}", shell=True, capture_output=True, text=True)
                    mac_match = re.search(r"([0-9a-fA-F-]{2,}[:-]){5,}[0-9a-fA-F-]{2,}", result.stdout)
                    if mac_match:
                        return router_ip, mac_match.group(0).lower().replace("-", ":")
                except:
                    continue
            return None, None
        
        router_ip, router_mac = get_router_info()
    
    if not router_ip or not router_mac:
        print("Could not determine router information for ARP spoofing detection")
        arp_monitor_running = False
        return
    
    print(f"ARP Spoofing Monitor Started - Watching router {router_ip} (MAC: {router_mac})")
    
    def arp_monitor_callback(packet):
        global suspicious_devices
        
        if packet.haslayer(ARP):
            arp_layer = packet[ARP]
            # Check if it's an ARP reply
            if arp_layer.op == 2:  # 2 is "is-at" (reply)
                sender_ip = arp_layer.psrc
                sender_mac = arp_layer.hwsrc.lower()
                
                # Check if someone is spoofing the router's IP
                if sender_ip == router_ip and sender_mac != router_mac:
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    reason = f"ARP Spoofing: MAC {sender_mac} is impersonating router {router_ip} (real MAC: {router_mac})"
                    
                    # Add to suspicious devices
                    suspicious_devices[sender_mac] = {
                        'reason': reason,
                        'timestamp': timestamp,
                        'target_ip': router_ip,
                        'type': 'ARP Spoofing',
                        'spoofed_ip': sender_ip
                    }
                    
                    print(f"[ALERT] {reason} at {timestamp}")
    
    # Start sniffing for ARP packets
    try:
        sniff(prn=arp_monitor_callback, filter="arp", store=0, timeout=30)
    except Exception as e:
        print(f"ARP spoofing detection error: {e}")
    finally:
        arp_monitor_running = False

def start_arp_monitor():
    """Start the ARP spoofing detection in a separate thread"""
    global arp_monitor_running, arp_monitor_thread
    
    if arp_monitor_running:
        return "Monitor already running"
    
    arp_monitor_running = True
    arp_monitor_thread = threading.Thread(target=detect_arp_spoofing, daemon=True)
    arp_monitor_thread.start()
    return "ARP spoofing monitor started"

# --- Enhanced Spoof detection (combines original + ARP spoofing) ---
def detect_spoof(devices):
    ip_to_macs = {}
    mac_to_ips = {}
    for d in devices:
        ip_to_macs.setdefault(d['ip'], set()).add(d['mac'])
        mac_to_ips.setdefault(d['mac'], set()).add(d['ip'])

    spoofed_messages = []
    annotated = []
    
    # Check for IP conflict and MAC anomalies
    for d in devices:
        ip, mac = d['ip'], d['mac']
        spoof_flag = False
        if len(ip_to_macs[ip]) > 1:
            spoof_flag = True
            spoofed_messages.append(f"IP CONFLICT: IP {ip} used by MACs {', '.join(sorted(ip_to_macs[ip]))}")
        if len(mac_to_ips[mac]) > 1:
            spoof_flag = True
            spoofed_messages.append(f"MAC ANOMALY: MAC {mac} seen on IPs {', '.join(sorted(mac_to_ips[mac]))}")
        
        # Check if device is in ARP spoofing suspicious list
        is_arp_spoofing = mac in suspicious_devices
        if is_arp_spoofing:
            spoof_flag = True
            spoofed_messages.append(f"ARP SPOOFING: {suspicious_devices[mac]['reason']}")
        
        annotated.append({
            'ip': ip, 
            'mac': mac, 
            'vendor': d.get('vendor', 'Unknown'), 
            'spoof': spoof_flag,
            'arp_spoofing': is_arp_spoofing
        })
    
    return annotated, list(dict.fromkeys(spoofed_messages))

# --- Save CSV ---
def save_log(devices, spoofed):
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    fname = f"network_log_{timestamp}.csv"
    path = os.path.join(LOG_DIR, fname)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["IP Address", "MAC Address", "Vendor", "Spoof Flag", "ARP Spoofing"])
        for d in devices:
            writer.writerow([
                d['ip'], 
                d['mac'], 
                d['vendor'], 
                "YES" if d.get('spoof') else "",
                "YES" if d.get('arp_spoofing') else ""
            ])
        writer.writerow([])
        writer.writerow(["--- Spoofed Devices / Anomalies ---"])
        for s in spoofed:
            writer.writerow([s])
    return fname

# --- Routes ---
@app.route("/", methods=["GET", "POST"])
def index():
    global suspicious_devices, router_ip_manual, router_mac_manual
    
    devices = []; spoofed = []; error = None; logfile = None
    target = ""; autorefresh = False; spoof_count = 0

    # Start ARP monitor on first visit if not already running
    if not arp_monitor_running:
        start_arp_monitor()

    # Auto-scan on first load with common subnet
    if request.method == "GET" and not devices:
        # Try to auto-detect network on first load
        try:
            # Get local IP to suggest subnet
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            target = ".".join(local_ip.split('.')[:3]) + ".0/24"
        except:
            target = "192.168.1.0/24"  # Fallback

    if request.method == "POST" or (request.method == "GET" and target):
        if request.method == "POST":
            target = request.form.get("subnet", "").strip()
            # Get manual router configuration
            router_ip_manual = request.form.get("router_ip", "").strip()
            router_mac_manual = request.form.get("router_mac", "").strip()
            
        autorefresh = bool(request.form.get("autorefresh", False))
        
        if not target:
            error = "Please enter subnet (example: 192.168.1.0/24)"
        else:
            try:
                try:
                    devices_raw = scan_with_scapy(target)
                except:
                    devices_raw = scan_with_ping_arp(target)
                devices, spoofed = detect_spoof(devices_raw)
                spoof_count = sum(1 for d in devices if d.get('spoof'))
                logfile = save_log(devices, spoofed)
            except Exception as e:
                error = f"Scan failed: {e}"

    return render_template("index.html",
                           devices=devices,
                           spoofed=spoofed,
                           error=error,
                           target=target,
                           logfile=logfile,
                           autorefresh=autorefresh,
                           spoof_count=spoof_count,
                           suspicious_devices=suspicious_devices,
                           arp_monitor_running=arp_monitor_running,
                           router_ip_manual=router_ip_manual,
                           router_mac_manual=router_mac_manual)

@app.route("/download/<path:fname>")
def download(fname):
    path = os.path.join(LOG_DIR, fname)
    if os.path.exists(path):
        return send_file(path, as_attachment=True)
    return "File not found", 404

@app.route("/start_arp_monitor", methods=["POST"])
def start_arp_monitor_route():
    """API endpoint to start ARP spoofing monitor"""
    try:
        result = start_arp_monitor()
        return jsonify({"status": "success", "message": result})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route("/set_router_config", methods=["POST"])
def set_router_config():
    """API endpoint to set manual router configuration"""
    global router_ip_manual, router_mac_manual
    try:
        router_ip_manual = request.json.get("router_ip", "").strip()
        router_mac_manual = request.json.get("router_mac", "").strip()
        
        if router_ip_manual and router_mac_manual:
            return jsonify({
                "status": "success", 
                "message": f"Router configured: {router_ip_manual} (MAC: {router_mac_manual})"
            })
        else:
            return jsonify({"status": "error", "message": "Both router IP and MAC are required"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route("/get_router_config", methods=["GET"])
def get_router_config():
    """API endpoint to get current router configuration"""
    return jsonify({
        "router_ip": router_ip_manual,
        "router_mac": router_mac_manual
    })

@app.route("/get_suspicious_devices", methods=["GET"])
def get_suspicious_devices():
    """API endpoint to get current suspicious devices"""
    return jsonify(suspicious_devices)

@app.route("/clear_suspicious", methods=["POST"])
def clear_suspicious():
    """API endpoint to clear suspicious devices list"""
    global suspicious_devices
    suspicious_devices.clear()
    return jsonify({"status": "success", "message": "Suspicious devices list cleared"})

@app.route("/arp_status", methods=["GET"])
def arp_status():
    """API endpoint to check ARP monitor status"""
    return jsonify({"running": arp_monitor_running})

@app.route("/debug")
def debug():
    """Debug endpoint to check system status"""
    return jsonify({
        "arp_monitor_running": arp_monitor_running,
        "suspicious_devices_count": len(suspicious_devices),
        "suspicious_devices": suspicious_devices,
        "router_ip_manual": router_ip_manual,
        "router_mac_manual": router_mac_manual,
        "platform": platform.system(),
        "is_windows": IS_WINDOWS
    })

if __name__ == "__main__":
    print("Starting Flask ARP Detection App...")
    print("Access the web interface at: http://localhost:5000")
    print("ARP Spoofing Monitor will start automatically")
    app.run(host="0.0.0.0", port=5000, debug=True)