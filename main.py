"""NetWatch backend service.

Scans the local network with ARP, keeps an in-memory baseline, persists network
history, and exposes device/alert data to the mobile app over a local API.
"""

from __future__ import annotations

import asyncio
import argparse
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Dict, List

try:
    import uvicorn
    from dotenv import load_dotenv
    from fastapi import FastAPI, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
except ImportError as error:
    missing_package = str(error).split("'")[1] if "'" in str(error) else str(error)
    print(
        "[NetWatch] Missing Python dependency: "
        f"{missing_package}\n\n"
        "Fix:\n"
        "  pip install -r requirements.txt\n\n"
        "If you want the Windows EXE build:\n"
        "  pip install -r requirements.txt\n"
        "  pyinstaller netwatch.spec\n"
    )
    raise SystemExit(1) from error

try:
    from scapy.all import ARP, Ether, conf, srp
except ImportError:  # Scapy is optional at import time so the API can explain itself.
    ARP = Ether = conf = srp = None


BASE_DIR = (
    Path(sys.executable).resolve().parent
    if getattr(sys, "frozen", False)
    else Path(__file__).resolve().parent
)
HISTORY_FILE = BASE_DIR / "netwatch_history.json"

load_dotenv(BASE_DIR / ".env")


def env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        print(f"[NetWatch] Invalid integer for {name}; using {default}.")
        return default

CONFIG = {
    "api_host": os.getenv("NETWATCH_API_HOST", "0.0.0.0"),
    "api_port": env_int("NETWATCH_API_PORT", 8000),
    "scan_interval": env_int("NETWATCH_SCAN_INTERVAL", 60),
    "network_cidr": os.getenv("NETWATCH_NETWORK_CIDR", "192.168.1.0/24"),
    "interface": os.getenv("NETWATCH_INTERFACE") or None,
}

VENDOR_PREFIXES = {
    "00:1A:79": "Apple",
    "3C:5A:B4": "Google",
    "44:65:0D": "Amazon",
    "50:C7:BF": "TP-Link",
    "70:4F:57": "Samsung",
    "8C:85:90": "Apple",
    "A4:5E:60": "Apple",
    "B8:27:EB": "Raspberry Pi",
    "C8:3A:35": "Tenda",
    "D8:31:34": "Samsung",
    "DC:A6:32": "Raspberry Pi",
    "F0:18:98": "Apple",
    "00:05:69": "VMware",
    "00:0C:29": "VMware",
    "00:1C:42": "Parallels",
    "00:50:56": "VMware",
    "08:00:27": "VirtualBox",
    "28:6C:07": "Xiaomi",
    "34:CE:00": "Xiaomi",
    "48:3F:DA": "Espressif",
    "60:01:94": "Espressif",
    "78:11:DC": "Xiaomi",
    "A0:20:A6": "Espressif",
    "AC:67:B2": "Amazon",
    "B4:E6:2D": "Apple",
    "D4:F5:47": "Google",
    "E0:98:61": "Apple",
}


@dataclass
class Device:
    ip: str
    mac: str
    vendor: str
    first_seen: str
    last_seen: str
    is_new: bool = False
    hostname: str = "Unknown"
    device_type: str = "Unknown device"
    connection_type: str = "LAN (ARP observed)"
    location: str = "Local network"
    network_role: str = "Client"
    confidence: str = "Medium"
    details: str = "Observed through ARP response/cache."
    blocked: bool = False


@dataclass
class Alert:
    ip: str
    mac: str
    vendor: str
    detected_at: str
    message: str


app = FastAPI(
    title="NetWatch API",
    description="Local network scanner and intrusion alert API.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

devices_by_mac: Dict[str, Device] = {}
alerts: List[Alert] = []
baseline_ready = False
blocked_ips: set[str] = set()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_mac(mac: str) -> str:
    clean = re.sub(r"[^0-9A-Fa-f]", "", mac)
    if len(clean) != 12:
        return mac.upper()
    return ":".join(clean[i : i + 2] for i in range(0, 12, 2)).upper()


def lookup_vendor(mac: str) -> str:
    prefix = normalize_mac(mac)[:8]
    return VENDOR_PREFIXES.get(prefix, "Unknown Vendor")


def resolve_hostname(ip: str) -> str:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (OSError, socket.herror):
        return "Unknown"


def location_for_ip(ip: str) -> str:
    try:
        parsed = ip_address(ip)
    except ValueError:
        return "Invalid IP"

    if parsed.is_private:
        return "Local network - physical location is not available from a private IP"
    if parsed.is_loopback:
        return "This computer"
    if parsed.is_link_local:
        return "Link-local network"
    if parsed.is_multicast:
        return "Multicast address"
    if parsed.is_reserved:
        return "Reserved network range"
    return "Public IP - external geolocation lookup required"


def infer_device_profile(ip: str, mac: str, vendor: str, hostname: str) -> dict:
    lower_vendor = vendor.lower()
    lower_host = hostname.lower()
    details = []
    confidence = "Medium"
    network_role = "Client"
    device_type = "Unknown device"

    if ip.endswith(".1") or "router" in lower_host or "gateway" in lower_host:
        device_type = "Router / gateway"
        network_role = "Gateway"
        confidence = "High"
        details.append("Gateway-like IP or hostname.")
    elif any(token in lower_vendor for token in ["apple", "samsung", "xiaomi", "google"]):
        device_type = "Phone / tablet / personal device"
        details.append("Consumer-device vendor prefix.")
    elif any(token in lower_vendor for token in ["tp-link", "tenda"]):
        device_type = "Router / network equipment"
        network_role = "Network infrastructure"
        confidence = "High"
        details.append("Network-equipment vendor prefix.")
    elif any(token in lower_vendor for token in ["raspberry", "espressif"]):
        device_type = "IoT / embedded device"
        confidence = "High"
        details.append("Embedded-device vendor prefix.")
    elif any(token in lower_vendor for token in ["vmware", "virtualbox", "parallels"]):
        device_type = "Virtual machine"
        confidence = "High"
        details.append("Virtualization MAC prefix.")
    elif any(token in lower_host for token in ["desktop", "laptop", "pc", "win"]):
        device_type = "Computer"
        details.append("Computer-like hostname.")
    elif any(token in lower_host for token in ["tv", "cast", "chromecast"]):
        device_type = "TV / media device"
        details.append("Media-device hostname.")

    connection_type = "LAN device seen via ARP"
    if ip_address(ip).is_private:
        connection_type += " (same local network)"

    if not details:
        details.append("No strong vendor or hostname signal; classification is a best-effort guess.")

    return {
        "hostname": hostname,
        "device_type": device_type,
        "connection_type": connection_type,
        "location": location_for_ip(ip),
        "network_role": network_role,
        "confidence": confidence,
        "details": " ".join(details),
    }


def build_device(ip: str, mac: str, now: str) -> Device:
    normalized = normalize_mac(mac)
    vendor = lookup_vendor(normalized)
    hostname = resolve_hostname(ip)
    profile = infer_device_profile(ip, normalized, vendor, hostname)
    return Device(
        ip=ip,
        mac=normalized,
        vendor=vendor,
        first_seen=now,
        last_seen=now,
        blocked=ip in blocked_ips,
        **profile,
    )


def is_real_lan_device(ip: str, mac: str) -> bool:
    try:
        parsed_ip = ip_address(ip)
    except ValueError:
        return False

    normalized_mac = normalize_mac(mac)
    if parsed_ip.is_multicast or parsed_ip.is_unspecified or parsed_ip.is_loopback:
        return False
    if normalized_mac in {"FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"}:
        return False
    if normalized_mac.startswith("01:00:5E"):
        return False
    return True


def detect_local_cidr() -> str:
    if os.getenv("NETWATCH_NETWORK_CIDR"):
        return CONFIG["network_cidr"]

    try:
        output = subprocess.check_output(
            ["ipconfig"],
            text=True,
            stderr=subprocess.DEVNULL,
            encoding="utf-8",
            errors="ignore",
        )
    except Exception:
        return CONFIG["network_cidr"]

    ip_match = re.search(r"IPv4 Address[^\d]*(\d{1,3}(?:\.\d{1,3}){3})", output)
    mask_match = re.search(r"Subnet Mask[^\d]*(\d{1,3}(?:\.\d{1,3}){3})", output)
    if not ip_match or not mask_match:
        return CONFIG["network_cidr"]

    try:
        return str(ip_network(f"{ip_match.group(1)}/{mask_match.group(1)}", strict=False))
    except ValueError:
        return CONFIG["network_cidr"]


def reset_history() -> None:
    global baseline_ready

    devices_by_mac.clear()
    alerts.clear()
    baseline_ready = False
    if HISTORY_FILE.exists():
        HISTORY_FILE.unlink()


def firewall_rule_name(ip: str, direction: str) -> str:
    safe_ip = re.sub(r"[^0-9A-Fa-f:.]", "_", ip)
    return f"NetWatch Block {direction} {safe_ip}"


def run_firewall_command(args: list[str]) -> None:
    completed = subprocess.run(
        ["netsh", "advfirewall", "firewall", *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        raise RuntimeError((completed.stderr or completed.stdout).strip())


def block_ip_on_this_pc(ip: str) -> None:
    try:
        parsed = ip_address(ip)
    except ValueError as error:
        raise ValueError("Invalid IP address.") from error

    if not parsed.is_private:
        raise ValueError("Only local/private LAN IP addresses can be blocked from NetWatch.")

    for direction in ["in", "out"]:
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={firewall_rule_name(ip, direction)}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        run_firewall_command(
            [
                "add",
                "rule",
                f"name={firewall_rule_name(ip, direction)}",
                f"dir={direction}",
                "action=block",
                f"remoteip={ip}",
                "enable=yes",
            ]
        )

    blocked_ips.add(ip)
    for device in devices_by_mac.values():
        if device.ip == ip:
            device.blocked = True
    save_history()


def unblock_ip_on_this_pc(ip: str) -> None:
    for direction in ["in", "out"]:
        run_firewall_command(["delete", "rule", f"name={firewall_rule_name(ip, direction)}"])

    blocked_ips.discard(ip)
    for device in devices_by_mac.values():
        if device.ip == ip:
            device.blocked = False
    save_history()


def load_history() -> None:
    global baseline_ready

    devices_by_mac.clear()
    alerts.clear()
    baseline_ready = False

    if not HISTORY_FILE.exists():
        return

    try:
        data = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return

    for item in data.get("devices", []):
        mac = normalize_mac(item["mac"])
        if not is_real_lan_device(item["ip"], mac):
            continue
        devices_by_mac[mac] = Device(
            ip=item["ip"],
            mac=mac,
            vendor=item.get("vendor", lookup_vendor(mac)),
            first_seen=item.get("first_seen", utc_now()),
            last_seen=item.get("last_seen", utc_now()),
            is_new=False,
            hostname=item.get("hostname", "Unknown"),
            device_type=item.get("device_type", "Unknown device"),
            connection_type=item.get("connection_type", "LAN (ARP observed)"),
            location=item.get("location", location_for_ip(item["ip"])),
            network_role=item.get("network_role", "Client"),
            confidence=item.get("confidence", "Medium"),
            details=item.get("details", "Loaded from saved history."),
            blocked=item.get("blocked", False),
        )
        if devices_by_mac[mac].blocked:
            blocked_ips.add(devices_by_mac[mac].ip)

    for item in data.get("alerts", []):
        mac = normalize_mac(item["mac"])
        if not is_real_lan_device(item["ip"], mac):
            continue
        alerts.append(
            Alert(
                ip=item["ip"],
                mac=mac,
                vendor=item.get("vendor", lookup_vendor(mac)),
                detected_at=item.get("detected_at", utc_now()),
                message=item.get("message", "New device detected"),
            )
        )

    baseline_ready = bool(devices_by_mac)


def save_history() -> None:
    payload = {
        "devices": [asdict(device) for device in devices_by_mac.values()],
        "alerts": [asdict(alert) for alert in alerts],
        "updated_at": utc_now(),
    }
    HISTORY_FILE.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def scan_with_scapy() -> List[Device]:
    if ARP is None or Ether is None or srp is None:
        raise RuntimeError("Scapy is not installed.")

    if CONFIG["interface"]:
        conf.iface = CONFIG["interface"]

    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=detect_local_cidr())
    answered, _ = srp(packet, timeout=3, verbose=False)

    found = []
    seen_macs = set()
    now = utc_now()

    for _, response in answered:
        mac = normalize_mac(response.hwsrc)
        if mac in seen_macs or not is_real_lan_device(response.psrc, mac):
            continue
        seen_macs.add(mac)
        found.append(build_device(response.psrc, mac, now))

    return found


def scan_with_system_arp() -> List[Device]:
    command = ["arp", "-a"]
    output = subprocess.check_output(command, text=True, stderr=subprocess.DEVNULL)
    now = utc_now()
    found = []

    for ip, mac in re.findall(
        r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F:-]{11,17})", output
    ):
        normalized = normalize_mac(mac)
        if not is_real_lan_device(ip, normalized):
            continue
        found.append(build_device(ip, normalized, now))

    return found


def scan_with_windows_neighbors() -> List[Device]:
    if platform.system().lower() != "windows":
        return []

    command = [
        "powershell",
        "-NoProfile",
        "-Command",
        (
            "Get-NetNeighbor -AddressFamily IPv4 | "
            "Where-Object {$_.LinkLayerAddress} | "
            "Select-Object IPAddress,LinkLayerAddress,State,InterfaceAlias | "
            "ConvertTo-Json -Compress"
        ),
    ]
    output = subprocess.check_output(
        command,
        text=True,
        stderr=subprocess.DEVNULL,
        encoding="utf-8",
        errors="ignore",
        timeout=8,
    )
    if not output.strip():
        return []

    rows = json.loads(output)
    if isinstance(rows, dict):
        rows = [rows]

    now = utc_now()
    found = []
    seen = set()
    for row in rows:
        ip = str(row.get("IPAddress", ""))
        mac = normalize_mac(str(row.get("LinkLayerAddress", "")))
        if mac in seen or not is_real_lan_device(ip, mac):
            continue
        seen.add(mac)
        device = build_device(ip, mac, now)
        iface = row.get("InterfaceAlias") or "Unknown interface"
        device.connection_type = f"Windows neighbor table via {iface}"
        device.details = f"Discovered from Windows neighbor cache. State={row.get('State', 'Unknown')}."
        found.append(device)

    return found


def warm_arp_cache() -> None:
    cidr = detect_local_cidr()
    try:
        network = ip_network(cidr, strict=False)
    except ValueError:
        return

    hosts = list(network.hosts())
    if len(hosts) > 254:
        hosts = hosts[:254]

    def ping(host: str) -> None:
        subprocess.run(
            ["ping", "-n", "1", "-w", "180", host],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    threads = []
    for host in hosts:
        thread = threading.Thread(target=ping, args=(str(host),), daemon=True)
        thread.start()
        threads.append(thread)
        if len(threads) >= 48:
            for item in threads:
                item.join()
            threads.clear()

    for item in threads:
        item.join()


def scan_network() -> List[Device]:
    discovered: dict[str, Device] = {}

    try:
        found = scan_with_scapy()
        for device in found:
            discovered[device.mac] = device
        if not found:
            print("[NetWatch] Scapy scan returned 0 device(s), using Windows discovery fallback.")
    except Exception as scapy_error:
        print(f"[NetWatch] Scapy scan failed, using Windows discovery fallback: {scapy_error}")

    try:
        for scanner in [scan_with_windows_neighbors, scan_with_system_arp]:
            for device in scanner():
                discovered.setdefault(device.mac, device)

        if not discovered:
            warm_arp_cache()
            for scanner in [scan_with_windows_neighbors, scan_with_system_arp]:
                for device in scanner():
                    discovered.setdefault(device.mac, device)

        return list(discovered.values())
    except Exception as arp_error:
        print(f"[NetWatch] ARP fallback failed: {arp_error}")
        return list(discovered.values())


def merge_scan_results(found_devices: List[Device]) -> None:
    global baseline_ready

    now = utc_now()
    if not baseline_ready:
        for device in found_devices:
            device.is_new = False
            devices_by_mac[device.mac] = device
        baseline_ready = True
        save_history()
        print(f"[NetWatch] Baseline created with {len(found_devices)} device(s).")
        return

    for scanned in found_devices:
        existing = devices_by_mac.get(scanned.mac)
        if existing:
            existing.ip = scanned.ip
            existing.last_seen = now
            existing.is_new = False
            existing.hostname = scanned.hostname
            existing.vendor = scanned.vendor
            existing.device_type = scanned.device_type
            existing.connection_type = scanned.connection_type
            existing.location = scanned.location
            existing.network_role = scanned.network_role
            existing.confidence = scanned.confidence
            existing.details = scanned.details
            existing.blocked = scanned.ip in blocked_ips
            continue

        scanned.first_seen = now
        scanned.last_seen = now
        scanned.is_new = True
        devices_by_mac[scanned.mac] = scanned

        alert = Alert(
            ip=scanned.ip,
            mac=scanned.mac,
            vendor=scanned.vendor,
            detected_at=now,
            message=f"New device detected: {scanned.ip} ({scanned.mac})",
        )
        alerts.append(alert)
        print(f"[NetWatch][ALERT] {alert.message} - {scanned.vendor}")

    save_history()


async def scanner_loop() -> None:
    while True:
        found_devices = await asyncio.to_thread(scan_network)
        merge_scan_results(found_devices)
        await asyncio.sleep(CONFIG["scan_interval"])


@app.on_event("startup")
async def startup_event() -> None:
    load_history()
    asyncio.create_task(scanner_loop())


@app.get("/devices")
def get_devices() -> List[dict]:
    return [asdict(device) for device in devices_by_mac.values()]


@app.get("/alerts")
def get_alerts() -> List[dict]:
    return [asdict(alert) for alert in alerts]


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "scanner": "running",
        "platform": platform.system(),
        "network_cidr": detect_local_cidr(),
        "device_count": len(devices_by_mac),
        "alert_count": len(alerts),
    }


@app.post("/reset")
def reset_baseline() -> dict:
    reset_history()
    return {"status": "reset", "message": "Baseline and alert history cleared."}


@app.post("/scan")
def scan_now() -> dict:
    found_devices = scan_network()
    merge_scan_results(found_devices)
    return {
        "status": "scanned",
        "found_count": len(found_devices),
        "device_count": len(devices_by_mac),
        "alert_count": len(alerts),
    }


@app.post("/devices/{ip}/block")
def block_device(ip: str) -> dict:
    try:
        block_ip_on_this_pc(ip)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    except RuntimeError as error:
        raise HTTPException(
            status_code=500,
            detail=f"Windows Firewall rule could not be created. Run NetWatch as Administrator. {error}",
        ) from error
    return {"status": "blocked", "ip": ip, "scope": "this_windows_pc"}


@app.post("/devices/{ip}/unblock")
def unblock_device(ip: str) -> dict:
    try:
        unblock_ip_on_this_pc(ip)
    except RuntimeError as error:
        raise HTTPException(
            status_code=500,
            detail=f"Windows Firewall rule could not be removed. Run NetWatch as Administrator. {error}",
        ) from error
    return {"status": "unblocked", "ip": ip, "scope": "this_windows_pc"}


def build_windows_exe(name: str = "NetWatch") -> None:
    """Build a single-file Windows executable with bundled dependencies."""
    try:
        import PyInstaller.__main__
    except ImportError:
        print(
            "[NetWatch] PyInstaller is not installed.\n\n"
            "Fix:\n"
            "  pip install -r requirements.txt\n"
            "Then run:\n"
            "  python main.py --build-exe"
        )
        raise SystemExit(1)

    dist_dir = BASE_DIR / "dist"
    build_dir = BASE_DIR / "build"
    spec_file = BASE_DIR / f"{name}.spec"

    shutil.rmtree(dist_dir, ignore_errors=True)
    shutil.rmtree(build_dir, ignore_errors=True)
    if spec_file.exists():
        spec_file.unlink()

    args = [
        str(BASE_DIR / "main.py"),
        f"--name={name}",
        "--onefile",
        "--windowed",
        "--clean",
        "--collect-all=scapy",
        "--collect-all=uvicorn",
        "--collect-all=fastapi",
        "--collect-all=starlette",
        "--collect-all=pydantic",
        "--collect-all=pydantic_core",
        "--collect-all=anyio",
        "--collect-all=dotenv",
        "--collect-all=click",
        "--collect-all=h11",
        "--collect-all=httptools",
        "--collect-all=watchfiles",
        "--collect-all=websockets",
        "--collect-all=yaml",
        "--hidden-import=tkinter",
        "--hidden-import=tkinter.ttk",
        "--hidden-import=tkinter.messagebox",
        "--hidden-import=uvicorn.protocols.http.auto",
        "--hidden-import=uvicorn.protocols.websockets.auto",
        "--hidden-import=uvicorn.lifespan.on",
        f"--distpath={dist_dir}",
        f"--workpath={build_dir}",
        f"--specpath={BASE_DIR}",
    ]

    env_example = BASE_DIR / ".env.example"
    if env_example.exists():
        args.append(f"--add-data={env_example}{os.pathsep}.")

    print(f"[NetWatch] Building {name}.exe. This can take a few minutes...")
    PyInstaller.__main__.run(args)
    if spec_file.exists():
        spec_file.unlink()
    print(f"[NetWatch] Done: {dist_dir / f'{name}.exe'}")


def start_api_server() -> None:
    uvicorn.run(
        app,
        host=CONFIG["api_host"],
        port=CONFIG["api_port"],
        log_level="warning",
        log_config=None,
    )


def run_gui() -> None:
    try:
        import tkinter as tk
        from tkinter import messagebox, ttk
    except ImportError:
        print("[NetWatch] Tkinter is not available on this Python installation.")
        raise SystemExit(1)

    load_history()

    api_thread_started = False

    root = tk.Tk()
    root.title("NetWatch")
    root.geometry("980x620")
    root.minsize(860, 540)
    root.configure(bg="#0e1117")

    style = ttk.Style()
    style.theme_use("clam")
    style.configure("Treeview", background="#171b23", foreground="#f4f7fb")
    style.configure("Treeview.Heading", background="#222936", foreground="#f4f7fb")
    style.configure("TNotebook", background="#0e1117", borderwidth=0)
    style.configure("TNotebook.Tab", padding=(18, 8))

    header = tk.Frame(root, bg="#0e1117")
    header.pack(fill="x", padx=18, pady=(16, 8))

    title = tk.Label(
        header,
        text="NetWatch",
        fg="#f4f7fb",
        bg="#0e1117",
        font=("Segoe UI", 24, "bold"),
    )
    title.pack(side="left")

    status_var = tk.StringVar(value="Hazir")
    status = tk.Label(
        header,
        textvariable=status_var,
        fg="#00d1a7",
        bg="#0e1117",
        font=("Segoe UI", 11),
    )
    status.pack(side="right")

    control = tk.Frame(root, bg="#0e1117")
    control.pack(fill="x", padx=18, pady=(0, 12))

    info_var = tk.StringVar(
        value=(
            f"CIDR: {CONFIG['network_cidr']}   "
            f"Interval: {CONFIG['scan_interval']}s   "
            f"API: http://127.0.0.1:{CONFIG['api_port']}"
        )
    )
    tk.Label(
        control,
        textvariable=info_var,
        fg="#aab4c3",
        bg="#0e1117",
        font=("Segoe UI", 10),
    ).pack(side="left")

    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True, padx=18, pady=(0, 18))

    devices_frame = tk.Frame(notebook, bg="#0e1117")
    alerts_frame = tk.Frame(notebook, bg="#0e1117")
    notebook.add(devices_frame, text="Devices")
    notebook.add(alerts_frame, text="Alerts")

    device_columns = ("ip", "mac", "vendor", "first_seen", "last_seen", "new")
    device_table = ttk.Treeview(
        devices_frame,
        columns=device_columns,
        show="headings",
        height=18,
    )
    for column, heading, width in [
        ("ip", "IP Address", 130),
        ("mac", "MAC Address", 160),
        ("vendor", "Vendor", 150),
        ("first_seen", "First Seen", 210),
        ("last_seen", "Last Seen", 210),
        ("new", "Status", 90),
    ]:
        device_table.heading(column, text=heading)
        device_table.column(column, width=width, anchor="w")
    device_table.pack(fill="both", expand=True)

    alert_columns = ("detected_at", "ip", "mac", "vendor", "message")
    alert_table = ttk.Treeview(
        alerts_frame,
        columns=alert_columns,
        show="headings",
        height=18,
    )
    for column, heading, width in [
        ("detected_at", "Detected At", 210),
        ("ip", "IP Address", 130),
        ("mac", "MAC Address", 160),
        ("vendor", "Vendor", 150),
        ("message", "Message", 300),
    ]:
        alert_table.heading(column, text=heading)
        alert_table.column(column, width=width, anchor="w")
    alert_table.pack(fill="both", expand=True)

    seen_alert_count = len(alerts)

    def refresh_tables() -> None:
        nonlocal seen_alert_count

        existing_device_rows = set(device_table.get_children())
        current_device_rows = set()
        for device in sorted(devices_by_mac.values(), key=lambda item: item.ip):
            row_id = device.mac
            current_device_rows.add(row_id)
            values = (
                device.ip,
                device.mac,
                device.vendor,
                device.first_seen,
                device.last_seen,
                "NEW" if device.is_new else "Known",
            )
            if row_id in existing_device_rows:
                device_table.item(row_id, values=values)
            else:
                device_table.insert("", "end", iid=row_id, values=values)

        for stale_row in existing_device_rows - current_device_rows:
            device_table.delete(stale_row)

        alert_table.delete(*alert_table.get_children())
        for index, alert in enumerate(reversed(alerts)):
            alert_table.insert(
                "",
                "end",
                iid=str(index),
                values=(
                    alert.detected_at,
                    alert.ip,
                    alert.mac,
                    alert.vendor,
                    alert.message,
                ),
            )

        status_var.set(f"{len(devices_by_mac)} cihaz | {len(alerts)} uyari")

        if len(alerts) > seen_alert_count:
            newest = alerts[-1]
            seen_alert_count = len(alerts)
            messagebox.showwarning(
                "NetWatch Alert",
                f"Yeni cihaz algilandi:\n\n{newest.ip}\n{newest.mac}\n{newest.vendor}",
            )

        root.after(1500, refresh_tables)

    def run_manual_scan() -> None:
        status_var.set("Taraniyor...")

        def worker() -> None:
            merge_scan_results(scan_network())
            root.after(0, lambda: status_var.set("Tarama tamamlandi"))

        threading.Thread(target=worker, daemon=True).start()

    def reset_baseline_from_gui() -> None:
        confirmed = messagebox.askyesno(
            "Reset Baseline",
            "Kayitli cihaz gecmisi silinsin ve baseline yeniden olusturulsun mu?",
        )
        if not confirmed:
            return
        reset_history()
        status_var.set("Baseline sifirlandi")
        refresh_tables()

    def start_monitoring() -> None:
        nonlocal api_thread_started
        if api_thread_started:
            status_var.set("Zaten calisiyor")
            return

        api_thread_started = True
        threading.Thread(target=start_api_server, daemon=True).start()
        status_var.set("Izleme baslatildi")

    button_bar = tk.Frame(root, bg="#0e1117")
    button_bar.pack(fill="x", padx=18, pady=(0, 16))

    start_button = tk.Button(
        button_bar,
        text="Start Monitoring",
        command=start_monitoring,
        bg="#00d1a7",
        fg="#07100e",
        activebackground="#15e6bd",
        activeforeground="#07100e",
        relief="flat",
        padx=18,
        pady=9,
        font=("Segoe UI", 10, "bold"),
    )
    start_button.pack(side="left")

    scan_button = tk.Button(
        button_bar,
        text="Scan Now",
        command=run_manual_scan,
        bg="#222936",
        fg="#f4f7fb",
        activebackground="#2f394a",
        activeforeground="#f4f7fb",
        relief="flat",
        padx=18,
        pady=9,
        font=("Segoe UI", 10, "bold"),
    )
    scan_button.pack(side="left", padx=(10, 0))

    reset_button = tk.Button(
        button_bar,
        text="Reset Baseline",
        command=reset_baseline_from_gui,
        bg="#3a2330",
        fg="#ffd7e2",
        activebackground="#563246",
        activeforeground="#ffffff",
        relief="flat",
        padx=18,
        pady=9,
        font=("Segoe UI", 10, "bold"),
    )
    reset_button.pack(side="left", padx=(10, 0))

    refresh_tables()
    root.mainloop()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="NetWatch backend service")
    parser.add_argument(
        "--build-exe",
        action="store_true",
        help="Build a single-file Windows EXE with bundled dependencies.",
    )
    parser.add_argument(
        "--build-backend-exe",
        action="store_true",
        help="Build the hidden backend EXE used by the C# desktop app.",
    )
    parser.add_argument(
        "--api-only",
        action="store_true",
        help="Run only the local API service without the desktop UI.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.build_exe:
        build_windows_exe()
    elif args.build_backend_exe:
        build_windows_exe("NetWatchBackend")
    elif args.api_only:
        start_api_server()
    else:
        run_gui()
