"""Read-only views of the OS counters, local sockets and existing neighbor cache."""

import ipaddress
import json
import socket
import subprocess
import sys
from pathlib import Path

import psutil


def read_interfaces():
    addresses = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    counters = psutil.net_io_counters(pernic=True, nowrap=False)
    interfaces = []
    for name in sorted(addresses.keys() | stats.keys() | counters.keys()):
        addrs = addresses.get(name, ())
        stat = stats.get(name)
        interfaces.append(
            {
                "name": name,
                "up": bool(stat and stat.isup),
                "speed_mbps": stat.speed if stat and stat.speed > 0 else None,
                "mtu": stat.mtu if stat else None,
                "ipv4": [a.address for a in addrs if a.family == socket.AF_INET],
                "ipv6": [a.address for a in addrs if a.family == socket.AF_INET6],
                "mac": next((a.address for a in addrs if a.family == psutil.AF_LINK), None),
            }
        )
    return interfaces, counters


def choose_interface(interfaces, counters):
    if not interfaces:
        return None

    def rank(item):
        ips = item["ipv4"] + item["ipv6"]
        external = any(not ipaddress.ip_address(addr.split("%")[0]).is_loopback for addr in ips)
        counter = counters.get(item["name"])
        return item["up"], bool(counter and external), (counter.bytes_recv if counter else 0)

    return max(interfaces, key=rank)["name"]


def neighbors():
    items = []
    message = ""
    if sys.platform == "win32":
        source = "Windows Get-NetNeighbor"
        command = (
            "$ErrorActionPreference='Stop'; "
            "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); "
            "$items=@(Get-NetNeighbor | Where-Object { $_.State -notin "
            "'Unreachable','Incomplete' } | Select-Object IPAddress,LinkLayerAddress,"
            "InterfaceAlias,@{Name='Status';Expression={$_.State.ToString()}}); "
            "ConvertTo-Json -Compress -InputObject $items"
        )
        try:
            result = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
                capture_output=True,
                timeout=8,
                check=True,
                encoding="utf-8",
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            for row in json.loads(result.stdout):
                addr = ipaddress.ip_address(row["IPAddress"].split("%")[0])
                mac = row["LinkLayerAddress"]
                if addr.is_multicast or addr.is_loopback or not mac:
                    continue
                if mac.replace("-", "").upper() in {"FFFFFFFFFFFF", "000000000000"}:
                    continue
                items.append(
                    {
                        "ip": row["IPAddress"],
                        "mac": mac,
                        "interface": row["InterfaceAlias"],
                        "state": row["Status"],
                    }
                )
        except (OSError, subprocess.SubprocessError, ValueError):
            message = "无法读取 Windows 邻居缓存，请检查系统命令和读取权限。"
    elif sys.platform.startswith("linux"):
        source = "Linux /proc/net/arp"
        try:
            for line in Path("/proc/net/arp").read_text().splitlines()[1:]:
                ip, _, flags, mac, _, device = line.split()
                if int(flags, 16) & 2:
                    items.append({"ip": ip, "mac": mac, "interface": device, "state": "已解析"})
        except (OSError, ValueError):
            message = "当前系统无法读取 IPv4 ARP 缓存。"
    else:
        source = "系统邻居缓存"
        message = "当前平台暂不支持读取邻居缓存。"
    return {
        "source": source,
        "scope": "仅含本机邻居缓存中的条目，最近通信及缓存过期会改变结果。",
        "items": items,
        "message": message,
    }


def _address_text(address):
    if not address:
        return ""
    host = f"[{address.ip}]" if ":" in address.ip else address.ip
    return f"{host}:{address.port}"


def connections():
    message = ""
    items = []
    try:
        sockets = psutil.net_connections(kind="inet")
        for entry in sorted(sockets, key=lambda s: (not bool(s.raddr), s.status, s.laddr))[:250]:
            items.append(
                {
                    "protocol": "TCP" if entry.type == socket.SOCK_STREAM else "UDP",
                    "local": _address_text(entry.laddr),
                    "remote": _address_text(entry.raddr),
                    "status": entry.status,
                }
            )
        if len(sockets) > len(items):
            message = f"显示 {len(sockets)} 个本机套接字中的前 {len(items)} 个，已连接端点优先。"
    except (psutil.Error, OSError):
        message = "无法读取套接字快照，请检查操作系统权限。"
    return {"source": "psutil · 本机套接字快照", "items": items, "message": message}
