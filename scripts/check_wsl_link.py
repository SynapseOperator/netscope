"""Windows manual acceptance using an owned WSL2 NAT guest, without uploading test data."""

import argparse
import asyncio
import json
import secrets
import socket
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from sqlalchemy import URL, create_engine, select

# Run from a source checkout: python scripts/check_wsl_link.py
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from netscope.speed import SpeedTest, results
from netscope.telemetry import AlertRule, Monitor
from netscope.telemetry_store import alerts, minutes

# Only the standard library and peer.py are imported on the guest. The random key
# travels over the inherited pipe, outside process arguments, files and the report.
GUEST = """
import json, runpy, subprocess, sys, threading
p = runpy.run_path(sys.argv[1])
dev = json.loads(subprocess.check_output(["ip", "-j", "-4", "route", "show", "default"]))[0]["dev"]
addrs = json.loads(subprocess.check_output(["ip", "-j", "-4", "addr", "show", "dev", dev]))
address = next(a["local"] for a in addrs[0]["addr_info"] if a["scope"] == "global")
if sys.argv[2] == "localhost":
    address = "127.0.0.1"
with p["PeerServer"]((address, 0), sys.stdin.readline().strip()) as server:
    print(json.dumps(server.server_address), flush=True)
    def wait_for_close():
        sys.stdin.read()
        server.shutdown()
    threading.Thread(target=wait_for_close, daemon=True).start()
    watchdog = threading.Timer(45, server.shutdown)
    watchdog.daemon = True
    watchdog.start()
    server.serve_forever()
"""


async def check(engine, host, port, token, duration_s=None):
    # UDP connect resolves the local route without sending a datagram.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
        route.connect((host, port))
        local = route.getsockname()[0]
    monitor = Monitor(engine)
    await monitor.start()
    try:
        name = next(i["name"] for i in monitor.interfaces if local in i["ipv4"])
        monitor.select_interface(name)
        monitor.configure(AlertRule(rx_mbps=4, tx_mbps=4, consecutive=1, cooldown_s=3))
        await asyncio.sleep(2.3)
        baseline = monitor.snapshot()["latest"]
        assert baseline and baseline["rx_bps"] is not None
        test = SpeedTest(engine, monitor.log)
        test.start(
            f"http://{host}:{port}", token, "sustained" if duration_s else "quick", duration_s or 5
        )
        await test.task
        assert test.state["phase"] == "complete", test.state["error"]
        result = test.state["result"]
        via_localhost = host == "127.0.0.1"
        assert result["scope"] == ("loopback" if via_localhost else "lan")
        assert result["interface"] == name, "实际测速连接未匹配当前路由网卡"
        report = {
            "network": "Windows to WSL2 via localhost forwarding"
            if via_localhost
            else "Windows to WSL2 virtual LAN",
            "mode": result["mode"],
            "download_bytes": result["download_bytes"],
            "upload_bytes": result["upload_bytes"],
            "download_seconds": round(result["download_seconds"], 3),
            "upload_seconds": round(result["upload_seconds"], 3),
            "windows_interfaces": len(monitor.interfaces),
            "windows_interfaces_up": sum(i["up"] for i in monitor.interfaces),
            "http_latency_ms": round(result["latency_ms"], 2),
            "download_mbps": round(result["download_mbps"], 2),
            "upload_mbps": round(result["upload_mbps"], 2),
        }
        if result["mode"] == "quick":
            report["direction_payload_bytes"] = result["download_bytes"]
        else:
            assert result["loaded_samples"] > 1 and result["loaded_latency_ms"] > 0
            assert result["loaded_jitter_ms"] is not None
            report.update(
                requested_seconds=duration_s,
                limit_reached=result["limit_reached"],
                segments=len(result["segments"]),
                loaded_samples=result["loaded_samples"],
                loaded_rtt_ms=round(result["loaded_latency_ms"], 3),
                loaded_jitter_ms=round(result["loaded_jitter_ms"], 3),
            )
        if via_localhost:
            # Windows loopback counters need not count forwarded payload. This path
            # validates the authenticated measurement without claiming a vNIC alarm.
            return name, report
        # Wait for one high and one low reading. Alarms in other adapters can be
        # caused by unrelated host traffic and do not count toward this check.
        for _ in range(12):
            await asyncio.sleep(1)
            with engine.connect() as db:
                episodes = db.execute(
                    select(alerts.c.kind, alerts.c.end_reason).where(
                        alerts.c.interface == name,
                        alerts.c.kind.in_(("rx_rate", "tx_rate")),
                        alerts.c.ts > baseline["ts"],
                    )
                ).all()
            if {row.kind for row in episodes if row.end_reason == "recovered"} == {
                "tx_rate",
                "rx_rate",
            }:
                break
        after = [p for p in monitor.snapshot()["series"] if p["ts"] > baseline["ts"]]
        latest = after[-1]
        rx_change = latest["rx_bytes"] - baseline["rx_bytes"]
        tx_change = latest["tx_bytes"] - baseline["tx_bytes"]
        assert rx_change >= result["download_bytes"] and tx_change >= result["upload_bytes"]
        recovered = sorted({row.kind for row in episodes if row.end_reason == "recovered"})
        assert recovered == ["rx_rate", "tx_rate"], "测试网卡需有空闲时段验证恢复"
        report.update(
            {
                "counter_rx_delta_bytes": rx_change,
                "counter_tx_delta_bytes": tx_change,
                "baseline_rx_mbps": round(baseline["rx_bps"] / 1e6, 3),
                "baseline_tx_mbps": round(baseline["tx_bps"] / 1e6, 3),
                "peak_rx_mbps": round(max(p["rx_bps"] for p in after) / 1e6, 3),
                "peak_tx_mbps": round(max(p["tx_bps"] for p in after) / 1e6, 3),
                "recovered_alerts": recovered,
            }
        )
    finally:
        await monitor.stop()
    return name, report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--distro", default="Ubuntu")
    parser.add_argument(
        "--duration", type=int, choices=[5, 10], help="持续测速秒数，省略则执行原有快速模式"
    )
    parser.add_argument(
        "--localhost", action="store_true", help="使用 WSL 原生 localhost 转发，单独验证回环路径"
    )
    args = parser.parse_args()
    command = ["wsl.exe", "-d", args.distro, "--exec"]
    path = subprocess.check_output(
        command + ["wslpath", "-u", str(ROOT / "netscope" / "peer.py")], text=True, encoding="utf-8"
    ).strip()
    token = secrets.token_urlsafe(32)
    with subprocess.Popen(
        command + ["python3", "-u", "-c", GUEST, path, "localhost" if args.localhost else "nat"],
        text=True,
        encoding="utf-8",
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    ) as proc:
        try:
            proc.stdin.write(token + "\n")
            proc.stdin.flush()
            host, port = json.loads(proc.stdout.readline())
            with TemporaryDirectory(prefix="netscope-check-") as temp:
                url = URL.create("sqlite", database=str(Path(temp) / "check.sqlite"))
                engine = create_engine(url)
                try:
                    name, report = asyncio.run(check(engine, host, port, token, args.duration))
                finally:
                    engine.dispose()
                reopened = create_engine(url)
                with reopened.connect() as db:
                    persisted = db.execute(
                        select(minutes.c.ts).where(minutes.c.interface == name)
                    ).all()
                    assert persisted and db.execute(select(results.c.id)).first()
                    report["persisted_minutes_after_reopen"] = len(persisted)
                reopened.dispose()
                print(json.dumps(report, indent=2))
        finally:
            proc.stdin.close()
            proc.wait(timeout=50)


if __name__ == "__main__":
    main()
