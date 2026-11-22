"""Manual integration test. Requires an installed Windows Npcap driver."""

import socket
import time

from fastapi import HTTPException
from scapy.all import conf
from sqlalchemy import create_engine

from netscope.packets import Capture, StartParams, capture_analysis


def main():
    engine = create_engine("sqlite://")
    capture = Capture(engine)
    loopback = next((i.name for i in conf.ifaces.values() if "loopback" in i.name.lower()), None)
    if not loopback:
        raise SystemExit("没有发现 Npcap 回环接口。请检查驱动安装。")
    with socket.socket() as tcp, socket.socket(type=socket.SOCK_DGRAM) as udp:
        tcp.bind(("127.0.0.1", 0))
        tcp.listen()
        udp.bind(("127.0.0.1", 0))
        ports = {"TCP": tcp.getsockname()[1], "UDP": udp.getsockname()[1]}
        try:
            capture.start(loopback, "tcp and (")
        except HTTPException as exc:
            assert exc.status_code == 422 and capture.worker is None
        else:
            raise AssertionError("捕获驱动应拒绝不完整表达式")
        capture.start(loopback, f"(tcp port {ports['TCP']}) or (udp port {ports['UDP']})")
        try:
            with (
                socket.create_connection(tcp.getsockname(), timeout=3) as client,
                tcp.accept()[0] as peer,
            ):
                client.sendall(b"NetScope")
                assert peer.recv(8) == b"NetScope"
            with socket.socket(type=socket.SOCK_DGRAM) as client:
                client.sendto(b"NetScope", udp.getsockname())
                assert udp.recv(8) == b"NetScope"
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                protocol_names = {entry["name"] for entry in capture.status()["protocols"]}
                if {"TCP", "UDP"}.issubset(protocol_names):
                    break
                time.sleep(0.05)
        finally:
            result = capture.stop()
        # Inspect a stopped snapshot so late TCP acknowledgements are included.
        counts = {
            name: sum(
                row["network"] == "IPv4"
                and row["src"] == row["dst"] == "127.0.0.1"
                and row["protocol"] == name
                and port in (row["sport"], row["dport"])
                and name in row["headers"]
                for row in capture.data.rows
            )
            for name, port in ports.items()
        }
        assert counts["TCP"] and counts["UDP"], counts
        assert result["state"] == "stopped", result["error"]
        assert result["total"] == sum(counts.values()), "捕获包含不匹配过滤器的报文"
        print(f"Windows Npcap BPF | IPv4/TCP {counts['TCP']} | IPv4/UDP {counts['UDP']} | stopped")
        # Reopen the same adapter. The receiver confirms both UDP datagrams arrived,
        # while the capture must observe only the control port selected by BPF.
        with (
            socket.socket(type=socket.SOCK_DGRAM) as excluded,
            socket.socket(type=socket.SOCK_DGRAM) as sender,
        ):
            excluded.bind(("127.0.0.1", 0))
            expression = StartParams(
                interface=loopback, protocol="UDP", ip="127.0.0.1", port=ports["UDP"]
            ).expression()
            capture.start(loopback, expression)
            try:
                for dest in (udp, excluded):
                    sender.sendto(b"NetScope", dest.getsockname())
                    assert dest.recv(8) == b"NetScope"
                deadline = time.monotonic() + 3
                while not capture.status()["total"] and time.monotonic() < deadline:
                    time.sleep(0.05)
                time.sleep(0.2)
            finally:
                stopped = capture.stop()
        analysis = capture_analysis(capture, scope="history", session_id=stopped["session_id"])
        assert stopped["state"] == "stopped" and stopped["total"] == 1
        assert analysis["total"] == 1 and analysis["flows"][0]["dport"] == ports["UDP"]
        assert analysis["flows"][0]["direction"] == "local"
        print("Restarted | delivered UDP 2 | matched 1 | excluded 1 | invalid BPF rejected")


if __name__ == "__main__":
    main()
