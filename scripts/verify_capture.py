"""Manual integration test. Requires an installed Windows Npcap driver."""

import socket
import time

from scapy.all import conf
from sqlalchemy import create_engine

from netscope.packets import Capture


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
        capture.start(loopback)
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
            counts = {}
            while time.monotonic() < deadline:
                with capture.lock:
                    records = list(capture.data.rows)
                counts = {
                    name: sum(
                        row["network"] == "IPv4"
                        and row["src"] == row["dst"] == "127.0.0.1"
                        and row["protocol"] == name
                        and port in (row["sport"], row["dport"])
                        and name in row["headers"]
                        for row in records
                    )
                    for name, port in ports.items()
                }
                if all(counts.values()):
                    break
                time.sleep(0.05)
        finally:
            result = capture.stop()
        assert counts["TCP"] and counts["UDP"], counts
        assert result["state"] == "stopped", result["error"]
        print(f"Windows Npcap OK | IPv4/TCP {counts['TCP']} | IPv4/UDP {counts['UDP']} | stopped")


if __name__ == "__main__":
    main()
