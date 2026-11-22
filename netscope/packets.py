"""Bounded header capture from a local Scapy socket or a classic PCAP stream."""

import struct
import sys
import threading
import time
from collections import deque
from io import BytesIO
from typing import Annotated

import psutil
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field, IPvAnyAddress
from scapy.all import ARP, ICMP, IP, TCP, UDP, IPv6, PcapReader, conf
from scapy.error import Scapy_Exception
from scapy.layers.inet6 import (
    IPv6ExtHdrDestOpt,
    IPv6ExtHdrFragment,
    IPv6ExtHdrHopByHop,
    IPv6ExtHdrRouting,
)
from scapy.packet import NoPayload
from sqlalchemy import JSON, Column, Float, Integer, MetaData, String, Table, select
from starlette.concurrency import run_in_threadpool

CAPACITY = 500
MAX_ENDPOINTS = 128
MAX_FILE = 8 * 1024 * 1024
MAX_RECORDS = 10_000
MAX_SESSIONS = 100
DRIVER_NOTE = "Windows 实时抓包需要 Npcap。请安装驱动并重启 NetScope，或导入 PCAP。"
OPEN_ERROR = "无法读取该接口。请检查网卡连接、Npcap 服务和当前账户的抓包权限。"
metadata = MetaData()
sessions = Table(
    "capture_sessions",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("source", String, nullable=False),
    Column("interface", String),
    Column("started_at", Float, nullable=False),
    Column("ended_at", Float, nullable=False),
    Column("total", Integer, nullable=False),
    Column("bytes", Integer, nullable=False),
    Column("protocols", JSON, nullable=False),
    Column("endpoints", JSON, nullable=False),
)
router = APIRouter(prefix="/capture", tags=["capture"])
extensions = (IPv6ExtHdrDestOpt, IPv6ExtHdrFragment, IPv6ExtHdrHopByHop, IPv6ExtHdrRouting)


def packet_headers(packet):
    # Walk from the outside in. An ICMP error may quote a different TCP/IP packet.
    layer = packet
    while not isinstance(layer, (IP, IPv6, ARP, NoPayload)):
        layer = layer.payload
    network, protocol, src, dst = "Other", "Other", "", ""
    sport = dport = None
    headers = {}
    if isinstance(layer, (IP, IPv6)):
        src, dst = layer.src, layer.dst
        if isinstance(layer, IP):
            network = "IPv4"
            headers[network] = {
                "Version": 4,
                "Header length (B)": layer.ihl * 4,
                "Total length": layer.len,
                "TTL": layer.ttl,
                "Protocol": layer.proto,
                "ID": layer.id,
                "Flags": str(layer.flags),
                "Fragment offset": layer.frag,
                "DS field": layer.tos,
                "Checksum": layer.chksum,
            }
            next_header = layer.proto
        else:
            network = "IPv6"
            headers[network] = {
                "Version": 6,
                "Traffic class": layer.tc,
                "Flow label": layer.fl,
                "Payload length": layer.plen,
                "Next header": layer.nh,
                "Hop limit": layer.hlim,
            }
            next_header = layer.nh
        headers[network].update({"Source": src, "Destination": dst})
        transport = layer.payload
        while isinstance(transport, extensions):
            next_header = transport.nh
            transport = transport.payload
        if isinstance(transport, (TCP, UDP)):
            sport, dport = transport.sport, transport.dport
            protocol = "TCP" if isinstance(transport, TCP) else "UDP"
            fields = {"Source port": sport, "Destination port": dport, "Checksum": transport.chksum}
            if protocol == "TCP":
                fields.update(
                    {
                        "Sequence": transport.seq,
                        "Acknowledgment": transport.ack,
                        "Header length (B)": transport.dataofs * 4,
                        "Flags": str(transport.flags),
                        "Window": transport.window,
                        "Urgent pointer": transport.urgptr,
                    }
                )
            else:
                fields["Length"] = transport.len
            headers[protocol] = fields
        elif isinstance(transport, ICMP):
            protocol = "ICMP"
            headers[protocol] = {
                "Type": transport.type,
                "Code": transport.code,
                "Checksum": transport.chksum,
            }
        elif network == "IPv6" and next_header == 58 and hasattr(transport, "type"):
            protocol = "ICMPv6"
            headers[protocol] = {"Type": transport.type, "Code": transport.code}
    elif isinstance(layer, ARP):
        network, src, dst = "ARP", str(layer.psrc), str(layer.pdst)
        headers["ARP"] = {"Operation": layer.op, "Source": src, "Destination": dst}
    return {
        "timestamp": float(packet.time),
        "network": network,
        "protocol": protocol,
        "src": src,
        "dst": dst,
        "sport": sport,
        "dport": dport,
        "length": packet.wirelen if packet.wirelen is not None else len(packet),
        "headers": headers,
    }


class Observations:
    def __init__(self):
        self.rows = deque(maxlen=CAPACITY)
        self.total = 0
        self.bytes = 0
        self.protocols = {}
        self.endpoints = {}

    def add(self, packet):
        row = packet_headers(packet)
        self.total += 1
        row["id"] = self.total
        self.bytes += row["length"]
        self.rows.append(row)
        protocol = row["network"] if row["network"] == "ARP" else row["protocol"]
        keys = [(self.protocols, protocol)]
        for address in {row["src"], row["dst"]} - {""}:
            if address not in self.endpoints and len(self.endpoints) >= MAX_ENDPOINTS:
                address = "其他端点"
            keys.append((self.endpoints, address))
        for counts, name in keys:
            entry = counts.setdefault(name, {"name": name, "packets": 0, "bytes": 0})
            entry["packets"] += 1
            entry["bytes"] += row["length"]

    def summary(self):
        def ranked(counts):
            return sorted((entry.copy() for entry in counts.values()), key=lambda e: -e["bytes"])

        return {
            "total": self.total,
            "bytes": self.bytes,
            "protocols": ranked(self.protocols),
            "endpoints": ranked(self.endpoints),
        }


def import_pcap(data):
    # PcapReader accepts truncated records silently. Check classic-PCAP framing first.
    magic = bytes(data[:4])
    formats = {
        b"\xd4\xc3\xb2\xa1": "<",
        b"\xa1\xb2\xc3\xd4": ">",
        b"\x4d\x3c\xb2\xa1": "<",
        b"\xa1\xb2\x3c\x4d": ">",
    }
    if magic not in formats or len(data) < 24:
        raise HTTPException(422, "请选择未压缩的标准 PCAP 文件。PCAPNG 可用 Wireshark 另存为 PCAP。")
    endian = formats[magic]
    major, minor = struct.unpack_from(endian + "HH", data, 4)
    snaplen, linktype = struct.unpack_from(endian + "II", data, 16)
    if (major, minor) != (2, 4) or snaplen == 0 or linktype not in conf.l2types.num2layer:
        raise HTTPException(422, "不支持此 PCAP 版本或链路层类型。")
    pos, records = 24, 0
    while pos < len(data):
        if len(data) - pos < 16:
            raise HTTPException(422, "PCAP 记录头不完整。")
        captured, wire = struct.unpack_from(endian + "II", data, pos + 8)
        pos += 16 + captured
        if pos > len(data) or captured > wire or captured > snaplen:
            raise HTTPException(422, "PCAP 记录长度无效或文件被截断。")
        records += 1
        if records > MAX_RECORDS:
            raise HTTPException(413, "单次最多导入 10000 个报文。")
    observations = Observations()
    with PcapReader(BytesIO(data)) as reader:
        for packet in reader:
            observations.add(packet)
    return observations


class Capture:
    def __init__(self, engine):
        self.engine = engine
        metadata.create_all(engine)
        self.control = threading.RLock()
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.worker = None
        self.data = Observations()
        self.source = self.interface = self.error = None
        self.state = "idle"
        self.started_at = 0.0

    @property
    def available(self):
        return sys.platform != "win32" or bool(conf.use_pcap)

    def status(self):
        with self.lock:
            return {
                "state": self.state,
                "source": self.source,
                "interface": self.interface,
                "available": self.available,
                "error": self.error,
                "driver_note": None if self.available else DRIVER_NOTE,
                "capacity": CAPACITY,
                **self.data.summary(),
            }

    def _listen(self, sock, check_link):
        next_check = time.monotonic() + 2
        try:
            with sock:
                while not self.stop_event.is_set():
                    if check_link and time.monotonic() >= next_check:
                        stats = psutil.net_if_stats().get(self.interface)
                        if stats is None or not stats.isup:
                            with self.lock:
                                self.error, self.state = (
                                    "接口已断开，请检查连接后重新开始抓包。",
                                    "error",
                                )
                            return
                        next_check = time.monotonic() + 2
                    if sock.select([sock], remain=0.15):
                        packet = sock.recv()
                        if packet is not None:
                            with self.lock:
                                self.data.add(packet)
        except (OSError, EOFError, Scapy_Exception, ValueError):
            with self.lock:
                self.error, self.state = OPEN_ERROR, "error"

    def start(self, interface):
        with self.control:
            if self.worker:
                if self.worker.is_alive():
                    raise HTTPException(409, "已有抓包任务正在运行。")
                self.stop()
            if not self.available:
                with self.lock:
                    self.error, self.state = DRIVER_NOTE, "error"
                raise HTTPException(503, DRIVER_NOTE)
            iface = next((item for item in conf.ifaces.values() if item.name == interface), None)
            if iface is None:
                raise HTTPException(422, "该接口不在当前抓包设备列表中。")
            try:
                link = psutil.net_if_stats().get(interface)
                if link and not link.isup:
                    with self.lock:
                        self.error, self.state = "所选网卡未连接，请选择已启用的接口。", "error"
                    raise HTTPException(409, self.error)
                sock = iface.l2listen()(iface=iface, promisc=False)
            except (OSError, Scapy_Exception, RuntimeError, ValueError):
                with self.lock:
                    self.error, self.state = OPEN_ERROR, "error"
                raise HTTPException(503, OPEN_ERROR) from None
            with self.lock:
                self.data, self.source, self.state = Observations(), "live", "running"
                self.interface, self.error, self.started_at = interface, None, time.time()
            self.stop_event.clear()
            self.worker = threading.Thread(
                target=self._listen, args=(sock, link is not None), name="netscope-capture", daemon=True
            )
            self.worker.start()
            return self.status()

    def _persist(self, summary, source, interface, started):
        with self.engine.begin() as conn:
            conn.execute(
                sessions.insert().values(
                    **summary,
                    source=source,
                    interface=interface,
                    started_at=started,
                    ended_at=time.time(),
                )
            )
            newest = select(sessions.c.id).order_by(sessions.c.id.desc()).limit(MAX_SESSIONS)
            conn.execute(sessions.delete().where(sessions.c.id.not_in(newest)))

    def stop(self):
        with self.control:
            if self.worker is not None:
                self.stop_event.set()
                self.worker.join()
                with self.lock:
                    if self.state == "running":
                        self.state = "stopped"
                    summary = self.data.summary()
                self._persist(summary, "live", self.interface, self.started_at)
                self.worker = None
            return self.status()

    def close(self):
        self.stop()

    def load(self, raw):
        with self.control:
            if self.worker and self.worker.is_alive():
                raise HTTPException(409, "请先停止当前抓包，再导入 PCAP。")
            if self.worker:
                self.stop()
            started = time.time()
            data = import_pcap(raw)
            self._persist(data.summary(), "pcap", None, started)
            with self.lock:
                self.data, self.source, self.state = data, "pcap", "imported"
                self.interface, self.error, self.started_at = None, None, started
            return self.status()


class StartParams(BaseModel):
    interface: str = Field(min_length=1, max_length=256)


@router.get("")
def status(request: Request):
    return request.app.state.capture.status()


@router.get("/interfaces")
def interfaces(request: Request):
    if not request.app.state.capture.available:
        return []
    links = psutil.net_if_stats()
    result = [
        {
            "name": item.name,
            "description": item.description,
            "is_up": links[item.name].isup if item.name in links else None,
        }
        for item in conf.ifaces.values()
    ]
    return sorted(result, key=lambda item: (item["is_up"] is not True, item["name"]))


@router.post("/start")
def start(params: StartParams, request: Request):
    return request.app.state.capture.start(params.interface)


@router.post("/stop")
def stop(request: Request):
    return request.app.state.capture.stop()


@router.post("/import")
async def upload(request: Request):
    raw = bytearray()
    async for chunk in request.stream():
        if len(raw) + len(chunk) > MAX_FILE:
            raise HTTPException(413, "PCAP 文件最大为 8 MiB。")
        raw.extend(chunk)
    return await run_in_threadpool(request.app.state.capture.load, raw)


@router.get("/packets")
def packets(
    request: Request,
    ip: IPvAnyAddress | None = None,
    port: Annotated[int | None, Query(ge=0, le=65535)] = None,
    protocol: Annotated[str, Query(max_length=12)] = "",
    limit: Annotated[int, Query(ge=1, le=CAPACITY)] = 100,
):
    capture = request.app.state.capture
    protocol = protocol.lower()
    if protocol not in {"", "ip", "ipv4", "ipv6", "arp", "tcp", "udp", "icmp", "icmpv6", "other"}:
        raise HTTPException(422, "未知协议过滤器。")
    with capture.lock:
        rows = list(reversed(capture.data.rows))
    address = str(ip) if ip is not None else None
    result = []
    for row in rows:
        if address and address not in (row["src"], row["dst"]):
            continue
        if port is not None and port not in (row["sport"], row["dport"]):
            continue
        layers = {row["network"].lower(), row["protocol"].lower()}
        if row["network"] in {"IPv4", "IPv6"}:
            layers.add("ip")
        if protocol and protocol not in layers:
            continue
        result.append(row)
        if len(result) == limit:
            break
    return result


@router.get("/history")
def history(request: Request, start: float | None = None, end: float | None = None):
    if start is not None and end is not None and end < start:
        raise HTTPException(422, "结束时间应晚于开始时间。")
    query = select(sessions).order_by(sessions.c.id.desc()).limit(MAX_SESSIONS)
    if start is not None:
        query = query.where(sessions.c.started_at >= start)
    if end is not None:
        query = query.where(sessions.c.started_at <= end)
    with request.app.state.capture.engine.connect() as conn:
        return [dict(row) for row in conn.execute(query).mappings()]
