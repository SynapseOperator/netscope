"""Bounded header capture from a local Scapy socket or a classic PCAP stream."""

import socket
import struct
import sys
import threading
import time
from collections import deque
from io import BytesIO
from typing import Annotated, Literal

import psutil
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress
from scapy.all import ARP, ICMP, IP, TCP, UDP, IPv6, PcapReader, conf
from scapy.error import Scapy_Exception
from scapy.layers.inet6 import (
    IPv6ExtHdrDestOpt,
    IPv6ExtHdrFragment,
    IPv6ExtHdrHopByHop,
    IPv6ExtHdrRouting,
    IPv6ExtHdrSegmentRouting,
)
from scapy.layers.ipsec import AH
from scapy.packet import NoPayload
from sqlalchemy import JSON, Column, Float, Integer, MetaData, String, Table, func, inspect, select
from starlette.concurrency import run_in_threadpool

from .flows import Analysis, FlowWindow, flow_id, flow_key, matches_protocol, tables

CAPACITY = 500
MAX_ENDPOINTS = 128
MAX_FILE = 8 * 1024 * 1024
MAX_RECORDS = 10_000
MAX_SESSIONS = 100
DETAIL_RETENTION_DAYS = 30
UtcQuery = Annotated[float | None, Query(allow_inf_nan=False, ge=0, le=253402300799)]
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
analysis_sessions, analysis_seconds = tables(metadata)
router = APIRouter(prefix="/capture", tags=["capture"])
extensions = (
    IPv6ExtHdrDestOpt,
    IPv6ExtHdrFragment,
    IPv6ExtHdrHopByHop,
    IPv6ExtHdrRouting,
    IPv6ExtHdrSegmentRouting,
    AH,
)


def supports_bpf(factory):
    # Scapy providers may accept **kwargs while ignoring them. Enable filtering
    # only for implementations known to attach the compiled program to the socket.
    from scapy.arch import libpcap

    if factory is getattr(libpcap, "L2pcapListenSocket", None) or factory is getattr(
        libpcap, "L2pcapSocket", None
    ):
        return True
    if sys.platform.startswith("linux"):
        from scapy.arch.linux import L2ListenSocket, L2Socket

        return factory in (L2ListenSocket, L2Socket)
    return False


def packet_headers(packet, local_ips=None):
    # Walk from the outside in. An ICMP error may quote a different TCP/IP packet.
    layer = packet
    while not isinstance(layer, (IP, IPv6, ARP, NoPayload)):
        layer = layer.payload
    network, protocol, src, dst = "Other", "Other", "", ""
    sport = dport = None
    headers = {}
    kind, fragmented = "link", False
    direction = "unknown"
    if isinstance(layer, (IP, IPv6)):
        src, dst = layer.src, layer.dst
        kind = "network"
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
            fragmented = bool(layer.frag or layer.flags.MF)
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
            if isinstance(transport, IPv6ExtHdrFragment):
                fragmented = bool(transport.offset or transport.m)
                headers["IPv6 Fragment"] = {
                    "ID": transport.id,
                    "Offset": transport.offset,
                    "More fragments": int(transport.m),
                    "Next header": transport.nh,
                }
            next_header = transport.nh
            transport = transport.payload
        # Only trust an IP protocol number when no complete transport header exists.
        protocol = {6: "TCP", 17: "UDP"}.get(next_header, "Other")
        if next_header == (1 if network == "IPv4" else 58):
            protocol = "ICMP" if network == "IPv4" else "ICMPv6"
        if isinstance(transport, (TCP, UDP)):
            kind = "transport"
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
            kind, protocol = "control", "ICMP"
            headers[protocol] = {
                "Type": transport.type,
                "Code": transport.code,
                "Checksum": transport.chksum,
            }
        elif network == "IPv6" and next_header == 58 and hasattr(transport, "type"):
            kind, protocol = "control", "ICMPv6"
            headers[protocol] = {"Type": transport.type, "Code": transport.code}
        if fragmented:
            kind = "fragment"
    elif isinstance(layer, ARP):
        kind, network, protocol = "arp", "ARP", "ARP"
        if (
            layer.ptype in (0x0800, 0x86DD)
            and isinstance(layer.psrc, str)
            and isinstance(layer.pdst, str)
        ):
            src, dst = layer.psrc, layer.pdst
        headers["ARP"] = {"Operation": layer.op, "Source": src, "Destination": dst}
    if src and dst and local_ips:
        here, there = src in local_ips, dst in local_ips
        direction = (
            "local" if here and there else "outbound" if here else "inbound" if there else "other"
        )
    captured_length = len(packet.original) if packet.original else len(packet)
    wire_length = packet.wirelen if packet.wirelen is not None else captured_length
    return {
        "captured_length": captured_length,
        "truncated": wire_length > captured_length,
        "kind": kind,
        "direction": direction,
        "timestamp": float(packet.time),
        "network": network,
        "protocol": protocol,
        "src": src,
        "dst": dst,
        "sport": sport,
        "dport": dport,
        "length": wire_length,
        "headers": headers,
    }


class Observations:
    def __init__(self, local_ips=None):
        self.local_ips = local_ips
        self.window = FlowWindow()
        self.rows = deque(maxlen=CAPACITY)
        self.total = 0
        self.bytes = 0
        self.protocols = {}
        self.endpoints = {}

    def add(self, packet):
        row = packet_headers(packet, self.local_ips)
        key = flow_key(row)
        row["flow_id"] = flow_id(key)
        self.window.add(row, key)
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
    ns_resolution = magic in {b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}
    fraction_limit = 1_000_000_000 if ns_resolution else 1_000_000
    pos, records = 24, 0
    while pos < len(data):
        if len(data) - pos < 16:
            raise HTTPException(422, "PCAP 记录头不完整。")
        subsecond, captured, wire = struct.unpack_from(endian + "III", data, pos + 4)
        if subsecond >= fraction_limit:
            raise HTTPException(422, "PCAP 报文时间戳的小数部分无效。")
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
        with engine.begin() as conn:
            existing = {c["name"] for c in inspect(conn).get_columns(analysis_sessions.name)}
            for column in ("expired_at", "saved_at"):
                if column not in existing:
                    conn.exec_driver_sql(
                        f"ALTER TABLE capture_analysis_sessions ADD COLUMN {column} FLOAT"
                    )
        self.control = threading.RLock()
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.worker = None
        self.data = Observations()
        self.source = self.interface = self.error = None
        self.bpf = self.session_id = None
        self.state = "idle"
        self.started_at = 0.0
        self.ended_at = None
        self.detail_expired = False
        self.next_prune = 0
        self.prune_expired()

    def prune_expired(self):
        """Sweep on startup and use; wake at the next saved session expiry or within one day."""
        now = time.time()
        with self.control:
            if now < self.next_prune:
                return
            lifetime = DETAIL_RETENTION_DAYS * 86400
            current_expired_at = None
            with self.engine.begin() as conn:
                joined = sessions.join(
                    analysis_sessions, sessions.c.id == analysis_sessions.c.session_id
                )
                # Early v1.1 schemas timestamped ended_at on commit, exactly when they were saved.
                saved = func.coalesce(analysis_sessions.c.saved_at, sessions.c.ended_at)
                expired = select(sessions.c.id).select_from(joined).where(saved <= now - lifetime)
                conn.execute(
                    analysis_seconds.delete().where(analysis_seconds.c.session_id.in_(expired))
                )
                conn.execute(
                    analysis_sessions.update()
                    .where(
                        analysis_sessions.c.session_id.in_(expired),
                        analysis_sessions.c.expired_at.is_(None),
                    )
                    .values(expired_at=now, bpf=None, discarded_before=None)
                )
                oldest = conn.scalar(
                    select(func.min(saved))
                    .select_from(joined)
                    .where(analysis_sessions.c.expired_at.is_(None))
                )
                if self.session_id is not None and not self.detail_expired:
                    current_expired_at = conn.scalar(
                        select(analysis_sessions.c.expired_at).where(
                            analysis_sessions.c.session_id == self.session_id
                        )
                    )
            if current_expired_at is not None:
                with self.lock:
                    self.data.window.seconds.clear()
                    self.data.window.incomplete.clear()
                    self.data.rows.clear()
                    self.bpf = None
                    self.detail_expired = True
            self.next_prune = min(now + 86400, oldest + lifetime) if oldest is not None else now + 86400

    @property
    def available(self):
        return sys.platform != "win32" or bool(conf.use_pcap)

    def status(self):
        self.prune_expired()
        with self.lock:
            return {
                "state": self.state,
                "bpf": self.bpf,
                "session_id": self.session_id,
                "source": self.source,
                "interface": self.interface,
                "available": self.available,
                "error": self.error,
                "driver_note": None if self.available else DRIVER_NOTE,
                "capacity": CAPACITY,
                "detail_retention_days": DETAIL_RETENTION_DAYS,
                "detail_expired": self.detail_expired,
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
        finally:
            with self.lock:
                self.ended_at = time.time()

    def start(self, interface, bpf=""):
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
                local_ips = {
                    a.address.split("%")[0]
                    for a in psutil.net_if_addrs().get(interface, ())
                    if a.family in (socket.AF_INET, socket.AF_INET6)
                }
                factory = iface.l2listen()
                if bpf and not supports_bpf(factory):
                    note = "当前捕获后端不支持已验证的 BPF 过滤。请安装 Npcap/libpcap 并重启服务。"
                    with self.lock:
                        self.error, self.state = note, "error"
                    raise HTTPException(503, note)
                started = time.time()
                sock = factory(iface=iface, promisc=False, filter=bpf or None)
            except (Scapy_Exception, ImportError) as exc:
                message = str(exc).lower()
                if bpf and "filter" in message:
                    missing = "libpcap is not available" in message
                    note = (
                        "系统缺少可编译捕获过滤器的 libpcap/Npcap。"
                        if missing
                        else "捕获驱动拒绝了 BPF，请检查语法以及接口的链路类型。"
                    )
                    with self.lock:
                        self.error, self.state = note, "error"
                    raise HTTPException(503 if missing else 422, note) from None
                with self.lock:
                    self.error, self.state = OPEN_ERROR, "error"
                raise HTTPException(503, OPEN_ERROR) from None
            except (OSError, RuntimeError, ValueError):
                with self.lock:
                    self.error, self.state = OPEN_ERROR, "error"
                raise HTTPException(503, OPEN_ERROR) from None
            with self.lock:
                self.data, self.source, self.state = Observations(local_ips), "live", "running"
                self.bpf, self.session_id = bpf, None
                self.detail_expired = False
                self.interface, self.error, self.started_at = interface, None, started
                self.ended_at = None
            self.stop_event.clear()
            self.worker = threading.Thread(
                target=self._listen, args=(sock, link is not None), name="netscope-capture", daemon=True
            )
            self.worker.start()
            return self.status()

    def _persist(self, data, source, interface, started, bpf, ended=None):
        self.prune_expired()
        window = data.window
        saved = time.time()
        with self.engine.begin() as conn:
            inserted = conn.execute(
                sessions.insert().values(
                    **data.summary(),
                    source=source,
                    interface=interface,
                    started_at=started,
                    ended_at=ended if ended is not None else saved,
                )
            )
            session_id = inserted.inserted_primary_key[0]
            conn.execute(
                analysis_sessions.insert().values(
                    session_id=session_id,
                    bpf=bpf,
                    saved_at=saved,
                    observed_start=window.observed_start,
                    observed_end=window.observed_end,
                    discarded_before=window.discarded_before,
                )
            )
            records = [dict(record, session_id=session_id) for record in window.records()]
            if records:
                conn.execute(analysis_seconds.insert(), records)
            newest = select(sessions.c.id).order_by(sessions.c.id.desc()).limit(MAX_SESSIONS)
            conn.execute(analysis_seconds.delete().where(analysis_seconds.c.session_id.not_in(newest)))
            conn.execute(
                analysis_sessions.delete().where(analysis_sessions.c.session_id.not_in(newest))
            )
            conn.execute(sessions.delete().where(sessions.c.id.not_in(newest)))
        return session_id

    def stop(self):
        with self.control:
            if self.worker is not None:
                self.stop_event.set()
                self.worker.join()
                with self.lock:
                    if self.state == "running":
                        self.state = "stopped"
                session_id = self._persist(
                    self.data, "live", self.interface, self.started_at, self.bpf, ended=self.ended_at
                )
                with self.lock:
                    self.session_id = session_id
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
            session_id = self._persist(data, "pcap", None, started, None)
            with self.lock:
                self.data, self.source, self.state = data, "pcap", "imported"
                self.bpf, self.session_id = None, session_id
                self.detail_expired = False
                self.interface, self.error, self.started_at = None, None, started
                self.ended_at = None
            return self.status()


class StartParams(BaseModel):
    model_config = ConfigDict(extra="forbid")
    interface: str = Field(min_length=1, max_length=256)
    protocol: Literal["TCP", "UDP", "ICMP", "ICMPv6", "IP", "IPv4", "IPv6", "ARP"] | None = None
    ip: IPvAnyAddress | None = None
    port: int | None = Field(default=None, ge=0, le=65535)
    bpf: str = Field(default="", max_length=256)

    def expression(self):
        advanced = self.bpf.strip()
        if advanced and (not self.bpf.isascii() or not self.bpf.isprintable()):
            raise HTTPException(422, "BPF 表达式只能使用可打印的 ASCII 字符。")
        if advanced and (self.protocol or self.ip or self.port is not None):
            raise HTTPException(422, "请选择预设过滤或高级 BPF 中的一种。")
        if advanced:
            return advanced
        if self.port is not None and self.protocol in ("ICMP", "ICMPv6", "ARP"):
            raise HTTPException(422, "所选协议没有传输层端口，请清空端口或选择 TCP/UDP。")
        terms = []
        if self.protocol:
            terms.append(
                {
                    "TCP": "tcp",
                    "UDP": "udp",
                    "ICMP": "icmp",
                    "ICMPv6": "icmp6",
                    "IP": "(ip or ip6)",
                    "IPv4": "ip",
                    "IPv6": "ip6",
                    "ARP": "arp",
                }[self.protocol]
            )
        if self.ip:
            terms.append(f"host {str(self.ip).split('%', 1)[0]}")
        if self.port is not None:
            terms.append(f"port {self.port}")
        return " and ".join(terms)


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
    return request.app.state.capture.start(params.interface, params.expression())


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
    flow_id: Annotated[str | None, Query(pattern="^[a-f0-9]{24}$")] = None,
    direction: Literal["", "inbound", "outbound", "local", "other", "unknown"] = "",
    start: UtcQuery = None,
    end: UtcQuery = None,
):
    capture = request.app.state.capture
    protocol = protocol.lower()
    if protocol not in {"", "ip", "ipv4", "ipv6", "arp", "tcp", "udp", "icmp", "icmpv6", "other"}:
        raise HTTPException(422, "未知协议过滤器。")
    capture.prune_expired()
    with capture.lock:
        rows = list(reversed(capture.data.rows))
    if start is not None and end is not None and end <= start:
        raise HTTPException(422, "结束时间应晚于开始时间。")
    address = str(ip).split("%", 1)[0] if ip is not None else None
    result = []
    for row in rows:
        if (
            flow_id is not None
            and row["flow_id"] != flow_id
            or direction
            and row["direction"] != direction
        ):
            continue
        if (
            start is not None
            and row["timestamp"] < start
            or end is not None
            and row["timestamp"] >= end
        ):
            continue
        if address and address not in (row["src"], row["dst"]):
            continue
        if port is not None and port not in (row["sport"], row["dport"]):
            continue
        if not matches_protocol(row["network"], row["protocol"], protocol):
            continue
        result.append(row)
        if len(result) == limit:
            break
    return result


def session_list():
    return select(
        sessions,
        analysis_sessions.c.session_id.label("analysis_id"),
        analysis_sessions.c.bpf,
        analysis_sessions.c.observed_start,
        analysis_sessions.c.observed_end,
        analysis_sessions.c.discarded_before,
        analysis_sessions.c.expired_at,
        analysis_sessions.c.saved_at,
    ).outerjoin(analysis_sessions, sessions.c.id == analysis_sessions.c.session_id)


def overlaps(source, observed_start, observed_end, started, ended, start, end):
    # Classic PCAP has no authoritative host interface. Its import time and packet
    # clock may be years apart, so only packet timestamps establish PCAP overlap.
    if source == "live":
        # Capture activity is a half-open interval. A quiet NIC or a restrictive BPF
        # can leave whole intervals without a packet, even when a session existed.
        return (start is None or ended > start) and (end is None or started < end)
    return (start is None or observed_end is not None and observed_end >= start) and (
        end is None or observed_start is not None and observed_start < end
    )


@router.get("/history")
def history(
    request: Request,
    start: UtcQuery = None,
    end: UtcQuery = None,
    interface: str | None = None,
    time_basis: Literal["session", "observed"] = "session",
):
    if (
        start is not None
        and end is not None
        and (end < start or end == start and time_basis == "observed")
    ):
        raise HTTPException(422, "结束时间应晚于开始时间。")
    request.app.state.capture.prune_expired()
    query = session_list().order_by(sessions.c.id.desc()).limit(MAX_SESSIONS)
    if interface is not None:
        query = query.where(sessions.c.interface == interface, sessions.c.source == "live")
    if time_basis == "session":
        if start is not None:
            query = query.where(sessions.c.started_at >= start)
        if end is not None:
            query = query.where(sessions.c.started_at <= end)
    with request.app.state.capture.engine.connect() as conn:
        return [
            dict(row)
            for row in conn.execute(query).mappings()
            if time_basis == "session"
            or overlaps(
                row["source"],
                row["observed_start"],
                row["observed_end"],
                row["started_at"],
                row["ended_at"],
                start,
                end,
            )
        ]


def capture_analysis(
    capture,
    *,
    scope="current",
    session_id=None,
    interface=None,
    start=None,
    end=None,
    protocol="",
    direction="",
    limit=10,
    ip=None,
):
    if start is not None and end is not None and end <= start:
        raise HTTPException(422, "结束时间应晚于开始时间。")
    if protocol.lower() not in {
        "",
        "ip",
        "ipv4",
        "ipv6",
        "arp",
        "tcp",
        "udp",
        "icmp",
        "icmpv6",
        "other",
    }:
        raise HTTPException(422, "未知协议过滤器。")
    output = Analysis(
        start, end, protocol, direction, limit, str(ip).split("%")[0] if ip is not None else None
    )
    history = scope == "history" or session_id is not None
    capture.prune_expired()
    with capture.control:
        # Take the in-memory snapshot while the worker owns mutable counters. A
        # stopping session is either included here or loaded from SQLite, once.
        with capture.lock:
            source, name = capture.source, capture.interface
            window = capture.data.window
            use_current = (
                source is not None
                and (interface is None or source == "live" and name == interface)
                and (not history or session_id is None and capture.worker is not None)
                and overlaps(
                    source,
                    window.observed_start,
                    window.observed_end,
                    capture.started_at,
                    capture.ended_at if capture.ended_at is not None else time.time(),
                    start,
                    end,
                )
            )
            if use_current:
                output.session(
                    capture.session_id,
                    source,
                    False,
                    window.observed_start,
                    window.discarded_before,
                    capture.bpf,
                    expired=capture.detail_expired,
                )
                current = list(window.records(start, end))
            else:
                current = []
        for record in current:
            output.add_bucket(**record)
        if history:
            query = session_list()
            if session_id is not None:
                query = query.where(sessions.c.id == session_id)
            if interface is not None:
                query = query.where(sessions.c.interface == interface, sessions.c.source == "live")
            retained = []
            with capture.engine.connect() as conn:
                for row in conn.execute(query).mappings():
                    legacy = row["analysis_id"] is None
                    explicit_legacy_pcap = legacy and session_id is not None and row["source"] == "pcap"
                    if not explicit_legacy_pcap and not overlaps(
                        row["source"],
                        row["observed_start"],
                        row["observed_end"],
                        row["started_at"],
                        row["ended_at"],
                        start,
                        end,
                    ):
                        continue
                    output.session(
                        row["id"],
                        row["source"],
                        legacy,
                        row["observed_start"],
                        row["discarded_before"],
                        row["bpf"],
                        expired=row["expired_at"] is not None,
                    )
                    if not legacy and row["expired_at"] is None:
                        retained.append(row["id"])
                if retained:
                    data_query = select(
                        analysis_seconds.c.second,
                        analysis_seconds.c.cells,
                        analysis_seconds.c.incomplete,
                    ).where(analysis_seconds.c.session_id.in_(retained))
                    if start is not None:
                        data_query = data_query.where(analysis_seconds.c.second >= int(start // 1))
                    if end is not None:
                        data_query = data_query.where(analysis_seconds.c.second < end)
                    for rec in conn.execute(data_query):
                        output.add_bucket(rec.second, rec.cells, rec.incomplete)
    return output.result()


@router.get("/analysis")
def analysis(
    request: Request,
    scope: Literal["current", "history"] = "current",
    session_id: Annotated[int | None, Query(ge=1, le=9_223_372_036_854_775_807)] = None,
    interface: str | None = None,
    start: UtcQuery = None,
    end: UtcQuery = None,
    protocol: Annotated[str, Query(max_length=12)] = "",
    direction: Literal["", "inbound", "outbound", "local", "other", "unknown"] = "",
    limit: Annotated[int, Query(ge=1, le=100)] = 10,
    ip: IPvAnyAddress | None = None,
):
    return capture_analysis(
        request.app.state.capture,
        scope=scope,
        session_id=session_id,
        interface=interface,
        start=start,
        end=end,
        protocol=protocol,
        direction=direction,
        limit=limit,
        ip=ip,
    )
