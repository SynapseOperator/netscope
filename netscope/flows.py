"""One-second aggregates for observed header metadata. No packet bodies or per-packet rows."""

import hashlib
import json
import math
from collections import Counter

from sqlalchemy import JSON, Boolean, Column, Float, Integer, String, Table

MAX_SECONDS = 120
MAX_GROUPS_PER_SECOND = 64
MAX_QUERY_GROUPS = 4096
KEY_FIELDS = ("kind", "network", "protocol", "src", "dst", "sport", "dport", "direction")


def tables(metadata):
    details = Table(
        "capture_analysis_sessions",
        metadata,
        Column("session_id", Integer, primary_key=True),
        Column("bpf", String(256)),
        Column("observed_start", Float),
        Column("observed_end", Float),
        Column("discarded_before", Integer),
        Column("expired_at", Float),
        Column("saved_at", Float),
    )
    buckets = Table(
        "capture_analysis_seconds",
        metadata,
        Column("session_id", Integer, primary_key=True),
        Column("second", Integer, primary_key=True),
        Column("cells", JSON, nullable=False),
        Column("incomplete", Boolean, nullable=False),
    )
    return details, buckets


def flow_key(row):
    key = tuple(row[name] for name in KEY_FIELDS)
    # Fragments cannot be reconstructed as a transport five-tuple. A first fragment
    # can still expose its true ports in the packet inspector.
    return (*key[:5], None, None, key[-1]) if row["kind"] == "fragment" else key


def flow_id(key):
    encoded = json.dumps(key, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.blake2s(encoded, digest_size=12).hexdigest()


def matches_protocol(network, protocol, wanted):
    return (
        not wanted
        or wanted in (network.lower(), protocol.lower())
        or (wanted == "ip" and network in {"IPv4", "IPv6"})
    )


class FlowWindow:
    """Retain whole observed seconds; under excessive cardinality flag the affected second."""

    def __init__(self):
        self.seconds = {}
        self.incomplete = set()
        self.observed_start = self.observed_end = self.discarded_before = None

    def add(self, row, key):
        ts = row["timestamp"]
        self.observed_start = ts if self.observed_start is None else min(ts, self.observed_start)
        self.observed_end = ts if self.observed_end is None else max(ts, self.observed_end)
        second = math.floor(ts)
        if self.discarded_before is not None and second < self.discarded_before:
            return
        if second not in self.seconds and len(self.seconds) == MAX_SECONDS:
            oldest = min(self.seconds)
            removed = min(second, oldest)
            self.discarded_before = removed + 1
            if second == removed:
                return
            del self.seconds[oldest]
            self.incomplete.discard(oldest)
        cells = self.seconds.setdefault(second, {})
        if key not in cells:
            if len(cells) == MAX_GROUPS_PER_SECOND:
                self.incomplete.add(second)
                return
            cells[key] = [0, 0, ts, ts]
        cell = cells[key]
        cell[0] += 1
        cell[1] += row["length"]
        cell[2] = min(cell[2], ts)
        cell[3] = max(cell[3], ts)

    def records(self, start=None, end=None):
        for second, cells in self.seconds.items():
            if (start is None or second + 1 > start) and (end is None or second < end):
                yield {
                    "second": second,
                    "incomplete": second in self.incomplete,
                    "cells": [[*key, *value] for key, value in cells.items()],
                }


class Analysis:
    def __init__(self, start, end, protocol, direction, limit, ip):
        self.start, self.end = start, end
        self.protocol, self.direction, self.limit = protocol.lower(), direction, limit
        self.ip = ip
        self.groups = {}
        self.seconds = {}
        self.sources = set()
        self.capture_filters = set()
        self.ids = set()
        self.expired_ids = set()
        self.session_count = 0
        self.legacy = self.modern = False
        self.partial = False

    def session(
        self,
        session_id,
        source,
        legacy,
        observed_start=None,
        discarded_before=None,
        bpf=None,
        expired=False,
    ):
        self.session_count += 1
        self.sources.add(source)
        if bpf:
            self.capture_filters.add(bpf)
        if session_id is not None:
            self.ids.add(session_id)
        if expired:
            self.expired_ids.add(session_id)
            return
        if legacy:
            self.legacy = True
        else:
            self.modern = True
        if (
            discarded_before is not None
            and (self.start is None or self.start < discarded_before)
            and (self.end is None or observed_start is None or self.end > observed_start)
        ):
            self.partial = True

    def add_bucket(self, second, cells, incomplete):
        self.partial |= incomplete
        for cell in cells:
            key = tuple(cell[: len(KEY_FIELDS)])
            _, network, proto, src, dst, _, _, direction = key
            if self.ip is not None and self.ip not in (src, dst):
                continue
            if not matches_protocol(network, proto, self.protocol) or (
                self.direction and direction != self.direction
            ):
                continue
            packets, size, first, last = cell[len(KEY_FIELDS) :]
            if (
                self.start is not None
                and last < self.start
                or self.end is not None
                and first >= self.end
            ):
                continue
            # A query cutting through a group cannot use its full count. Preserve the
            # unknown portion explicitly, even for a sub-second diagnostic window.
            if (
                self.start is not None
                and first < self.start
                or self.end is not None
                and last >= self.end
            ):
                self.partial = True
                continue
            if key not in self.groups and len(self.groups) >= MAX_QUERY_GROUPS:
                self.partial = True
                continue
            group = self.groups.setdefault(key, [0, 0, first, last])
            group[0] += packets
            group[1] += size
            group[2] = min(group[2], first)
            group[3] = max(group[3], last)
            point = self.seconds.setdefault(second, [0, 0])
            point[0] += packets
            point[1] += size

    def result(self):
        protocols = {}
        endpoints = {}
        flows = []
        for key, (count, size, first, last) in self.groups.items():
            row = dict(zip(KEY_FIELDS, key, strict=True))
            flows.append(
                dict(row, id=flow_id(key), packets=count, bytes=size, first_seen=first, last_seen=last)
            )
            proto = "ARP" if row["network"] == "ARP" else row["protocol"]
            peers = {row["src"], row["dst"]} - {""}
            for stats, name in [(protocols, proto), *((endpoints, ip) for ip in peers)]:
                entry = stats.setdefault(name, Counter())
                entry.update(packets=count, bytes=size)

        def ranks(mapping):
            return sorted(
                (dict(counts, name=name) for name, counts in mapping.items()),
                key=lambda row: (-row["bytes"], -row["packets"], row["name"]),
            )

        status = "ok"
        message = "统计来自所选范围内有记录的报文秒桶。"
        if self.expired_ids and not self.modern and not self.legacy:
            status, message = "empty", "所选会话的秒桶与流统计已超过保留期，仍可查看整场汇总。"
        elif self.legacy and not self.modern and not self.expired_ids:
            status, message = "legacy", "此旧会话仅保存整场汇总，缺少时间桶与流记录。"
        elif self.partial or self.legacy or self.expired_ids:
            status, message = (
                "partial",
                "部分记录超出保留容量、来自旧会话或跨越查询边界，数值仅覆盖可归属的记录。",
            )
        elif not flows:
            status = "empty"
            if "live" in self.sources:
                message = "该窗口内存在实时抓包会话，但没有符合条件的报文记录。"
            elif self.sources:
                message = "所选会话中没有符合时间与筛选条件的报文记录。"
            else:
                message = "所选来源、接口和时间内没有匹配的抓包会话。"
        if status == "partial" and self.expired_ids:
            message += " 部分会话的细分统计已到期。"
        if self.capture_filters:
            message += " 启用 BPF 的会话仅覆盖通过内核过滤的报文。"
        evidence = bool(flows)
        return {
            "status": status,
            "message": message,
            "source": next(iter(self.sources))
            if len(self.sources) == 1
            else "mixed"
            if self.sources
            else None,
            "total": sum(p[0] for p in self.seconds.values()) if evidence else None,
            "bytes": sum(p[1] for p in self.seconds.values()) if evidence else None,
            "protocols": ranks(protocols),
            "endpoints": ranks(endpoints)[: self.limit],
            "flows": sorted(flows, key=lambda f: (-f["bytes"], -f["packets"], f["id"]))[: self.limit],
            "flow_count": len(flows) if status == "ok" else None,
            "endpoint_count": len(endpoints) if status == "ok" else None,
            "session_ids": sorted(self.ids),
            "session_count": self.session_count,
            "expired_session_ids": sorted(self.expired_ids),
            "bucket_seconds": 1,
            "capture_filters": sorted(self.capture_filters),
            "buckets": [
                {"start": t, "end": t + 1, "packets": p[0], "bytes": p[1]}
                for t, p in sorted(self.seconds.items())
            ],
        }
