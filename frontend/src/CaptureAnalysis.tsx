import { useState, type FormEvent } from "react";
import {
  ChartNoAxesColumnIncreasing,
  Clock3,
  SlidersHorizontal,
} from "lucide-react";
import { type Count, useResource } from "./data";
import { bytes, clock, Empty, Field, Notice, num, Panel, Tag } from "./ui";
import "./analysis.css";

export const directionNames: Record<string, string> = {
  inbound: "入站",
  outbound: "出站",
  local: "本机互通",
  other: "其他方向",
  unknown: "未知方向",
};
export const analysisProtocols = [
  "IP",
  "IPv4",
  "IPv6",
  "TCP",
  "UDP",
  "ICMP",
  "ICMPv6",
  "ARP",
  "Other",
];
type Flow = {
  id: string;
  kind: string;
  network: string;
  protocol: string;
  src: string;
  dst: string;
  sport: number | null;
  dport: number | null;
  direction: string;
  packets: number;
  bytes: number;
  first_seen: number;
  last_seen: number;
};
type Bucket = { start: number; end: number; packets: number; bytes: number };
type Analysis = {
  status: "ok" | "empty" | "legacy" | "partial";
  message: string;
  source: "live" | "pcap" | "mixed" | null;
  total: number | null;
  bytes: number | null;
  protocols: Count[];
  endpoints: Count[];
  flows: Flow[];
  buckets: Bucket[];
  endpoint_count: number | null;
  flow_count: number | null;
  session_ids: number[];
  expired_session_ids: number[];
  bucket_seconds: number;
};
export type Selection = {
  protocol?: string;
  direction?: string;
  start?: number;
  end?: number;
  ip?: string;
  flow_id?: string;
};
type Props = {
  historical?: boolean;
  start?: number;
  end?: number;
  iface?: string;
  sessionId?: number;
  running?: boolean;
  onDrill?: (filter: Selection, caption: string) => void;
};
type TimeFilter = {
  start?: number;
  end?: number;
  protocol?: string;
  direction?: string;
  ip?: string;
};
const kindNames: Record<string, string> = {
  transport: "传输流",
  fragment: "IP 分片",
  control: "控制报文",
  network: "网络层",
  arp: "地址解析",
  link: "链路层",
};
function localStamp(ts?: number) {
  if (ts == null) return "";
  const d = new Date(ts * 1000);
  return new Date(d.getTime() - d.getTimezoneOffset() * 60000)
    .toISOString()
    .slice(0, 19);
}
function Timeline({
  buckets,
  onSelect,
}: {
  buckets: Bucket[];
  onSelect: (start: number, end: number) => void;
}) {
  if (!buckets.length) return <Empty title="当前范围没有时间桶" />;
  const first = Math.min(...buckets.map((b) => b.start)),
    last = Math.max(...buckets.map((b) => b.end));
  const span = Math.max(1, last - first),
    width = Math.max(1, Math.ceil(span / 48));
  const bins = Array.from({ length: Math.ceil(span / width) }, (_, i) => ({
    start: first + i * width,
    end: Math.min(last, first + (i + 1) * width),
    bytes: 0,
    packets: 0,
    observed: false,
  }));
  for (const bucket of buckets) {
    const slot =
      bins[
        Math.min(bins.length - 1, Math.floor((bucket.start - first) / width))
      ];
    slot.observed = true;
    slot.bytes += bucket.bytes;
    slot.packets += bucket.packets;
  }
  const max = Math.max(1, ...bins.map((b) => b.bytes));
  return (
    <div className="capture-timeline">
      <div className="timeline-head">
        <span>
          <Clock3 size={13} />
          报文字节量
        </span>
        <small>每格 {num(width)} 秒 · 选择有记录的时间段</small>
      </div>
      <div className="time-bars">
        {bins.map((b) => (
          <button
            type="button"
            key={b.start}
            disabled={!b.observed}
            aria-label={
              "筛查时段 " + clock(b.start, true) + " 至 " + clock(b.end, true)
            }
            title={
              clock(b.start, true) +
              " – " +
              clock(b.end, true) +
              " · " +
              (b.observed
                ? num(b.packets) + " 个报文 · " + bytes(b.bytes)
                : "无记录")
            }
            onClick={() => onSelect(b.start, b.end)}
          >
            <i
              style={{
                height:
                  (b.observed ? Math.max(3, (100 * b.bytes) / max) : 1) + "%",
              }}
            />
          </button>
        ))}
      </div>
      <div className="timeline-scale">
        <span>{clock(first, true)}</span>
        <span>{clock(last, true)}</span>
      </div>
    </div>
  );
}
export function CaptureAnalysis(props: Props) {
  return (
    <AnalysisView
      key={[
        props.historical,
        props.sessionId,
        props.iface,
        props.start,
        props.end,
      ].join("|")}
      {...props}
    />
  );
}
function AnalysisView({
  historical = false,
  start,
  end,
  iface,
  sessionId,
  running = false,
  onDrill,
}: Props) {
  const baseline: TimeFilter = { start, end };
  const [filter, setFilter] = useState<TimeFilter>(baseline),
    [tab, setTab] = useState<"flows" | "endpoints" | "protocols">("flows"),
    [limit, setLimit] = useState(10),
    [error, setError] = useState(""),
    [selectedFlow, setSelectedFlow] = useState<Flow | null>(null);
  const q = new URLSearchParams({
    scope: historical ? "history" : "current",
    limit: String(limit),
  });
  if (iface) q.set("interface", iface);
  if (sessionId != null) q.set("session_id", String(sessionId));
  for (const [k, v] of Object.entries(filter)) {
    if (v != null && v !== "") q.set(k, String(v));
  }
  const res = useResource<Analysis>(
      "/capture/analysis?" + q,
      running ? 1600 : 0,
    ),
    a = res.data;
  const setScope = (next: TimeFilter, caption: string) => {
    setError("");
    setSelectedFlow(null);
    setFilter(next);
    onDrill?.(next, caption);
  };
  function apply(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const values = new FormData(e.currentTarget);
    const startInput = String(values.get("start") ?? ""),
      endInput = String(values.get("end") ?? "");
    const lower =
        startInput === localStamp(filter.start)
          ? filter.start
          : startInput
            ? new Date(startInput).getTime() / 1000
            : start,
      upper =
        endInput === localStamp(filter.end)
          ? filter.end
          : endInput
            ? new Date(endInput).getTime() / 1000
            : end;
    if (lower != null && upper != null && lower >= upper) {
      setError("分析开始时间必须早于结束时间。");
      return;
    }
    if (
      (start != null && lower != null && lower < Math.floor(start)) ||
      (end != null && upper != null && upper > Math.ceil(end))
    ) {
      setError("所选时段超出了报告时间范围。");
      return;
    }
    const next = {
      ip: filter.ip,
      start: start == null || lower == null ? lower : Math.max(start, lower),
      end: end == null || upper == null ? upper : Math.min(end, upper),
      protocol: String(values.get("protocol") || ""),
      direction: String(values.get("direction") || ""),
    };
    setScope(next, "分析条件");
  }
  function showFlow(flow: Flow) {
    if (onDrill)
      onDrill(
        { ...filter, flow_id: flow.id },
        [flow.src, flow.dst].filter(Boolean).join(" → ") || flow.protocol,
      );
    else setSelectedFlow(flow);
  }
  function showRank(name: string) {
    setTab("flows");
    setScope(
      {
        ...filter,
        ...(tab === "endpoints" ? { ip: name } : { protocol: name }),
      },
      name,
    );
  }
  const hasRecords = a && a.total != null && a.total > 0;
  const ranks = tab === "endpoints" ? a?.endpoints : a?.protocols;
  let emptyTitle = historical ? "该时间段没有抓包记录" : "当前会话暂无报文";
  if (a?.status === "legacy") emptyTitle = "旧会话缺少分桶证据";
  else if (a?.status === "partial") emptyTitle = "所选时段缺少可归属的报文统计";
  else if (a?.expired_session_ids.length)
    emptyTitle = "该时段的抓包明细已过保留期";
  else if (a?.source) emptyTitle = "没有符合筛选条件的报文";
  return (
    <Panel
      title={historical ? "历史报文分析" : "会话流量分析"}
      icon={ChartNoAxesColumnIncreasing}
      desc={
        historical
          ? "按报文观测时间查询保留的聚合桶。原始报文与应用载荷不写入历史。"
          : "基于已捕获报文生成统计。选择端点、流或时段可联动当前缓存中的报文。"
      }
      action={
        <Tag tone={a?.source === "live" ? "good" : "neutral"}>
          {a?.source === "live"
            ? "网卡抓包"
            : a?.source === "pcap"
              ? "PCAP 文件"
              : a?.source === "mixed"
                ? "多个数据来源"
                : "报文统计"}
        </Tag>
      }
    >
      <form
        key={JSON.stringify(filter)}
        className="toolbar analysis-toolbar"
        onSubmit={apply}
      >
        <Field
          label="分析开始时间"
          name="start"
          type="datetime-local"
          step="any"
          defaultValue={localStamp(filter.start)}
        />
        <Field
          label="分析结束时间（不含）"
          name="end"
          type="datetime-local"
          step="any"
          defaultValue={localStamp(filter.end)}
        />
        <label className="field">
          <span>分析协议</span>
          <select name="protocol" defaultValue={filter.protocol ?? ""}>
            <option value="">全部协议</option>
            {analysisProtocols.map((p) => (
              <option key={p}>{p}</option>
            ))}
          </select>
        </label>
        <label className="field">
          <span>分析方向</span>
          <select name="direction" defaultValue={filter.direction ?? ""}>
            <option value="">全部方向</option>
            {Object.entries(directionNames).map(([key, v]) => (
              <option key={key} value={key}>
                {v}
              </option>
            ))}
          </select>
        </label>
        <button className="btn" type="submit">
          <SlidersHorizontal size={13} />
          应用分析筛选
        </button>
        <button
          className="softbtn"
          type="reset"
          onClick={() => setScope(baseline, "全部报文")}
        >
          重置分析
        </button>
      </form>
      {filter.ip && (
        <div className="linked-scope">
          <strong>端点详情</strong>
          <code>{filter.ip}</code>
          <button
            className="btn-link"
            onClick={() => setScope({ ...filter, ip: undefined }, "分析条件")}
          >
            清除端点筛选
          </button>
        </div>
      )}
      {(error || res.error) && (
        <div className="panel-body">
          <Notice>{error || res.error}</Notice>
        </div>
      )}
      {res.busy && <Empty busy title="正在读取报文聚合" />}
      {a && (
        <>
          <div className="analysis-stats">
            {[
              ["匹配报文", num(a.total)],
              ["观测字节", bytes(a.bytes)],
              ["IP 端点", num(a.endpoint_count)],
              ["流记录", num(a.flow_count)],
            ].map(([label, v]) => (
              <span key={label}>
                <small>{label}</small>
                <strong>{v}</strong>
              </span>
            ))}
          </div>
          {!!a.message && (
            <p
              className={
                "analysis-message " + (a.status === "partial" ? "partial" : "")
              }
            >
              {a.message}
            </p>
          )}
          {a.source === "pcap" && (
            <p className="analysis-message">
              离线文件未保存本机接口归属，方向显示为未知。
            </p>
          )}
          {hasRecords ? (
            <>
              <div className="panel-body analysis-chart">
                <Timeline
                  buckets={a.buckets}
                  onSelect={(lo, hi) =>
                    setScope(
                      {
                        ...filter,
                        start: Math.max(lo, filter.start ?? lo),
                        end: Math.min(hi, filter.end ?? hi),
                      },
                      "选定时段",
                    )
                  }
                />
              </div>
              <div className="ranking-head">
                <div className="tabgroup" aria-label="分析视图">
                  {(
                    [
                      ["flows", "网络流"],
                      ["endpoints", "IP 端点"],
                      ["protocols", "协议分布"],
                    ] as const
                  ).map(([k, v]) => (
                    <button
                      key={k}
                      aria-pressed={tab === k}
                      onClick={() => setTab(k)}
                    >
                      {v}
                    </button>
                  ))}
                </div>
                {tab !== "protocols" && (
                  <label className="top-n">
                    <span>按字节量</span>
                    <select
                      aria-label="排行条数"
                      value={limit}
                      onChange={(e) => setLimit(Number(e.target.value))}
                    >
                      {[5, 10, 25, 50, 100].map((n) => (
                        <option value={n} key={n}>
                          前 {n} 项
                        </option>
                      ))}
                    </select>
                  </label>
                )}
              </div>
              {tab === "flows" ? (
                a.flows.length ? (
                  <div className="table-wrap scroll-table">
                    <table>
                      <thead>
                        <tr>
                          {[
                            "源端点",
                            "目的端点",
                            "网络层 / 协议",
                            "流类型",
                            "方向",
                            "报文数",
                            "字节量",
                            "首次 / 末次观测",
                          ].map((h) => (
                            <th key={h}>{h}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {a.flows.map((f) => (
                          <tr key={f.id}>
                            <td className="mono">
                              <button
                                type="button"
                                className="btn-link"
                                title={
                                  historical
                                    ? "查看历史流详情"
                                    : "筛查当前缓存中的流报文"
                                }
                                onClick={() => showFlow(f)}
                              >
                                {f.src || "—"}
                                {f.sport != null ? " / " + f.sport : ""}
                              </button>
                            </td>
                            <td className="mono">
                              {f.dst || "—"}
                              {f.dport != null ? " / " + f.dport : ""}
                            </td>
                            <td>
                              {f.network} / {f.protocol}
                            </td>
                            <td>{kindNames[f.kind] ?? f.kind}</td>
                            <td>
                              {directionNames[f.direction] ?? f.direction}
                            </td>
                            <td>{num(f.packets)}</td>
                            <td>{bytes(f.bytes)}</td>
                            <td className="mono">
                              {clock(f.first_seen, true)} /{" "}
                              {clock(f.last_seen, true)}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <Empty title="当前范围内无可列出的流" />
                )
              ) : ranks?.length ? (
                <div className="table-wrap scroll-table">
                  <table>
                    <thead>
                      <tr>
                        <th>
                          {tab === "endpoints" ? "IP 地址" : "传输或控制协议"}
                        </th>
                        <th>报文数</th>
                        <th>字节量</th>
                      </tr>
                    </thead>
                    <tbody>
                      {ranks.map((r) => (
                        <tr key={r.name}>
                          <td className="mono">
                            <button
                              type="button"
                              className="btn-link"
                              onClick={() => showRank(r.name)}
                            >
                              {r.name}
                            </button>
                          </td>
                          <td>{num(r.packets)}</td>
                          <td>{bytes(r.bytes)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <Empty title="所选维度暂无可列出的记录" />
              )}
              {historical && tab === "flows" && selectedFlow && (
                <div className="historical-flow">
                  <div className="flex-between">
                    <h3>历史流详情</h3>
                    <button
                      className="btn-link"
                      onClick={() => setSelectedFlow(null)}
                    >
                      收起详情
                    </button>
                  </div>
                  <dl className="kv">
                    {[
                      [
                        "源地址 / 端口",
                        (selectedFlow.src || "—") +
                          " / " +
                          (selectedFlow.sport ?? "—"),
                      ],
                      [
                        "目的地址 / 端口",
                        (selectedFlow.dst || "—") +
                          " / " +
                          (selectedFlow.dport ?? "—"),
                      ],
                      [
                        "网络 / 传输协议",
                        selectedFlow.network + " / " + selectedFlow.protocol,
                      ],
                      [
                        "流类型 / 方向",
                        (kindNames[selectedFlow.kind] ?? selectedFlow.kind) +
                          " / " +
                          (directionNames[selectedFlow.direction] ??
                            selectedFlow.direction),
                      ],
                      [
                        "首次 / 末次观测",
                        clock(selectedFlow.first_seen, true) +
                          " / " +
                          clock(selectedFlow.last_seen, true),
                      ],
                      [
                        "报文 / 字节",
                        num(selectedFlow.packets) +
                          " 个 / " +
                          bytes(selectedFlow.bytes),
                      ],
                    ].map(([k, v]) => (
                      <div key={k}>
                        <dt>{k}</dt>
                        <dd>{v}</dd>
                      </div>
                    ))}
                  </dl>
                  <p className="hint">
                    历史记录保留聚合元数据，逐包首部仅在当前会话缓存中可查。
                  </p>
                </div>
              )}
              {tab === "endpoints" && (
                <div className="panel-note">
                  每个报文为不同的源、目的 IP
                  各计一次；端点字节量相加可能超过观测字节。
                </div>
              )}
            </>
          ) : (
            <Empty
              title={emptyTitle}
              detail="调整时间、方向或协议，或先捕获、导入一段报文。"
            />
          )}
        </>
      )}
    </Panel>
  );
}
