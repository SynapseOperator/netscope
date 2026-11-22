import { useRef, useState, type FormEvent } from "react";
import {
  Archive,
  Cable,
  FileUp,
  Layers3,
  ListFilter,
  Network,
  Play,
  Square,
} from "lucide-react";
import {
  type Capture,
  type Count,
  type Packet,
  api,
  errorText,
  post,
  useResource,
} from "./data";
import {
  bytes,
  clock,
  Empty,
  Field,
  Heading,
  Notice,
  num,
  Panel,
  Tag,
} from "./ui";

export function CountTable({
  items,
  endpoint = false,
}: {
  items: Count[];
  endpoint?: boolean;
}) {
  return items.length ? (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>{endpoint ? "端点" : "协议"}</th>
            <th className="num">报文数</th>
            <th className="num">字节量</th>
          </tr>
        </thead>
        <tbody>
          {items.map((s) => (
            <tr key={s.name}>
              <td className="mono">{s.name}</td>
              <td className="num">{num(s.packets)}</td>
              <td className="num">{bytes(s.bytes)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  ) : (
    <Empty title="暂无抓包统计" />
  );
}
export function Packets() {
  const capture = useResource<Capture>("/capture", 1800);
  const interfaces = useResource<{ name: string; description: string }[]>(
    "/capture/interfaces",
  );
  const [name, setName] = useState(""),
    [busy, setBusy] = useState(false),
    [msg, setMsg] = useState(""),
    [filters, setFilters] = useState("");
  const [selected, setSelected] = useState<Packet | null>(null);
  const file = useRef<HTMLInputElement>(null);
  const packets = useResource<Packet[]>(
    "/capture/packets?limit=150" + filters,
    capture.data?.state === "running" ? 1000 : 0,
  );
  const c = capture.data,
    running = c?.state === "running";
  const selectedName =
    (running && c?.interface) || name || interfaces.data?.[0]?.name || "";
  const action = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setMsg("");
    try {
      await fn();
      setSelected(null);
      packets.reload();
    } catch (e) {
      setMsg(errorText(e));
    } finally {
      capture.reload();
      setBusy(false);
    }
  };
  const filter = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const fields = new FormData(e.currentTarget),
      query = new URLSearchParams();
    for (const key of ["ip", "port", "protocol"]) {
      const value = String(fields.get(key) || "").trim();
      if (value) query.set(key, value);
    }
    setFilters(query.size ? "&" + query.toString() : "");
    setSelected(null);
    packets.reload();
  };
  const states = {
    idle: "待命",
    running: "正在捕获",
    stopped: "已停止",
    imported: "已导入",
    error: "捕获失败",
  };
  return (
    <>
      <Heading
        title="报文分析"
        desc="从授权网卡捕获报文，或导入 PCAP 查看协议分层与首部字段。"
        action={
          <>
            <input
              type="file"
              hidden
              accept=".pcap,.cap"
              ref={file}
              onChange={(e) => {
                const f = e.target.files?.[0];
                e.target.value = "";
                if (!f) return;
                if (f.size > 8 * 1024 * 1024) {
                  setMsg("文件超过 8 MiB，请缩小样本后再导入。");
                  return;
                }
                void action(() =>
                  api("/capture/import", {
                    method: "POST",
                    body: f,
                    headers: { "Content-Type": "application/octet-stream" },
                  }),
                );
              }}
            />
            <button
              className="btn"
              disabled={busy || running}
              onClick={() => file.current?.click()}
            >
              <FileUp size={15} />
              导入 PCAP
            </button>
          </>
        }
      />
      <div className="stack">
        {(capture.error || msg || c?.error) && (
          <Notice>{msg || capture.error || c?.error}</Notice>
        )}
        {interfaces.error && <Notice>{interfaces.error}</Notice>}
        {!!c?.driver_note && <Notice tone="info">{c.driver_note}</Notice>}
        <Panel
          title="捕获会话"
          icon={Cable}
          action={
            <Tag
              tone={
                running ? "good" : c?.state === "error" ? "danger" : "neutral"
              }
            >
              {c ? states[c.state] : "读取中"}
            </Tag>
          }
        >
          <div className="capture-strip">
            <div className="capture-input">
              <label className="field">
                <span>抓包网卡</span>
                <select
                  value={selectedName}
                  disabled={running || busy || !interfaces.data?.length}
                  onChange={(e) => setName(e.target.value)}
                  aria-label="抓包网卡"
                >
                  {!selectedName && <option value="">无可选接口</option>}
                  {interfaces.data?.map((i) => (
                    <option key={i.name} value={i.name}>
                      {i.name}
                      {i.description && i.description !== i.name
                        ? " · " + i.description
                        : ""}
                    </option>
                  ))}
                </select>
              </label>
              {running ? (
                <button
                  className="btn"
                  disabled={busy}
                  onClick={() => void action(() => post("/capture/stop"))}
                >
                  <Square size={14} />
                  停止抓包
                </button>
              ) : (
                <button
                  className="primary"
                  disabled={!c?.available || !selectedName || busy}
                  onClick={() =>
                    void action(() =>
                      post("/capture/start", { interface: selectedName }),
                    )
                  }
                >
                  <Play size={14} />
                  开始抓包
                </button>
              )}
            </div>
            <div className="session-metric">
              <small>会话报文</small>
              <strong>{num(c?.total)}</strong>
            </div>
            <div className="session-metric">
              <small>会话字节量</small>
              <strong>{bytes(c?.bytes)}</strong>
            </div>
          </div>
          <div className="panel-note">
            来源 ·{" "}
            {c?.source === "pcap"
              ? "PCAP 文件"
              : c?.source === "live"
                ? "实时网卡"
                : "尚未开始"}{" "}
            / 保留最近 {c?.capacity ?? 500} 条报文的首部元数据
          </div>
        </Panel>
        <div className="packet-grid">
          <Panel
            title="报文列表"
            icon={ListFilter}
            desc="显示最近匹配的 150 条记录，点击查看首部。"
          >
            <form className="toolbar" onSubmit={filter}>
              <Field label="IP 地址" name="ip" placeholder="任一端点" />
              <Field
                label="端口"
                name="port"
                type="number"
                min="0"
                max="65535"
                placeholder="全部"
              />
              <label className="field">
                <span>协议层</span>
                <select name="protocol" defaultValue="">
                  <option value="">全部协议</option>
                  {[
                    "IP",
                    "IPv4",
                    "IPv6",
                    "TCP",
                    "UDP",
                    "ICMP",
                    "ICMPv6",
                    "ARP",
                  ].map((p) => (
                    <option key={p}>{p}</option>
                  ))}
                </select>
              </label>
              <button className="btn">筛选</button>
              <button
                type="reset"
                className="softbtn"
                onClick={() => {
                  setFilters("");
                  setSelected(null);
                  packets.reload();
                }}
              >
                重置
              </button>
            </form>
            {packets.error && (
              <div className="panel-body">
                <Notice>{packets.error}</Notice>
              </div>
            )}
            {packets.data?.length ? (
              <div className="table-wrap scroll-table">
                <table>
                  <thead>
                    <tr>
                      {[
                        "序号",
                        "时间",
                        "网络层",
                        "协议",
                        "源地址 / 端口",
                        "目的地址 / 端口",
                        "长度",
                      ].map((h) => (
                        <th key={h}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {packets.data.map((p) => (
                      <tr
                        className={selected?.id === p.id ? "selected" : ""}
                        key={p.id}
                        onClick={() => setSelected(p)}
                      >
                        <td>
                          <button
                            className="btn-link"
                            aria-label={"查看报文 " + p.id}
                            onClick={() => setSelected(p)}
                          >
                            #{p.id}
                          </button>
                        </td>
                        <td className="mono">{clock(p.timestamp)}</td>
                        <td>{p.network}</td>
                        <td>
                          <span className="pill">{p.protocol}</span>
                        </td>
                        <td className="mono">
                          {p.src}
                          {p.sport != null ? " / " + p.sport : ""}
                        </td>
                        <td className="mono">
                          {p.dst}
                          {p.dport != null ? " / " + p.dport : ""}
                        </td>
                        <td>{p.length} B</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              !packets.error && (
                <Empty
                  busy={packets.busy}
                  title={
                    packets.busy
                      ? "正在读取报文"
                      : filters
                        ? "没有匹配的报文"
                        : "暂无报文"
                  }
                  detail="开始捕获、导入文件或调整筛选条件后，可在这里检查报文。"
                />
              )
            )}
          </Panel>
          <Panel
            title="报文详情"
            icon={Layers3}
            action={selected && <span className="pill">#{selected.id}</span>}
          >
            {selected ? (
              <div className="panel-body header-fields">
                {Object.entries(selected.headers).map(([layer, fields]) => (
                  <details open key={layer}>
                    <summary>{layer} 首部</summary>
                    <dl className="kv">
                      {Object.entries(fields).map(([k, v]) => (
                        <div key={k}>
                          <dt>{k}</dt>
                          <dd className="mono">{String(v)}</dd>
                        </div>
                      ))}
                    </dl>
                  </details>
                ))}
                {!Object.keys(selected.headers).length && (
                  <Empty title="当前报文无可解析首部" />
                )}
              </div>
            ) : (
              <Empty
                title="选择一条报文"
                detail="逐层查看网络与传输协议的首部字段。"
              />
            )}
          </Panel>
        </div>
        <div className="duo">
          <Panel title="协议分布" icon={Archive} desc="按传输或控制协议计数。">
            <CountTable items={c?.protocols ?? []} />
          </Panel>
          <Panel
            title="通信端点"
            icon={Network}
            desc="每个不同的源或目的地址各计一次，收发地址相同时计一次。"
          >
            <CountTable endpoint items={c?.endpoints ?? []} />
          </Panel>
        </div>
      </div>
    </>
  );
}
