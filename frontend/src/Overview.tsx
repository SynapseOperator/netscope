import { useState } from "react";
import {
  Activity,
  ArrowDownLeft,
  ArrowUpRight,
  ArrowRight,
  Cable,
  ChevronRight,
  CircleCheck,
  Clock3,
  Database,
  Download,
  Layers3,
  Network,
  Radio,
  Router,
  Upload,
  Waypoints,
  type LucideIcon,
} from "lucide-react";
import {
  type AlertRow,
  type Live,
  type Monitor,
  type Page,
  type Sample,
  statusNames,
  useResource,
  errorText,
} from "./data";
import { TrafficChart } from "./chart";
import {
  bytes,
  clock,
  Empty,
  Heading,
  Notice,
  num,
  Panel,
  rate,
  Tag,
} from "./ui";

function Sparkline({
  values,
  tone,
}: {
  values: (number | null)[];
  tone: string;
}) {
  const nums = values.filter((x): x is number => x != null);
  if (nums.length < 2) return null;
  const max = Math.max(...nums),
    min = Math.min(...nums);
  let start = true;
  const path = values
    .map((n, i) => {
      if (n == null) {
        start = true;
        return "";
      }
      const pt =
        (start ? "M" : "L") +
        (2 + (i * 70) / (values.length - 1)).toFixed(1) +
        " " +
        (27 - ((n - min) / (max - min || 1)) * 22).toFixed(1);
      start = false;
      return pt;
    })
    .join(" ");
  return (
    <svg className={"spark " + tone} viewBox="0 0 75 32" aria-hidden="true">
      <path
        d={path}
        fill="none"
        stroke="currentColor"
        strokeWidth="1.75"
        strokeLinejoin="round"
      />
    </svg>
  );
}
function Metric({
  label,
  icon: Icon,
  tone,
  value,
  unit,
  detail,
  values,
}: {
  label: string;
  icon: LucideIcon;
  tone: string;
  value: string;
  unit?: string;
  detail: string;
  values?: (number | null)[];
}) {
  return (
    <div className={"metric " + tone}>
      <div className="metric-label">
        <span className="metric-icon">
          <Icon size={15} />
        </span>
        {label}
      </div>
      <div className="metric-value">
        {value} <small>{unit}</small>
      </div>
      <div className="metric-detail">{detail}</div>
      {values && <Sparkline values={values} tone={tone} />}
    </div>
  );
}
export function AdapterPicker({ live }: { live: Live }) {
  const [err, setErr] = useState(""),
    [working, setWorking] = useState(false);
  return (
    <div className="adapter-picker">
      <label>
        <Cable size={15} />
        <select
          aria-label="监控网卡"
          value={live.data?.selected ?? ""}
          disabled={working || !live.data?.interfaces.length}
          onChange={async (e) => {
            setErr("");
            setWorking(true);
            try {
              await live.select(e.target.value);
            } catch (err) {
              setErr(errorText(err));
            } finally {
              setWorking(false);
            }
          }}
        >
          {!live.data?.selected && <option value="">选择网卡</option>}
          {live.data?.interfaces.map((i) => (
            <option value={i.name} key={i.name}>
              {i.name}
            </option>
          ))}
        </select>
      </label>
      {err && <Notice>{err}</Notice>}
    </div>
  );
}
function StatusTag({ state }: { state?: Monitor["status"] }) {
  return (
    <Tag
      tone={
        state === "collecting" ? "good" : state === "error" ? "danger" : "warn"
      }
    >
      {state ? statusNames[state] : "连接中"}
    </Tag>
  );
}
function SampleRail({ series }: { series: Sample[] }) {
  const samples = series.slice(-30);
  return (
    <div
      className="sample-rail"
      aria-label={"最近 " + samples.length + " 个样本的连续性"}
    >
      {Array.from({ length: 30 }, (_, i) => {
        const s = samples[i - (30 - samples.length)];
        return (
          <i
            key={i}
            className={s ? (s.rx_bps == null ? "gap" : "observed") : ""}
            title={
              s
                ? clock(s.ts) +
                  (s.rx_bps == null ? " · 采样间断" : " · 有效样本")
                : "等待样本"
            }
          />
        );
      })}
    </div>
  );
}
export function Overview({
  live,
  dark,
  go,
}: {
  live: Live;
  dark: boolean;
  go: (p: Page) => void;
}) {
  const m = live.data,
    s = m?.latest,
    selected = m?.interfaces.find((i) => i.name === m.selected);
  const [period, setPeriod] = useState(60);
  const alerts = useResource<{ items: AlertRow[] }>("/alerts", 5000);
  const down = rate(s?.rx_bps),
    up = rate(s?.tx_bps),
    sum =
      s?.rx_bytes != null && s.tx_bytes != null
        ? bytes(s.rx_bytes + s.tx_bytes).split(" ")
        : ["—", ""];
  const range = (m?.series ?? []).slice(-24);
  return (
    <>
      <Heading
        title="网络总览"
        desc="查看当前网卡的实时流量、链路状态与最近告警。"
        action={<AdapterPicker live={live} />}
      />
      <div className="stack">
        {m && (m.status === "error" || m.status === "offline") && (
          <Notice>{m.message}</Notice>
        )}
        <div className="metrics">
          <Metric
            label="下载速率"
            icon={ArrowDownLeft}
            tone="blue"
            {...down}
            detail="网卡接收 · 实时"
            values={range.map((p) => p.rx_bps)}
          />
          <Metric
            label="上传速率"
            icon={ArrowUpRight}
            tone="teal"
            {...up}
            detail="网卡发送 · 实时"
            values={range.map((p) => p.tx_bps)}
          />
          <Metric
            label="累计流量"
            icon={Database}
            tone="violet"
            value={sum[0]}
            unit={sum[1]}
            detail="网卡计数器 · 收发合计"
          />
          <Metric
            label="可用网卡"
            icon={Network}
            tone="slate"
            value={m ? String(m.interfaces.filter((i) => i.up).length) : "—"}
            unit={m ? " / " + m.interfaces.length : ""}
            detail="已启用接口 / 系统接口"
          />
        </div>
        <div className="dashboard-mid">
          <Panel
            title="实时流量趋势"
            icon={Activity}
            desc="系统网卡计数器 · 收发速率"
            action={
              <div className="tabgroup" aria-label="趋势时间窗口">
                {[30, 60, 120].map((n) => (
                  <button
                    key={n}
                    aria-pressed={n === period}
                    onClick={() => setPeriod(n)}
                  >
                    {n < 60 ? n + " 秒" : n / 60 + " 分钟"}
                  </button>
                ))}
              </div>
            }
          >
            <div className="chart-inner">
              <TrafficChart
                points={m?.series ?? []}
                period={period}
                dark={dark}
              />
            </div>
            <div className="chart-foot">
              <div className="legend">
                <i />
                下载
                <i />
                上传
              </div>
              <span>
                <Clock3 size={12} />
                {m?.interval ?? 1} 秒采样
              </span>
            </div>
          </Panel>
          <Panel
            title="采集接口"
            icon={Radio}
            action={<StatusTag state={m?.status} />}
          >
            <div className="panel-body">
              <div className="interface-chip">
                <span>
                  <Cable size={23} />
                </span>
                <div>
                  <strong>{selected?.name ?? "等待选择"}</strong>
                  <small>当前监控网卡</small>
                </div>
              </div>
              <dl className="kv">
                <div>
                  <dt>协商链路速率</dt>
                  <dd>
                    {selected?.speed_mbps
                      ? num(selected.speed_mbps) + " Mbit/s"
                      : "未报告"}
                  </dd>
                </div>
                <div>
                  <dt>最大传输单元</dt>
                  <dd>{selected?.mtu ? num(selected.mtu) + " B" : "—"}</dd>
                </div>
                <div>
                  <dt>最后采样</dt>
                  <dd className="mono">{clock(s?.ts)}</dd>
                </div>
              </dl>
              <div className="sample-label">
                最近 30 个样本<span>连续性</span>
              </div>
              <SampleRail series={m?.series ?? []} />
            </div>
          </Panel>
        </div>
        <div className="dashboard-bottom">
          <Panel
            title="网卡计数器"
            icon={Layers3}
            action={
              <button className="softbtn" onClick={() => go("devices")}>
                设备详情
                <ChevronRight size={14} />
              </button>
            }
          >
            <div className="counter-head">
              <span>传输方向</span>
              <span>累计字节</span>
              <span>累计报文</span>
            </div>
            <div className="counter-row">
              <span>
                <Download size={15} className="blue-text" />
                接收
              </span>
              <strong>{bytes(s?.rx_bytes)}</strong>
              <span>{num(s?.rx_packets)}</span>
            </div>
            <div className="counter-row">
              <span>
                <Upload size={15} className="teal-text" />
                发送
              </span>
              <strong>{bytes(s?.tx_bytes)}</strong>
              <span>{num(s?.tx_packets)}</span>
            </div>
          </Panel>
          <Panel
            title="最近告警"
            icon={Activity}
            action={
              <button className="softbtn" onClick={() => go("alerts")}>
                查看全部
                <ChevronRight size={14} />
              </button>
            }
          >
            {alerts.error && (
              <div className="panel-body">
                <Notice>{alerts.error}</Notice>
              </div>
            )}
            {alerts.data?.items.length ? (
              <div className="activity-list">
                {alerts.data.items.slice(0, 2).map((a) => (
                  <div key={a.id}>
                    <i className={a.recovered_at ? "ok" : ""} />
                    <p>
                      <strong>{a.message}</strong>
                      <span>
                        {a.interface} · {clock(a.ts, true)}
                      </span>
                    </p>
                  </div>
                ))}
              </div>
            ) : alerts.busy ? (
              <Empty title="正在读取告警" busy />
            ) : (
              !alerts.error && (
                <div className="quiet">
                  <CircleCheck size={24} />
                  <div>
                    <strong>暂无告警记录</strong>
                    <p>出现持续超阈值或接口状态变化时会记录在此。</p>
                  </div>
                </div>
              )
            )}
          </Panel>
        </div>
      </div>
    </>
  );
}

type Neighbor = { ip: string; mac: string; interface: string; state: string };
type Connection = {
  protocol: string;
  local: string;
  remote: string;
  status: string;
};
export function Devices({ live }: { live: Live }) {
  const [tab, setTab] = useState<"interfaces" | "neighbors" | "connections">(
    "interfaces",
  );
  const neighbors = useResource<{
    items: Neighbor[];
    source: string;
    scope: string;
    message: string;
  }>(tab === "neighbors" ? "/neighbors" : null, 10000);
  const connections = useResource<{
    items: Connection[];
    source: string;
    message: string;
  }>(tab === "connections" ? "/connections" : null, 5000);
  const selected = live.data?.interfaces.find(
    (i) => i.name === live.data?.selected,
  );
  const [pending, setPending] = useState(false),
    [err, setErr] = useState("");
  const choose = async (name: string) => {
    setPending(true);
    setErr("");
    try {
      await live.select(name);
    } catch (e) {
      setErr(errorText(e));
    } finally {
      setPending(false);
    }
  };
  const labels = {
    interfaces: "本机网卡",
    neighbors: "邻居缓存",
    connections: "本机连接",
  };
  return (
    <>
      <Heading
        title="网络设备"
        desc="按数据来源查看本机接口、系统邻居缓存和通信端点。"
      />
      <div className="stack">
        <div className="view-tabs">
          {(Object.keys(labels) as (keyof typeof labels)[]).map((k) => (
            <button key={k} aria-pressed={tab === k} onClick={() => setTab(k)}>
              {labels[k]}
            </button>
          ))}
        </div>
        {err && <Notice>{err}</Notice>}
        {tab === "interfaces" && (
          <div className="layout-detail">
            <Panel
              title="本机接口"
              icon={Router}
              desc="系统枚举，包括虚拟接口和回环接口。"
            >
              <div className="device-list">
                {live.data?.interfaces.length ? (
                  live.data.interfaces.map((i) => (
                    <button
                      key={i.name}
                      disabled={pending}
                      onClick={() => void choose(i.name)}
                      className={
                        "device " + (i.name === selected?.name ? "chosen" : "")
                      }
                      aria-pressed={i.name === selected?.name}
                    >
                      <span className="tile-icon">
                        <Cable size={18} />
                      </span>
                      <span>
                        <strong>{i.name}</strong>
                        <small>{i.ipv4[0] ?? i.ipv6[0] ?? "无 IP 地址"}</small>
                      </span>
                      <Tag tone={i.up ? "good" : "neutral"}>
                        {i.up ? "在线" : "离线"}
                      </Tag>
                    </button>
                  ))
                ) : (
                  <Empty
                    busy={!live.data && !live.error}
                    title={live.data ? "未发现网卡" : "等待读取网卡"}
                  />
                )}
              </div>
            </Panel>
            <Panel
              title="所选接口"
              icon={Waypoints}
              desc="选择接口后，网络总览同步切换。"
            >
              <div className="panel-body">
                {selected ? (
                  <dl className="kv">
                    {[
                      ["接口名", selected.name],
                      ["IPv4", selected.ipv4.join("、") || "—"],
                      ["IPv6", selected.ipv6.join("、") || "—"],
                      ["MAC", selected.mac || "—"],
                      [
                        "链路速率",
                        selected.speed_mbps
                          ? num(selected.speed_mbps) + " Mbit/s"
                          : "未报告",
                      ],
                      ["MTU", selected.mtu ? num(selected.mtu) + " B" : "—"],
                    ].map(([k, v]) => (
                      <div key={k}>
                        <dt>{k}</dt>
                        <dd>{v}</dd>
                      </div>
                    ))}
                  </dl>
                ) : (
                  <Empty title="等待选择接口" />
                )}
              </div>
            </Panel>
          </div>
        )}
        {tab === "neighbors" && (
          <Panel
            title="系统邻居缓存"
            icon={Network}
            desc={
              neighbors.data?.scope ||
              "显示本机已学习的链路邻居，覆盖范围取决于缓存与接口。"
            }
            action={
              <button className="btn" onClick={neighbors.reload}>
                刷新
              </button>
            }
          >
            {neighbors.error && (
              <div className="panel-body">
                <Notice>{neighbors.error}</Notice>
              </div>
            )}
            {!!neighbors.data?.message && (
              <p className="hint panel-body">{neighbors.data.message}</p>
            )}
            {neighbors.data?.items.length ? (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      {["IP 地址", "MAC 地址", "接口", "邻居状态"].map((h) => (
                        <th key={h}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {neighbors.data.items.map((n, i) => (
                      <tr key={i}>
                        <td className="mono">{n.ip}</td>
                        <td className="mono">{n.mac}</td>
                        <td>{n.interface}</td>
                        <td>{n.state}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              !neighbors.error && (
                <Empty
                  busy={neighbors.busy}
                  title={neighbors.busy ? "正在读取邻居缓存" : "邻居缓存为空"}
                />
              )
            )}
            {neighbors.data && (
              <div className="panel-note">来源 · {neighbors.data.source}</div>
            )}
          </Panel>
        )}
        {tab === "connections" && (
          <Panel
            title="本机连接"
            icon={ArrowRight}
            desc="系统可见的套接字，按当前权限读取。"
            action={
              <button className="btn" onClick={connections.reload}>
                刷新
              </button>
            }
          >
            {connections.error && (
              <div className="panel-body">
                <Notice>{connections.error}</Notice>
              </div>
            )}
            {!!connections.data?.message && (
              <p className="hint panel-body">{connections.data.message}</p>
            )}
            {connections.data?.items.length ? (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      {["协议", "本地端点", "远程端点", "状态"].map((h) => (
                        <th key={h}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {connections.data.items.map((c, i) => (
                      <tr key={i}>
                        <td>{c.protocol}</td>
                        <td className="mono">{c.local}</td>
                        <td className="mono">{c.remote || "—"}</td>
                        <td>{c.status}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              !connections.error && (
                <Empty
                  busy={connections.busy}
                  title={
                    connections.busy ? "正在读取本机连接" : "当前没有可见连接"
                  }
                />
              )
            )}
            {connections.data && (
              <div className="panel-note">来源 · {connections.data.source}</div>
            )}
          </Panel>
        )}
      </div>
    </>
  );
}
