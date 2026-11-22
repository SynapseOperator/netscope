import { useState, type FormEvent } from "react";
import {
  BellRing,
  Check,
  Clock3,
  Download,
  FileChartColumn,
  History,
  Layers3,
  ListChecks,
  ShieldCheck,
} from "lucide-react";
import {
  type AlertRow,
  type Live,
  type Rule,
  type Session,
  type TestResult,
  errorText,
  post,
  useResource,
} from "./data";
import { TrafficChart } from "./chart";
import { CaptureAnalysis } from "./CaptureAnalysis";
import { AlertDiagnosis } from "./AlertDiagnosis";
import { historyLink, readWindow } from "./timeWindow";
import { CountTable } from "./Packets";
import { SpeedTable } from "./Speed";
import {
  bytes,
  clock,
  Empty,
  Field,
  Heading,
  Notice,
  num,
  Panel,
  rate,
  Tag,
} from "./ui";
type Aggregate = {
  ts: number;
  interface: string;
  seconds: number;
  rx_bytes: number;
  tx_bytes: number;
  rx_packets: number;
  tx_packets: number;
  rx_bps: number;
  tx_bps: number;
};
function localTime(ts: number) {
  const t = new Date(ts);
  return new Date(t.getTime() - t.getTimezoneOffset() * 60000)
    .toISOString()
    .slice(0, 19);
}
export function Reports({ live, dark }: { live: Live; dark: boolean }) {
  const params = new URLSearchParams(location.hash.split("?")[1]);
  const [tab, setTab] = useState<"traffic" | "captures" | "speed">(
    params.get("tab") === "captures" ? "captures" : "traffic",
  );
  const [filter, setFilter] = useState(() => {
    const linked = readWindow(params);
    const now = Math.floor(Date.now() / 1000);
    return {
      start: linked?.start ?? now - 86400,
      end: linked?.end ?? now,
      iface: linked?.interface ?? "",
    };
  });
  const [range, setRange] = useState(() => ({
      start: localTime(filter.start * 1000),
      end: localTime(filter.end * 1000),
      iface: filter.iface,
    })),
    [msg, setMsg] = useState(""),
    [page, setPage] = useState(0),
    [chosen, setChosen] = useState<number | null>(null);
  const from = filter.start,
    to = filter.end;
  const q = new URLSearchParams({
    start: String(from),
    end: String(to - 0.001),
  });
  if (filter.iface) q.set("interface", filter.iface);
  const hist = useResource<{ items: Aggregate[]; truncated: boolean }>(
    tab === "traffic" ? "/history?" + q : null,
  );
  const sessions = useResource<Session[]>(
    tab === "captures"
      ? "/capture/history?start=" + from + "&end=" + (to - 0.001)
      : null,
  );
  const speeds = useResource<TestResult[]>(
    tab === "speed"
      ? "/speed/history?start=" + from + "&end=" + (to - 0.001)
      : null,
  );
  const recorded = sessions.data?.filter(
    (s) => !filter.iface || s.interface === filter.iface,
  );
  const selected = recorded?.find((s) => s.id === chosen);
  function apply(e: FormEvent) {
    e.preventDefault();
    const start =
        range.start === localTime(from * 1000)
          ? from
          : new Date(range.start).getTime() / 1000,
      end =
        range.end === localTime(to * 1000)
          ? to
          : new Date(range.end).getTime() / 1000;
    if (!(start < end)) {
      setMsg("开始时间须早于结束时间。");
      return;
    }
    setMsg("");
    setPage(0);
    setChosen(null);
    setFilter({ start, end, iface: range.iface });
    hist.reload();
    sessions.reload();
    speeds.reload();
  }
  const items = hist.data?.items ?? [],
    shown = items.slice(page * 30, page * 30 + 30);
  return (
    <>
      <Heading
        title="历史报告"
        desc="按时间范围查询网卡聚合流量、抓包会话和测速记录。"
        action={
          tab === "traffic" && (
            <a className="btn" download href={"/api/history.csv?" + q}>
              <Download size={15} />
              导出 CSV
            </a>
          )
        }
      />
      <div className="stack">
        <div className="view-tabs">
          {(
            [
              ["traffic", "流量记录"],
              ["captures", "抓包统计"],
              ["speed", "测速记录"],
            ] as const
          ).map(([key, label]) => (
            <button
              key={key}
              aria-pressed={tab === key}
              onClick={() => {
                setTab(key);
                setPage(0);
              }}
            >
              {label}
            </button>
          ))}
        </div>
        <div className="panel">
          <form className="toolbar filter-line" onSubmit={apply}>
            <Field
              label="开始时间"
              type="datetime-local"
              step="1"
              value={range.start}
              required
              onChange={(e) => setRange({ ...range, start: e.target.value })}
            />
            <Field
              label="结束时间（不含）"
              type="datetime-local"
              step="1"
              value={range.end}
              required
              onChange={(e) => setRange({ ...range, end: e.target.value })}
            />
            {tab !== "speed" && (
              <label className="field">
                <span>网卡</span>
                <select
                  value={range.iface}
                  onChange={(e) =>
                    setRange({ ...range, iface: e.target.value })
                  }
                >
                  <option value="">全部网卡</option>
                  {range.iface &&
                    !live.data?.interfaces.some(
                      (i) => i.name === range.iface,
                    ) && <option value={range.iface}>{range.iface}</option>}
                  {live.data?.interfaces.map((i) => (
                    <option key={i.name}>{i.name}</option>
                  ))}
                </select>
              </label>
            )}
            <button className="primary">查询</button>
          </form>
        </div>
        {msg && <Notice>{msg}</Notice>}
        {tab === "traffic" && (
          <>
            {hist.error && <Notice>{hist.error}</Notice>}
            {!!filter.iface && items.length > 0 && (
              <Panel
                title="历史速率趋势"
                icon={FileChartColumn}
                desc={filter.iface}
              >
                <TrafficChart
                  points={[...items].sort((a, b) => a.ts - b.ts)}
                  dark={dark}
                  step={Math.max(1, ...items.map((r) => r.seconds))}
                />
              </Panel>
            )}
            <Panel
              title="流量聚合记录"
              icon={History}
              desc="显示与查询范围重叠的完整分钟桶。每桶速率按其有效采样时长计算。"
              action={<span className="pill">{items.length} 条</span>}
            >
              {hist.data?.truncated && (
                <div className="panel-body">
                  <Notice tone="info">
                    结果达到查询上限，请缩小时间范围。
                  </Notice>
                </div>
              )}
              {shown.length ? (
                <>
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          {[
                            "窗口时间",
                            "网卡",
                            "有效时长",
                            "下载字节",
                            "上传字节",
                            "平均下载",
                            "平均上传",
                            "同期抓包",
                          ].map((h) => (
                            <th key={h}>{h}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {shown.map((r, i) => (
                          <tr key={i}>
                            <td className="mono">{clock(r.ts, true)}</td>
                            <td>{r.interface}</td>
                            <td>{num(r.seconds)} s</td>
                            <td>{bytes(r.rx_bytes)}</td>
                            <td>{bytes(r.tx_bytes)}</td>
                            <td>{Object.values(rate(r.rx_bps)).join(" ")}</td>
                            <td>{Object.values(rate(r.tx_bps)).join(" ")}</td>
                            <td>
                              <a
                                className="btn-link"
                                href={historyLink({
                                  start: r.ts,
                                  end: r.ts + 60,
                                  interface: r.interface,
                                })}
                              >
                                查看该分钟
                              </a>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <div className="pager">
                    <button
                      className="btn"
                      disabled={!page}
                      onClick={() => setPage((p) => p - 1)}
                    >
                      上一页
                    </button>
                    <span>
                      {page + 1} / {Math.ceil(items.length / 30)}
                    </span>
                    <button
                      className="btn"
                      disabled={(page + 1) * 30 >= items.length}
                      onClick={() => setPage((p) => p + 1)}
                    >
                      下一页
                    </button>
                  </div>
                </>
              ) : (
                !hist.error && (
                  <Empty
                    busy={hist.busy}
                    title={
                      hist.busy ? "正在读取流量记录" : "所选范围暂无聚合数据"
                    }
                    detail="采样窗口写入后可查询，或调整网卡与时间范围。"
                  />
                )
              )}
            </Panel>
          </>
        )}
        {tab === "captures" && (
          <>
            <CaptureAnalysis
              historical
              start={from}
              end={to}
              iface={filter.iface}
            />
            {sessions.error && <Notice>{sessions.error}</Notice>}
            <Panel
              title="完整会话记录"
              icon={Layers3}
              desc="列出在此区间启动或导入的会话。下表显示整场合计，区间内的捕获量见上方分析。"
            >
              {recorded?.length ? (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        {[
                          "会话",
                          "开始时间",
                          "来源",
                          "接口",
                          "报文数",
                          "字节量",
                        ].map((h) => (
                          <th key={h}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {recorded.map((s) => (
                        <tr
                          key={s.id}
                          className={s.id === selected?.id ? "selected" : ""}
                        >
                          <td>
                            <button
                              className="btn-link"
                              onClick={() => setChosen(s.id)}
                            >
                              #{s.id} 查看
                            </button>
                          </td>
                          <td>{clock(s.started_at, true)}</td>
                          <td>
                            {s.source === "pcap" ? "PCAP 文件" : "实时抓包"}
                          </td>
                          <td>{s.interface || "—"}</td>
                          <td>{num(s.total)}</td>
                          <td>{bytes(s.bytes)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                !sessions.error && (
                  <Empty
                    busy={sessions.busy}
                    title={
                      sessions.busy ? "正在读取会话" : "所选范围暂无抓包会话"
                    }
                  />
                )
              )}
            </Panel>
            {selected && (
              <div className="duo">
                <Panel title="会话协议分布" desc={"会话 #" + selected.id}>
                  <CountTable items={selected.protocols} />
                </Panel>
                <Panel
                  title="会话通信端点"
                  desc="每个不同的源或目的地址各计一次。"
                >
                  <CountTable endpoint items={selected.endpoints} />
                </Panel>
              </div>
            )}
          </>
        )}
        {tab === "speed" && (
          <Panel title="测速记录" icon={Clock3}>
            {speeds.error && (
              <div className="panel-body">
                <Notice>{speeds.error}</Notice>
              </div>
            )}
            {speeds.busy ? (
              <Empty busy title="正在读取测速记录" />
            ) : (
              speeds.data && <SpeedTable rows={speeds.data} />
            )}
          </Panel>
        )}
      </div>
    </>
  );
}
function RuleForm({ rule, done }: { rule: Rule; done: () => void }) {
  const [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [saved, setSaved] = useState(false);
  async function save(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    const draft: Rule = {
      enabled: form.has("enabled"),
      rx_mbps: Number(form.get("rx_mbps")),
      tx_mbps: Number(form.get("tx_mbps")),
      consecutive: Number(form.get("consecutive")),
      recovery_ratio: Number(form.get("recovery_ratio")),
      cooldown_s: Number(form.get("cooldown_s")),
    };
    setBusy(true);
    setSaved(false);
    setError("");
    try {
      await post("/alerts/rule", draft, "PUT");
      setSaved(true);
      done();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <form
      className="panel-body form-stack"
      onSubmit={save}
      onChange={() => setSaved(false)}
    >
      <label className="check">
        <input type="checkbox" name="enabled" defaultChecked={rule.enabled} />
        启用流量阈值告警
      </label>
      <div className="form-grid">
        {(
          [
            { key: "rx_mbps", name: "下载阈值 (Mbit/s)", step: "any" },
            { key: "tx_mbps", name: "上传阈值 (Mbit/s)", step: "any" },
            { key: "consecutive", name: "连续样本数（1–120）", step: "1" },
            {
              key: "recovery_ratio",
              name: "恢复比例（大于 0 且小于 1）",
              step: "any",
            },
            { key: "cooldown_s", name: "冷却时间（秒）", step: "1" },
          ] as const
        ).map((f) => (
          <Field
            key={f.key}
            label={f.name}
            type="number"
            step={f.step}
            required
            min={f.key === "consecutive" ? 1 : 0}
            max={
              {
                rx_mbps: 10000000,
                tx_mbps: 10000000,
                consecutive: 120,
                recovery_ratio: 1,
                cooldown_s: 3600,
              }[f.key]
            }
            name={f.key}
            defaultValue={rule[f.key]}
          />
        ))}
      </div>
      {error && <Notice>{error}</Notice>}
      {saved && <Notice tone="success">规则已保存。</Notice>}
      <div>
        <button className="primary" disabled={busy}>
          保存规则
        </button>
      </div>
    </form>
  );
}
export function Alerts() {
  const rows = useResource<{ items: AlertRow[] }>("/alerts", 3500),
    rule = useResource<Rule>("/alerts/rule");
  const [filter, setFilter] = useState("all"),
    [diagnosed, setDiagnosed] = useState<number | null>(null),
    [busy, setBusy] = useState(0),
    [error, setError] = useState("");
  const items = (rows.data?.items ?? []).filter(
    (a) =>
      filter === "all" ||
      (filter === "active" ? !a.recovered_at : !a.acknowledged),
  );
  async function ack(id: number) {
    setBusy(id);
    setError("");
    try {
      await post("/alerts/" + id + "/ack");
      rows.reload();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(0);
    }
  }
  return (
    <>
      <Heading
        title="异常告警"
        desc="配置持续超限检测，确认事件并查看对应的指标诊断。"
      />
      <div className="alerts-grid">
        <Panel
          title="告警历史"
          icon={BellRing}
          action={
            <select
              aria-label="告警筛选"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            >
              <option value="all">全部事件</option>
              <option value="active">当前活动</option>
              <option value="unread">未确认</option>
            </select>
          }
        >
          {(error || rows.error) && (
            <div className="panel-body">
              <Notice>{error || rows.error}</Notice>
            </div>
          )}
          {items.length ? (
            <div className="alert-list">
              {items.map((a) => (
                <article key={a.id}>
                  <div className="flex-between">
                    <div className="inline">
                      <Tag tone={a.recovered_at ? "neutral" : "warn"}>
                        {a.end_reason === "rule_changed"
                          ? "规则已变更"
                          : a.recovered_at
                            ? "已恢复"
                            : "活动中"}
                      </Tag>
                      <span className="hint">{clock(a.ts, true)}</span>
                    </div>
                    {a.acknowledged ? (
                      <span className="hint">已确认</span>
                    ) : (
                      <button
                        className="btn"
                        disabled={busy === a.id}
                        onClick={() => void ack(a.id)}
                      >
                        <Check size={13} />
                        确认
                      </button>
                    )}
                  </div>
                  <h3>{a.message}</h3>
                  <p>
                    {a.interface} · {a.kind}
                  </p>
                  <div className="advice">
                    <ShieldCheck size={14} />
                    {a.advice}
                  </div>
                  <button
                    className="btn-link"
                    aria-expanded={diagnosed === a.id}
                    onClick={() =>
                      setDiagnosed(diagnosed === a.id ? null : a.id)
                    }
                  >
                    {diagnosed === a.id ? "收起诊断" : "查看诊断依据"}
                  </button>
                  {diagnosed === a.id && <AlertDiagnosis id={a.id} />}
                </article>
              ))}
            </div>
          ) : (
            !rows.error && (
              <Empty
                busy={rows.busy}
                title={rows.busy ? "正在读取告警" : "暂无符合条件的告警"}
                detail="事件触发、恢复和确认状态将在此保留。"
              />
            )
          )}
        </Panel>
        <Panel
          title="阈值规则"
          icon={ListChecks}
          desc="规则应用于全部正在采样的网卡。"
        >
          {rule.error && (
            <div className="panel-body">
              <Notice>{rule.error}</Notice>
            </div>
          )}
          {rule.data ? (
            <RuleForm
              rule={rule.data}
              done={() => {
                rule.reload();
                rows.reload();
              }}
            />
          ) : (
            !rule.error && <Empty title="正在读取规则" busy />
          )}
        </Panel>
      </div>
    </>
  );
}
