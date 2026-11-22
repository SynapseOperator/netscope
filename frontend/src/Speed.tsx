import { Fragment, useState, type FormEvent } from "react";
import {
  ArrowDownLeft,
  ArrowUpRight,
  Clock3,
  Gauge,
  History,
  Play,
  Server,
  Square,
  Waves,
} from "lucide-react";
import {
  type Speed as SpeedState,
  type SpeedSegment,
  type TestResult,
  post,
  useResource,
  scopeNames,
  errorText,
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
import "./analysis.css";
import { historyLink } from "./timeWindow";

function modeName(r: TestResult) {
  if (r.mode === "sustained")
    return "持续 · 每方向 " + num(r.duration_s) + " 秒";
  if (r.mode === "repeated") return "重复 · " + num(r.rounds) + " 轮";
  return "快速单轮";
}
function measured(value: number | null | undefined, unit: string) {
  return value == null ? "—" : num(value) + " " + unit;
}
function Measurement({ result: r }: { result: TestResult }) {
  return (
    <div className="test-evidence">
      <div>
        <h3>HTTP 往返延迟</h3>
        <dl className="kv">
          <div>
            <dt>空闲中位 RTT</dt>
            <dd>{measured(r.latency_ms, "ms")}</dd>
          </div>
          <div>
            <dt>负载中位 RTT</dt>
            <dd>{measured(r.loaded_latency_ms, "ms")}</dd>
          </div>
          <div>
            <dt>负载 − 空闲</dt>
            <dd>{measured(r.latency_delta_ms, "ms")}</dd>
          </div>
          <div>
            <dt>空闲 / 负载波动</dt>
            <dd>
              {measured(r.idle_jitter_ms, "ms")} /{" "}
              {measured(r.loaded_jitter_ms, "ms")}
            </dd>
          </div>
          <div>
            <dt>有效负载探针</dt>
            <dd>{measured(r.loaded_samples, "个")}</dd>
          </div>
        </dl>
      </div>
      <div>
        <h3>实际传输</h3>
        <dl className="kv">
          <div>
            <dt>下载字节 / 耗时</dt>
            <dd>
              {bytes(r.download_bytes)} / {measured(r.download_seconds, "s")}
            </dd>
          </div>
          <div>
            <dt>上传字节 / 耗时</dt>
            <dd>
              {bytes(r.upload_bytes)} / {measured(r.upload_seconds, "s")}
            </dd>
          </div>
          <div>
            <dt>下载 / 上传吞吐变异系数</dt>
            <dd>
              {measured(r.download_cv_pct, "%")} /{" "}
              {measured(r.upload_cv_pct, "%")}
            </dd>
          </div>
          <div>
            <dt>测试窗口</dt>
            <dd>
              {clock(r.started_at, true)} – {clock(r.ended_at, true)}
            </dd>
          </div>
          <div>
            <dt>传输接口</dt>
            <dd>{r.interface || "未记录"}</dd>
          </div>
        </dl>
      </div>
      {r.started_at != null && r.ended_at != null && r.interface && (
        <div className="speed-history-link">
          <a
            href={historyLink(
              { start: r.started_at, end: r.ended_at, interface: r.interface },
              "captures",
            )}
          >
            查看同网卡、同时段的抓包记录
          </a>
          <span>网卡分钟聚合覆盖完整分钟，测速结果按实际传输窗口计算。</span>
        </div>
      )}
    </div>
  );
}
function SegmentPlot({ segments }: { segments: SpeedSegment[] }) {
  const peak = Math.max(1, ...segments.map((s) => s.mbps));
  return (
    <div className="segment-plot">
      {(["download", "upload"] as const).map((direction) => {
        const rows = segments.filter((s) => s.direction === direction),
          label = direction === "download" ? "下载" : "上传";
        return (
          <div key={direction}>
            <div className="flex-between">
              <strong>{label}分段</strong>
              <span className="hint">{rows.length} 段</span>
            </div>
            {rows.length ? (
              <div
                className={"segment-bars " + direction}
                role="list"
                aria-label={label + "分段吞吐量"}
              >
                {rows.map((s, i) => (
                  <span
                    role="listitem"
                    key={i}
                    title={
                      label +
                      " · 第 " +
                      (i + 1) +
                      " 段 · 累计 " +
                      num(s.elapsed_s) +
                      " s · " +
                      bytes(s.bytes) +
                      " · " +
                      measured(s.mbps, "Mbit/s")
                    }
                  >
                    <i
                      style={{
                        height: Math.max(2, (100 * s.mbps) / peak) + "%",
                      }}
                    />
                  </span>
                ))}
              </div>
            ) : (
              <p className="hint">等待分段样本</p>
            )}
            {rows.length > 0 && (
              <div className="segment-stats">
                {measured(rows.at(-1)?.elapsed_s, "s")} 已测量 · 最近一段{" "}
                {measured(rows.at(-1)?.mbps, "Mbit/s")}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
export function SpeedTable({ rows }: { rows: TestResult[] }) {
  const [expanded, setExpanded] = useState<number | null>(null);
  return rows.length ? (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            {[
              "测试时间",
              "目标",
              "范围与方式",
              "空闲 RTT",
              "下载",
              "上传",
              "测量详情",
            ].map((h) => (
              <th key={h}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <Fragment key={r.at + "-" + i}>
              <tr>
                <td className="mono">{clock(r.at, true)}</td>
                <td>{r.target}</td>
                <td>
                  {scopeNames[r.scope] ?? r.scope} · {modeName(r)}
                </td>
                <td>{measured(r.latency_ms, "ms")}</td>
                <td>{measured(r.download_mbps, "Mbit/s")}</td>
                <td>{measured(r.upload_mbps, "Mbit/s")}</td>
                <td>
                  <button
                    className="btn-link"
                    aria-expanded={expanded === r.at}
                    onClick={() => setExpanded(expanded === r.at ? null : r.at)}
                  >
                    {expanded === r.at ? "收起" : "展开"}
                  </button>
                </td>
              </tr>
              {expanded === r.at && (
                <tr>
                  <td colSpan={7} className="measurement-detail">
                    <Measurement result={r} />
                    {r.limit_reached && (
                      <p className="hint">
                        达到单方向字节上限，记录按实际传输计算。
                      </p>
                    )}
                    {!!r.segments?.length && (
                      <SegmentPlot segments={r.segments} />
                    )}
                  </td>
                </tr>
              )}
            </Fragment>
          ))}
        </tbody>
      </table>
    </div>
  ) : (
    <Empty title="暂无测速记录" detail="成功完成测试后可查看完整结果。" />
  );
}
const phases: Record<string, string> = {
  idle: "等待启动",
  latency: "测量空闲延迟",
  download: "测量下载吞吐量",
  upload: "测量上传吞吐量",
  complete: "测试完成",
  cancelled: "已取消",
  error: "测试失败",
};
export function Speed() {
  const state = useResource<SpeedState>("/speed", 650),
    hist = useResource<TestResult[]>("/speed/history", 3000);
  const [target, setTarget] = useState("http://127.0.0.1:8766"),
    [token, setToken] = useState(""),
    [mode, setMode] = useState("quick"),
    [duration, setDuration] = useState(5),
    [pending, setPending] = useState(false),
    [err, setErr] = useState("");
  async function command(path: string, body?: unknown) {
    setErr("");
    setPending(true);
    try {
      await post(path, body);
      state.reload();
      hist.reload();
    } catch (e) {
      setErr(errorText(e));
    } finally {
      setPending(false);
    }
  }
  function run(e: FormEvent) {
    e.preventDefault();
    void command("/speed", {
      target: target.trim(),
      token,
      mode,
      ...(mode === "sustained" ? { duration_s: duration } : {}),
    });
  }
  const s = state.data,
    result = s?.result,
    progress = Math.min(100, Math.max(0, s?.progress ?? 0)),
    busy = s?.running || pending,
    segments = result?.segments ?? s?.segments ?? [];
  return (
    <>
      <Heading
        title="性能测试"
        desc="使用受控配对服务测量 HTTP 往返延迟、负载延迟变化和双向应用层吞吐量。"
      />
      <div className="stack">
        {(err || state.error || s?.error) && (
          <Notice>{err || state.error || s?.error}</Notice>
        )}
        <div className="duo">
          <Panel
            title="受控测试目标"
            icon={Server}
            desc="使用目标电脑启动测速服务时显示的配对密钥。"
          >
            <form className="form-stack panel-body" onSubmit={run}>
              <Field
                label="目标服务地址"
                type="url"
                required
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                disabled={busy}
              />
              <Field
                label="配对密钥"
                type="password"
                required
                minLength={12}
                maxLength={128}
                value={token}
                onChange={(e) => setToken(e.target.value)}
                autoComplete="off"
                disabled={busy}
              />
              <div className="mode-fields">
                <label className="field">
                  <span>测试方式</span>
                  <select
                    value={mode}
                    onChange={(e) => setMode(e.target.value)}
                    disabled={busy}
                    aria-label="测试方式"
                  >
                    <option value="quick">快速 · 每方向 4 MiB</option>
                    <option value="repeated">重复 · 每方向 8 轮</option>
                    <option value="sustained">持续吞吐</option>
                  </select>
                </label>
                {mode === "sustained" && (
                  <label className="field">
                    <span>每方向持续时间</span>
                    <select
                      aria-label="每方向持续时间"
                      value={duration}
                      onChange={(e) => setDuration(Number(e.target.value))}
                      disabled={busy}
                    >
                      <option value="5">5 秒</option>
                      <option value="10">10 秒</option>
                    </select>
                  </label>
                )}
              </div>
              <p className="hint">
                {mode === "sustained"
                  ? "按下载、上传顺序测量。每方向最多 512 MiB，达到时间或字节上限后结束。"
                  : mode === "repeated"
                    ? "每方向传输 8 轮，每轮 4 MiB，按各轮实测吞吐量计算波动。"
                    : "每方向传输一轮。回环目标用于验证本机服务。"}
              </p>
              <div>
                {s?.running ? (
                  <button
                    type="button"
                    className="btn"
                    disabled={pending}
                    onClick={() => void command("/speed/cancel")}
                  >
                    <Square size={14} />
                    取消测试
                  </button>
                ) : (
                  <button className="primary" disabled={pending || !s}>
                    <Play size={14} />
                    开始测试
                  </button>
                )}
              </div>
            </form>
          </Panel>
          <Panel
            title="测试进度"
            icon={Gauge}
            action={
              <Tag
                tone={
                  s?.running
                    ? "blue"
                    : s?.phase === "complete"
                      ? "good"
                      : "neutral"
                }
              >
                {s ? (phases[s.phase] ?? s.phase) : "读取中"}
              </Tag>
            }
          >
            <div className="panel-body">
              <div className="progress-large">
                <strong>{num(progress)}</strong>
                <span>%</span>
              </div>
              <progress aria-label="测试进度" max="100" value={progress} />
              <div className="phase-list">
                {[
                  ["latency", "空闲 RTT"],
                  ["download", "下载测试"],
                  ["upload", "上传测试"],
                ].map(([key, v], i) => (
                  <span key={key} className={s?.phase === key ? "current" : ""}>
                    <i>{i + 1}</i>
                    {v}
                  </span>
                ))}
              </div>
              {result && (
                <p className="panel-note flush">
                  {scopeNames[result.scope]} · {modeName(result)} ·{" "}
                  {clock(result.at, true)}
                  {result.limit_reached && " · 已达字节上限"}
                </p>
              )}
              {s?.phase === "cancelled" && (
                <p className="hint">测试已停止，本次未生成完整测速记录。</p>
              )}
              {!!segments.length && <SegmentPlot segments={segments} />}
            </div>
          </Panel>
        </div>
        <div className="triad">
          {[
            {
              name: "空闲中位 RTT",
              val: result?.latency_ms,
              unit: "ms",
              icon: Clock3,
              color: "violet",
            },
            {
              name: "下载吞吐量",
              val: result?.download_mbps,
              unit: "Mbit/s",
              icon: ArrowDownLeft,
              color: "blue",
            },
            {
              name: "上传吞吐量",
              val: result?.upload_mbps,
              unit: "Mbit/s",
              icon: ArrowUpRight,
              color: "teal",
            },
          ].map(({ name, val, unit, icon: Icon, color }) => (
            <div key={name} className={"metric " + color}>
              <div className="metric-label">
                <span className="metric-icon">
                  <Icon size={16} />
                </span>
                {name}
              </div>
              <div className="metric-value">
                {num(val)} <small>{unit}</small>
              </div>
              <div className="metric-detail">本次完整测量</div>
            </div>
          ))}
        </div>
        {result && (
          <Panel
            title="测量依据"
            icon={Waves}
            desc="RTT 为配对 HTTP 往返时间。波动取相邻 RTT 之差绝对值的均值。样本不足时显示空值。"
          >
            <div className="panel-body">
              <Measurement result={result} />
            </div>
          </Panel>
        )}
        <Panel title="测速历史" icon={History}>
          {hist.error && (
            <div className="panel-body">
              <Notice>{hist.error}</Notice>
            </div>
          )}
          {hist.busy ? (
            <Empty busy title="正在读取测试历史" />
          ) : (
            hist.data && <SpeedTable rows={hist.data} />
          )}
        </Panel>
      </div>
    </>
  );
}
