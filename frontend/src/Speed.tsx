import { useState, type FormEvent } from "react";
import {
  ArrowDownLeft,
  ArrowUpRight,
  Clock3,
  Gauge,
  History,
  Play,
  Server,
} from "lucide-react";
import {
  type Speed as SpeedState,
  type TestResult,
  post,
  useResource,
  scopeNames,
  errorText,
} from "./data";
import { clock, Empty, Field, Heading, Notice, num, Panel, Tag } from "./ui";

export function SpeedTable({ rows }: { rows: TestResult[] }) {
  return rows.length ? (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            {["测试时间", "目标", "范围", "延迟", "下载", "上传"].map((h) => (
              <th key={h}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i}>
              <td className="mono">{clock(r.at, true)}</td>
              <td>{r.target}</td>
              <td>{scopeNames[r.scope] ?? r.scope}</td>
              <td>{num(r.latency_ms)} ms</td>
              <td>{num(r.download_mbps)} Mbit/s</td>
              <td>{num(r.upload_mbps)} Mbit/s</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  ) : (
    <Empty title="暂无测速记录" detail="完成一次测试后，结果将保存在本机。" />
  );
}
const phases: Record<string, string> = {
  idle: "等待启动",
  latency: "测量往返延迟",
  download: "测量下载吞吐量",
  upload: "测量上传吞吐量",
  complete: "测试完成",
  error: "测试失败",
};
export function Speed() {
  const state = useResource<SpeedState>("/speed", 900),
    hist = useResource<TestResult[]>("/speed/history", 3500);
  const [target, setTarget] = useState("http://127.0.0.1:8766"),
    [token, setToken] = useState(""),
    [sending, setSending] = useState(false),
    [err, setErr] = useState("");
  const run = async (e: FormEvent) => {
    e.preventDefault();
    setSending(true);
    setErr("");
    try {
      await post("/speed", { target: target.trim(), token });
      state.reload();
      hist.reload();
    } catch (e) {
      setErr(errorText(e));
    } finally {
      setSending(false);
    }
  };
  const s = state.data,
    result = s?.result,
    progress = Math.min(100, Math.max(0, s?.progress ?? 0)),
    busy = s?.running || sending;
  return (
    <>
      <Heading
        title="性能测试"
        desc="通过 NetScope 配对服务测量 HTTP 往返延迟，以及双向应用层吞吐量。"
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
                placeholder="http://127.0.0.1:8766"
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
              <span className="hint">
                回环地址用于本机验证。输入另一台受控计算机的服务地址可测量两端链路。
              </span>
              <div>
                <button className="primary" disabled={busy || !s}>
                  <Play size={14} />
                  {busy ? "测试进行中" : "开始测试"}
                </button>
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
                  ["latency", "往返延迟"],
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
                <div className="panel-note flush">
                  测量范围 · {scopeNames[result.scope]} /{" "}
                  {clock(result.at, true)}
                </div>
              )}
            </div>
          </Panel>
        </div>
        <div className="triad">
          {[
            {
              name: "往返延迟",
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
              <div className="metric-detail">本次测试结果</div>
            </div>
          ))}
        </div>
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
