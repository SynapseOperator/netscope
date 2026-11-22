import { type AlertRow, useResource } from "./data";
import { bytes, clock, Empty, Notice, num, rate } from "./ui";
import { type AnalysisWindow, historyLink } from "./timeWindow";

type Diagnosis = {
  event: AlertRow & {
    observation?: {
      observed_bps?: number;
      threshold_bps?: number;
      consecutive?: number;
      gap_seconds?: number;
    } | null;
  };
  window: AnalysisWindow;
  counter: {
    minutes: number;
    seconds: number;
    rx_bytes: number;
    tx_bytes: number;
  } | null;
  capture: {
    status: string;
    total: number | null;
    bytes: number | null;
    endpoints: { name: string }[];
  } | null;
  speed_tests: {
    started_at: number;
    ended_at: number;
    mode: string;
    download_mbps: number;
    upload_mbps: number;
  }[];
  possible: string;
  check: string;
  limitations: string[];
};
const speedText = (n: number) => {
  const r = rate(n);
  return r.value + " " + r.unit;
};

export function AlertDiagnosis({ id }: { id: number }) {
  const { data, error } = useResource<Diagnosis>(
    "/alerts/" + id + "/diagnosis",
  );
  if (error) return <Notice>{error}</Notice>;
  if (!data) return <Empty busy title="正在关联事件记录" />;
  const { event, window, counter, capture } = data;
  const observed = event.observation;
  return (
    <section className="diagnosis" aria-label="事件诊断依据">
      <h4>已观测事实</h4>
      <p>
        {window.interface || "整机采集"} · {clock(window.start, true)} 至{" "}
        {clock(window.end, true)}（本地时间）
      </p>
      <dl>
        <dt>触发条件 · 系统采样</dt>
        <dd>
          {observed?.observed_bps != null && observed.threshold_bps != null
            ? `连续 ${observed.consecutive} 个有效样本超出 ${speedText(observed.threshold_bps)}，触发时为 ${speedText(observed.observed_bps)}。`
            : event.message}
        </dd>
        {counter && (
          <>
            <dt>网卡计数器 · 分钟聚合</dt>
            <dd>
              {counter.minutes} 个分钟桶，有效采样 {num(counter.seconds)}{" "}
              s。接收 {bytes(counter.rx_bytes)}，发送 {bytes(counter.tx_bytes)}
              。
            </dd>
          </>
        )}
        {capture?.total != null && (
          <>
            <dt>同接口捕获 · 报文时间</dt>
            <dd>
              {capture.status === "partial" ? "已定位至少 " : "已捕获 "}
              {num(capture.total)} 个报文，合计 {bytes(capture.bytes)}。
              {capture.endpoints[0]?.name &&
                "高流量端点：" + capture.endpoints[0].name}
            </dd>
          </>
        )}
        {data.speed_tests.length > 0 && (
          <>
            <dt>同接口测速 · 与窗口重叠的最近记录</dt>
            {data.speed_tests.map((s, i) => (
              <dd key={i}>
                {clock(s.started_at)} 至 {clock(s.ended_at)}，下载{" "}
                {num(s.download_mbps)}、上传 {num(s.upload_mbps)}{" "}
                Mbit/s（整次测试）。
              </dd>
            ))}
          </>
        )}
      </dl>
      {data.limitations.length > 0 && (
        <div className="diagnosis-limit">
          <strong>证据范围</strong>
          <ul>
            {data.limitations.map((note) => (
              <li key={note}>{note}</li>
            ))}
          </ul>
        </div>
      )}
      <h4>可能解释</h4>
      <p>{data.possible}</p>
      <h4>建议检查</h4>
      <p>{data.check}</p>
      {window.interface && (
        <div className="diagnosis-links">
          <a className="btn-link" href={historyLink(window, "traffic")}>
            同期网卡记录
          </a>
          <a className="btn-link" href={historyLink(window)}>
            同期抓包与端点
          </a>
        </div>
      )}
    </section>
  );
}
