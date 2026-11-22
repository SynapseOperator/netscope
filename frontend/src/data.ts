import { useCallback, useEffect, useState } from "react";

export type User = { username: string };
export type Adapter = {
  name: string;
  up: boolean;
  speed_mbps: number | null;
  mtu: number | null;
  ipv4: string[];
  ipv6: string[];
  mac: string | null;
};
export type Sample = {
  ts: number;
  rx_bps: number | null;
  tx_bps: number | null;
  rx_bytes: number | null;
  tx_bytes: number | null;
  rx_packets: number | null;
  tx_packets: number | null;
};
export type Monitor = {
  selected: string | null;
  status: "collecting" | "warming" | "offline" | "error";
  message: string;
  interval: number;
  interfaces: Adapter[];
  series: Sample[];
  latest: Sample | null;
};
export type AlertRow = {
  id: number;
  ts: number;
  interface: string;
  kind: string;
  message: string;
  recovered_at: number | null;
  acknowledged: boolean;
  advice: string;
  end_reason?: string;
};
export type LogRow = { ts: number; action: string; message: string };
export type Rule = {
  enabled: boolean;
  rx_mbps: number;
  tx_mbps: number;
  consecutive: number;
  recovery_ratio: number;
  cooldown_s: number;
};
export type Count = { name: string; packets: number; bytes: number };
export type Capture = {
  state: "idle" | "running" | "stopped" | "imported" | "error";
  source: null | "live" | "pcap";
  interface: string | null;
  available: boolean;
  error: string | null;
  driver_note: string | null;
  total: number;
  bytes: number;
  capacity: number;
  protocols: Count[];
  endpoints: Count[];
};
export type Session = {
  id: number;
  source: string;
  interface: string | null;
  started_at: number;
  ended_at: number | null;
  total: number;
  bytes: number;
  protocols: Count[];
  endpoints: Count[];
};
export type Packet = {
  id: number;
  timestamp: number;
  network: string;
  protocol: string;
  src: string;
  dst: string;
  sport: number | null;
  dport: number | null;
  length: number;
  headers: Record<string, Record<string, string | number>>;
};
export type TestResult = {
  at: number;
  target: string;
  scope: "loopback" | "lan" | "internet";
  latency_ms: number;
  download_mbps: number;
  upload_mbps: number;
  mode?: "quick" | "repeated" | null;
  rounds?: number | null;
  download_cv_pct?: number | null;
  upload_cv_pct?: number | null;
};
export type Speed = {
  running: boolean;
  phase: string;
  progress: number;
  result: TestResult | null;
  error: string | null;
};
export const scopeNames: Record<TestResult["scope"], string> = {
  loopback: "本机回环",
  lan: "局域网",
  internet: "互联网",
};
export const statusNames: Record<Monitor["status"], string> = {
  collecting: "采集中",
  warming: "建立基线",
  offline: "接口离线",
  error: "采集异常",
};
export type Page =
  | "dashboard"
  | "devices"
  | "packets"
  | "speed"
  | "history"
  | "alerts"
  | "settings";
export const pages: Record<Page, string> = {
  dashboard: "网络总览",
  devices: "网络设备",
  packets: "报文分析",
  speed: "性能测试",
  history: "历史报告",
  alerts: "异常告警",
  settings: "设置",
};
export const errorText = (e: unknown) =>
  e instanceof Error ? e.message : "请求未完成，请重试。";
export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}
export async function api<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  let response: Response;
  try {
    response = await fetch("/api" + path, {
      ...options,
      headers: {
        ...(options.body && typeof options.body === "string"
          ? { "Content-Type": "application/json" }
          : {}),
        ...options.headers,
      },
    });
  } catch (e) {
    if (options.signal?.aborted) throw e;
    throw new ApiError(0, "无法连接本地服务，请检查服务是否运行。");
  }
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    const detail = body?.detail;
    const message =
      typeof detail === "string"
        ? detail
        : Array.isArray(detail)
          ? detail
              .map((i: { msg?: string }) => i.msg)
              .filter(Boolean)
              .join(" · ")
          : "服务请求失败（HTTP " + response.status + "）";
    if (response.status === 401 && !path.startsWith("/auth/"))
      window.dispatchEvent(new Event("netscope-session-ended"));
    throw new ApiError(response.status, message);
  }
  return (response.status === 204 ? null : await response.json()) as T;
}
export const post = <T>(path: string, body?: unknown, method = "POST") =>
  api<T>(path, {
    method,
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
export function useResource<T>(path: string | null, everyMs = 0) {
  const [version, update] = useState(0);
  const [entry, setEntry] = useState<{
    path: string;
    data?: T;
    error?: string;
  }>();
  const reload = useCallback(() => update((v) => v + 1), []);
  useEffect(() => {
    if (!path) return;
    const ctl = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    const read = async () => {
      try {
        const data = await api<T>(path, { signal: ctl.signal });
        if (!ctl.signal.aborted) setEntry({ path, data });
      } catch (e) {
        if (!ctl.signal.aborted)
          setEntry((old) => ({
            path,
            data: old?.path === path ? old.data : undefined,
            error: errorText(e),
          }));
      }
      if (everyMs && !ctl.signal.aborted) timer = setTimeout(read, everyMs);
    };
    void read();
    return () => {
      ctl.abort();
      clearTimeout(timer);
    };
  }, [path, everyMs, version]);
  const result = entry?.path === path ? entry : undefined;
  return {
    data: result?.data,
    error: result?.error,
    busy: !!path && !result,
    reload,
  };
}
export function useMonitor() {
  const [data, setData] = useState<Monitor | null>(null);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState("");
  const [version, restart] = useState(0);
  useEffect(() => {
    let active = true,
      retry: ReturnType<typeof setTimeout>,
      socket: WebSocket | undefined;
    const ctl = new AbortController();
    const connect = async () => {
      try {
        const current = await api<Monitor>("/monitor", { signal: ctl.signal });
        if (active) {
          setData(current);
          setError("");
        }
      } catch (e) {
        if (active) setError(errorText(e));
      }
      if (!active) return;
      socket = new WebSocket(
        (location.protocol === "https:" ? "wss://" : "ws://") +
          location.host +
          "/api/live",
      );
      socket.onmessage = (event) => {
        if (!active) return;
        try {
          const next = JSON.parse(event.data) as Monitor;
          if (Array.isArray(next.series)) {
            setData(next);
            setConnected(true);
            setError("");
          }
        } catch {
          setError("收到无法读取的采集状态。");
        }
      };
      socket.onclose = () => {
        if (active) {
          setConnected(false);
          setError("实时连接中断，正在重新连接。");
          retry = setTimeout(connect, 2000);
        }
      };
      socket.onerror = () => socket?.close();
    };
    void connect();
    return () => {
      active = false;
      ctl.abort();
      clearTimeout(retry);
      socket?.close();
    };
  }, [version]);
  return {
    data,
    connected,
    error,
    select: async (name: string) => {
      setData(await post<Monitor>("/monitor/interface", { name }, "PUT"));
      restart((x) => x + 1);
    },
  };
}
export type Live = ReturnType<typeof useMonitor>;
