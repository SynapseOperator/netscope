import { useEffect, useRef } from "react";
import * as echarts from "echarts/core";
import { LineChart } from "echarts/charts";
import { GridComponent, TooltipComponent } from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";
import { clock, Empty, rate } from "./ui";
echarts.use([LineChart, GridComponent, TooltipComponent, CanvasRenderer]);
export type PlotPoint = {
  ts: number;
  rx_bps: number | null;
  tx_bps: number | null;
};
export function TrafficChart({
  points,
  dark = false,
  period = 0,
  step = 1,
  onInspect,
}: {
  points: PlotPoint[];
  dark?: boolean;
  period?: number;
  step?: number;
  onInspect?: (second: number) => void;
}) {
  const host = useRef<HTMLDivElement | null>(null),
    instance = useRef<echarts.EChartsType | null>(null);
  useEffect(() => {
    if (!host.current) return;
    const graph = echarts.init(host.current, undefined, { renderer: "canvas" });
    instance.current = graph;
    const obs = new ResizeObserver(() => graph.resize());
    obs.observe(host.current);
    return () => {
      obs.disconnect();
      graph.dispose();
      instance.current = null;
    };
  }, []);
  useEffect(() => {
    const graph = instance.current;
    if (!graph || !onInspect) return;
    const selectPoint = (event: { offsetX: number; offsetY: number }) => {
      const pixel = [event.offsetX, event.offsetY];
      if (!graph.containPixel({ gridIndex: 0 }, pixel)) return;
      const [milliseconds] = graph.convertFromPixel(
        { gridIndex: 0 },
        pixel,
      ) as number[];
      const nearest = points.reduce<PlotPoint | null>(
        (best, point) =>
          point.rx_bps === null && point.tx_bps === null
            ? best
            : !best ||
                Math.abs(point.ts * 1000 - milliseconds) <
                  Math.abs(best.ts * 1000 - milliseconds)
              ? point
              : best,
        null,
      );
      if (nearest && Math.abs(nearest.ts * 1000 - milliseconds) <= 3000)
        onInspect(nearest.ts);
    };
    graph.getZr().on("click", selectPoint);
    return () => {
      if (!graph.isDisposed()) graph.getZr().off("click", selectPoint);
    };
  }, [points, onInspect]);
  useEffect(() => {
    const graph = instance.current;
    if (!graph) return;
    const token = (id: string) =>
      getComputedStyle(document.documentElement).getPropertyValue(id).trim();
    const latest = points.at(-1)?.ts ?? 0;
    const filtered = period
      ? points.filter((p) => p.ts >= latest - period)
      : points;
    // Explicit breaks keep sleeping adapters and unobserved intervals visible as gaps.
    const visible: PlotPoint[] = [];
    for (const p of filtered) {
      const prev = visible.at(-1);
      if (prev && p.ts - prev.ts > step * 2.5)
        visible.push({ ts: (prev.ts + p.ts) / 2, rx_bps: null, tx_bps: null });
      visible.push(p);
    }
    const max = Math.max(
      1,
      ...visible.map((p) => Math.max(p.tx_bps ?? 0, p.rx_bps ?? 0)),
    );
    const k = max >= 1e9 ? 1e9 : max >= 1e6 ? 1e6 : max >= 1e3 ? 1e3 : 1;
    const unit = rate(max).unit;
    const series = (name: string, key: "rx_bps" | "tx_bps", color: string) => ({
      type: "line",
      name,
      data: visible.map((p) => [
        p.ts * 1000,
        p[key] == null ? null : p[key] / k,
      ]),
      showSymbol: visible.length < 4,
      symbolSize: 4,
      connectNulls: false,
      lineStyle: { width: 2, color },
      itemStyle: { color },
      areaStyle: {
        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
          { offset: 0, color },
          { offset: 1, color: token("--surface") },
        ]),
        opacity: 0.1,
      },
    });
    graph.setOption(
      {
        animation: false,
        color: [token("--blue"), token("--teal")],
        grid: { left: 54, right: 17, top: 28, bottom: 28 },
        textStyle: {
          fontFamily: getComputedStyle(document.documentElement).fontFamily,
        },
        tooltip: {
          trigger: "axis",
          confine: true,
          renderMode: "richText",
          backgroundColor: token("--surface"),
          borderColor: token("--line"),
          textStyle: { color: token("--ink"), fontSize: 11 },
          valueFormatter: (v: number | null) =>
            v == null
              ? "—"
              : v.toLocaleString("zh-CN", { maximumFractionDigits: 2 }) +
                " " +
                unit,
        },
        xAxis: {
          type: "time",
          ...(period && latest
            ? { min: (latest - period) * 1000, max: latest * 1000 }
            : {}),
          boundaryGap: false,
          splitNumber: 5,
          axisLabel: {
            color: token("--muted"),
            fontSize: 10,
            hideOverlap: true,
            formatter: (v: number) => clock(v / 1000),
          },
          axisLine: { lineStyle: { color: token("--line") } },
          splitLine: { show: false },
          axisTick: { show: false },
        },
        yAxis: {
          type: "value",
          min: 0,
          name: unit,
          nameLocation: "end",
          nameGap: 9,
          nameTextStyle: {
            color: token("--muted"),
            align: "right",
            fontSize: 10,
          },
          axisLabel: { color: token("--muted"), fontSize: 10 },
          splitNumber: 3,
          splitLine: {
            lineStyle: { color: token("--subtle"), type: "dashed" },
          },
        },
        series: [
          series("下载", "rx_bps", token("--blue")),
          series("上传", "tx_bps", token("--teal")),
        ],
      },
      true,
    );
  }, [points, dark, period, step]);
  return (
    <div className="chart-area">
      <div
        ref={host}
        className="chart"
        role="img"
        aria-label="下载与上传速率时间序列图"
      />
      {!points.some((p) => p.rx_bps != null || p.tx_bps != null) && (
        <div className="chart-overlay">
          <Empty title="等待有效速率样本" detail="图表将在采样完成后显示。" />
        </div>
      )}
    </div>
  );
}
