export type AnalysisWindow = { start: number; end: number; interface: string };

export function historyLink(
  range: AnalysisWindow,
  tab: "captures" | "traffic" = "captures",
) {
  const params = new URLSearchParams({
    tab,
    start: String(range.start),
    end: String(range.end),
    interface: range.interface,
  });
  return "#history?" + params;
}

export function readWindow(params: URLSearchParams): AnalysisWindow | null {
  const start = Number(params.get("start"));
  const end = Number(params.get("end"));
  if (
    !params.has("start") ||
    !Number.isFinite(start) ||
    !Number.isFinite(end) ||
    start < 0 ||
    end <= start ||
    end > 253402300799
  )
    return null;
  return { start, end, interface: params.get("interface") || "" };
}
