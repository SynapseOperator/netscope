import { useId, type ReactNode, type InputHTMLAttributes } from "react";
import { Root as Label } from "@radix-ui/react-label";
import {
  Activity,
  AlertCircle,
  Check,
  CircleDashed,
  LoaderCircle,
  type LucideIcon,
} from "lucide-react";

export function Mark({ size = 36 }: { size?: number }) {
  return <img src="/netscope.svg" width={size} height={size} alt="" />;
}
export function Tag({
  children,
  tone = "neutral",
}: {
  children: ReactNode;
  tone?: "good" | "warn" | "danger" | "blue" | "neutral";
}) {
  return (
    <span className={"tag " + tone}>
      <i />
      {children}
    </span>
  );
}
export function Notice({
  children,
  tone = "error",
}: {
  children: ReactNode;
  tone?: "error" | "info" | "success";
}) {
  const Icon =
    tone === "success" ? Check : tone === "info" ? Activity : AlertCircle;
  return (
    <div
      role={tone === "error" ? "alert" : "status"}
      className={"notice " + tone}
    >
      <Icon size={16} />
      <span>{children}</span>
    </div>
  );
}
export function Empty({
  title,
  detail,
  busy = false,
}: {
  title: string;
  detail?: string;
  busy?: boolean;
}) {
  const Icon = busy ? LoaderCircle : CircleDashed;
  return (
    <div className="empty" role="status">
      <Icon className={busy ? "spin" : ""} size={23} />
      <strong>{title}</strong>
      {detail && <span>{detail}</span>}
    </div>
  );
}
export function Panel({
  title,
  icon: Icon,
  action,
  desc,
  children,
  className = "",
}: {
  title: string;
  icon?: LucideIcon;
  action?: ReactNode;
  desc?: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={"panel " + className}>
      <header className="panel-heading">
        <div>
          <h2>
            {Icon && <Icon size={17} />} {title}
          </h2>
          {desc && <p>{desc}</p>}
        </div>
        {action}
      </header>
      {children}
    </section>
  );
}
export function Heading({
  title,
  desc,
  action,
}: {
  title: string;
  desc: string;
  action?: ReactNode;
}) {
  return (
    <div className="page-head">
      <div>
        <h1>{title}</h1>
        <p>{desc}</p>
      </div>
      {action && <div className="page-actions">{action}</div>}
    </div>
  );
}
export function Field({
  label,
  ...props
}: InputHTMLAttributes<HTMLInputElement> & { label: string }) {
  const id = useId();
  return (
    <div className="field">
      <Label htmlFor={id}>{label}</Label>
      <input id={id} {...props} />
    </div>
  );
}
const fmt = new Intl.NumberFormat("zh-CN", { maximumFractionDigits: 2 });
export function rate(n?: number | null) {
  if (n == null) return { value: "—", unit: "bit/s" };
  const k = n >= 1e9 ? 3 : n >= 1e6 ? 2 : n >= 1000 ? 1 : 0;
  return {
    value: fmt.format(n / 1000 ** k),
    unit: ["bit/s", "Kbit/s", "Mbit/s", "Gbit/s"][k],
  };
}
export function bytes(n?: number | null) {
  if (n == null) return "—";
  const k = n >= 2 ** 30 ? 3 : n >= 2 ** 20 ? 2 : n >= 1024 ? 1 : 0;
  return fmt.format(n / 1024 ** k) + " " + ["B", "KiB", "MiB", "GiB"][k];
}
export const num = (n: number | null | undefined) =>
  n == null ? "—" : fmt.format(n);
export function clock(ts?: number | null, day = false) {
  if (ts == null) return "—";
  const date = new Date(ts * 1000);
  return (
    (day
      ? date.toLocaleDateString("zh-CN", { month: "2-digit", day: "2-digit" }) +
        " "
      : "") + date.toLocaleTimeString("zh-CN", { hour12: false })
  );
}
