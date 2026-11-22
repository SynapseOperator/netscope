import { useEffect, useState, type FormEvent } from "react";
import {
  Activity,
  ArrowRight,
  Bell,
  Cable,
  ChevronDown,
  ChevronRight,
  Database,
  FileClock,
  Gauge,
  Layers3,
  LayoutDashboard,
  LockKeyhole,
  LogOut,
  Menu,
  Moon,
  Network,
  PanelLeft,
  Radio,
  RefreshCw,
  Settings as Cog,
  Sun,
  UserRound,
  type LucideIcon,
} from "lucide-react";
import {
  ApiError,
  type Live,
  type LogRow,
  type Page,
  type User,
  api,
  errorText,
  pages,
  post,
  useMonitor,
  useResource,
} from "./data";
import { AdapterPicker, Devices, Overview } from "./Overview";
import { Packets } from "./Packets";
import { Speed } from "./Speed";
import { Alerts, Reports } from "./Reports";
import { clock, Empty, Field, Heading, Mark, Notice, Panel, Tag } from "./ui";

const navIcons: Record<Page, LucideIcon> = {
  dashboard: LayoutDashboard,
  devices: Network,
  packets: Layers3,
  speed: Gauge,
  history: FileClock,
  alerts: Bell,
  settings: Cog,
};
function readPage(): Page {
  const key = location.hash.slice(1);
  return Object.hasOwn(pages, key) ? (key as Page) : "dashboard";
}
function Auth({ onUser }: { onUser: (u: User) => void }) {
  const [register, setRegister] = useState(false),
    [name, setName] = useState(""),
    [pass, setPass] = useState(""),
    [busy, setBusy] = useState(false),
    [err, setErr] = useState("");
  const [canRegister, setCanRegister] = useState<boolean | null>(null);
  useEffect(() => {
    let active = true;
    api<{ needs_initial_account: boolean }>("/auth/setup")
      .then((status) => {
        if (active) setCanRegister(status.needs_initial_account);
      })
      .catch(() => {
        if (active) setCanRegister(null);
      });
    return () => { active = false; };
  }, []);
  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      onUser(
        await post<User>("/auth/" + (register ? "register" : "login"), {
          username: name.trim(),
          password: pass,
        }),
      );
    } catch (e) {
      setErr(errorText(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <main className="auth">
      <div className="auth-shell">
        <section className="auth-product">
          <div className="auth-brand">
            <Mark size={35} />
            <strong>NetScope</strong>
          </div>
          <div className="auth-intro">
            <div className="auth-symbol">
              <Activity size={48} />
            </div>
            <h1>网络监测工作台</h1>
            <p>
              在本机观察网卡流量、分析报文，
              <br />
              并验证网络性能。
            </p>
          </div>
          <div className="auth-flow">
            {[
              [Cable, "系统网卡"],
              [Activity, "实时采集"],
              [Database, "本地存储"],
            ].map(([I, label]) => {
              const Icon = I as LucideIcon;
              return (
                <div key={String(label)}>
                  <Icon size={18} />
                  <span>{String(label)}</span>
                </div>
              );
            })}
          </div>
        </section>
        <section className="auth-form">
          <span className="auth-lock">
            <LockKeyhole size={22} />
          </span>
          <h2>{register ? "创建本地账户" : "登录工作台"}</h2>
          <p>
            {register
              ? "使用此账户访问这台电脑上的 NetScope。"
              : "使用本地账户访问监测数据。"}
          </p>
          <form className="form-stack" onSubmit={submit}>
            <Field
              label="用户名"
              value={name}
              autoComplete="username"
              required
              minLength={register ? 2 : 1}
              maxLength={40}
              onChange={(e) => setName(e.target.value)}
            />
            <Field
              label="密码"
              type="password"
              value={pass}
              autoComplete={register ? "new-password" : "current-password"}
              required
              minLength={register ? 8 : 1}
              maxLength={128}
              onChange={(e) => setPass(e.target.value)}
            />
            {register && (
              <span className="hint">密码长度为 8 至 128 个字符。</span>
            )}
            {err && <Notice>{err}</Notice>}
            <button className="primary" disabled={busy}>
              {busy ? "正在提交…" : register ? "注册并登录" : "登录"}
              <ArrowRight size={15} />
            </button>
          </form>
          {canRegister !== false && (
            <p className="switch-auth">
              {register ? "已有账户？" : "首次使用？"}
              <button
                className="btn-link"
                disabled={busy}
                onClick={() => {
                  setRegister(!register);
                  setErr("");
                  setPass("");
                }}
              >
                {register ? "返回登录" : "创建账户"}
              </button>
            </p>
          )}
        </section>
      </div>
    </main>
  );
}
function Preferences({
  user,
  live,
  dark,
  setDark,
  logout,
}: {
  user: User;
  live: Live;
  dark: boolean;
  setDark: (v: boolean) => void;
  logout: () => Promise<void>;
}) {
  const logs = useResource<{ items: LogRow[] }>("/logs", 5000);
  const [error, setError] = useState(""),
    [leaving, setLeaving] = useState(false);
  const [newName, setNewName] = useState(""),
    [newPassword, setNewPassword] = useState(""),
    [adding, setAdding] = useState(false),
    [added, setAdded] = useState("");
  async function addAccount(e: FormEvent) {
    e.preventDefault();
    setAdding(true);
    setAdded("");
    setError("");
    try {
      await post("/auth/register", { username: newName.trim(), password: newPassword });
      setAdded("已创建本地账户：" + newName.trim());
      setNewName("");
      setNewPassword("");
    } catch (e) {
      setError(errorText(e));
    } finally {
      setAdding(false);
    }
  }
  return (
    <>
      <Heading title="设置" desc="管理本地账户、界面外观和当前采集配置。" />
      <div className="stack">
        <div className="duo">
          <Panel title="账户与外观" icon={UserRound}>
            <div className="panel-body">
              <dl className="kv">
                <div>
                  <dt>当前账户</dt>
                  <dd>{user.username}</dd>
                </div>
                <div>
                  <dt>登录范围</dt>
                  <dd>本地工作台</dd>
                </div>
                <div>
                  <dt>界面主题</dt>
                  <dd>
                    <div className="tabgroup">
                      <button
                        aria-pressed={!dark}
                        onClick={() => setDark(false)}
                      >
                        浅色
                      </button>
                      <button aria-pressed={dark} onClick={() => setDark(true)}>
                        深色
                      </button>
                    </div>
                  </dd>
                </div>
              </dl>
              <details className="panel-note">
                <summary>添加本地账户</summary>
                <p className="hint">新账户可以访问本机共享的监测数据。</p>
                <form className="form-stack" onSubmit={addAccount}>
                  <Field
                    label="新用户名"
                    value={newName}
                    onChange={(e) => setNewName(e.target.value)}
                    minLength={2}
                    maxLength={40}
                    required
                    autoComplete="off"
                  />
                  <Field
                    label="初始密码"
                    type="password"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    minLength={8}
                    maxLength={128}
                    required
                    autoComplete="new-password"
                  />
                  <button className="btn" disabled={adding}>
                    {adding ? "正在创建…" : "创建账户"}
                  </button>
                </form>
                {added && <Notice tone="success">{added}</Notice>}
              </details>
              <button
                className="btn mt-4"
                disabled={leaving}
                onClick={async () => {
                  setLeaving(true);
                  try {
                    await logout();
                  } catch (e) {
                    setError(errorText(e));
                    setLeaving(false);
                  }
                }}
              >
                <LogOut size={14} />
                退出登录
              </button>
              {error && <Notice>{error}</Notice>}
            </div>
          </Panel>
          <Panel title="采集设置" icon={Radio}>
            <div className="panel-body">
              <dl className="kv">
                <div>
                  <dt>监控网卡</dt>
                  <dd>
                    <AdapterPicker live={live} />
                  </dd>
                </div>
                <div>
                  <dt>采样周期</dt>
                  <dd>{live.data?.interval ?? 1} 秒</dd>
                </div>
                <div>
                  <dt>实时传输</dt>
                  <dd>
                    <Tag tone={live.connected ? "good" : "warn"}>
                      {live.connected ? "WebSocket 已连接" : "正在连接"}
                    </Tag>
                  </dd>
                </div>
                <div>
                  <dt>历史存储</dt>
                  <dd>本机 SQLite</dd>
                </div>
              </dl>
            </div>
          </Panel>
        </div>
        <Panel
          title="操作与采集日志"
          icon={FileClock}
          action={
            <button className="btn" onClick={logs.reload}>
              <RefreshCw size={14} />
              刷新
            </button>
          }
        >
          {logs.error && (
            <div className="panel-body">
              <Notice>{logs.error}</Notice>
            </div>
          )}
          {logs.data?.items.length ? (
            <div className="table-wrap scroll-table">
              <table>
                <thead>
                  <tr>
                    <th>发生时间</th>
                    <th>操作</th>
                    <th>记录</th>
                  </tr>
                </thead>
                <tbody>
                  {logs.data.items.map((l, i) => (
                    <tr key={i}>
                      <td className="mono">{clock(l.ts, true)}</td>
                      <td>{l.action}</td>
                      <td className="wrap-cell">{l.message}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            !logs.error && (
              <Empty
                busy={logs.busy}
                title={logs.busy ? "正在读取日志" : "暂无日志记录"}
              />
            )
          )}
        </Panel>
      </div>
    </>
  );
}
function Workbench({
  user,
  onLogout,
  dark,
  setDark,
}: {
  user: User;
  onLogout: () => void;
  dark: boolean;
  setDark: (v: boolean) => void;
}) {
  const live = useMonitor(),
    [page, setPage] = useState(readPage),
    [menu, setMenu] = useState(false);
  useEffect(() => {
    const change = () => {
      setPage(readPage());
      setMenu(false);
      window.scrollTo(0, 0);
    };
    window.addEventListener("hashchange", change);
    return () => window.removeEventListener("hashchange", change);
  }, []);
  useEffect(() => {
    document.title = pages[page] + " · NetScope";
  }, [page]);
  useEffect(() => {
    if (!menu) return;
    const close = (e: KeyboardEvent) => {
      if (e.key === "Escape") setMenu(false);
    };
    window.addEventListener("keydown", close);
    return () => window.removeEventListener("keydown", close);
  }, [menu]);
  const go = (p: Page) => {
    location.hash = p;
  };
  const links = (keys: Page[]) =>
    keys.map((key) => {
      const Icon = navIcons[key];
      return (
        <a
          href={"#" + key}
          key={key}
          aria-current={page === key ? "page" : undefined}
          className={"nav-link " + (page === key ? "active" : "")}
          onClick={() => setMenu(false)}
        >
          <Icon size={17} />
          {pages[key]}
        </a>
      );
    });
  return (
    <div className="shell">
      {menu && (
        <button
          className="mobile-scrim"
          aria-label="关闭导航"
          onClick={() => setMenu(false)}
        />
      )}
      <aside className={"sidebar " + (menu ? "open" : "")}>
        <div className="brand">
          <Mark />
          <div>
            <div className="brand-name">NetScope</div>
            <div className="brand-caption">Network monitor</div>
          </div>
        </div>
        <nav aria-label="工作台导航">
          <span className="nav-group">监测工作台</span>
          <div className="nav-list">
            {links(["dashboard", "devices", "packets", "speed"])}
          </div>
          <span className="nav-group">记录与诊断</span>
          <div className="nav-list">{links(["history", "alerts"])}</div>
        </nav>
        <div className="sidebar-bottom">
          {links(["settings"])}
          <a className="profile" href="#settings">
            <span className="avatar">
              <UserRound size={16} />
            </span>
            <span>
              {user.username}
              <small>本地账户</small>
            </span>
            <ChevronDown size={13} />
          </a>
        </div>
      </aside>
      <main>
        <header className="topbar">
          <div className="crumb">
            <button
              className="iconbtn mobile-menu"
              aria-label="展开导航"
              aria-expanded={menu}
              onClick={() => setMenu(true)}
            >
              <Menu size={17} />
            </button>
            <PanelLeft className="desktop-icon" size={15} />
            <span className="workspace-name">本地工作台</span>
            <ChevronRight size={13} />
            <strong>{pages[page]}</strong>
          </div>
          <div className="top-actions">
            <Tag tone={live.connected ? "good" : "warn"}>
              {live.connected ? "服务已连接" : "连接中"}
            </Tag>
            <span className="vert-line" />
            <span className="clock">{clock(live.data?.latest?.ts)}</span>
            <button
              className="iconbtn theme-btn"
              aria-label={dark ? "切换浅色主题" : "切换深色主题"}
              title={dark ? "切换浅色主题" : "切换深色主题"}
              onClick={() => setDark(!dark)}
            >
              {dark ? <Sun size={15} /> : <Moon size={15} />}
            </button>
          </div>
        </header>
        <div className="content">
          {live.error && (
            <div className="global-error">
              <Notice>
                {live.error}
                {live.data ? " 当前显示上次成功读取的数据。" : ""}
              </Notice>
            </div>
          )}
          {page === "dashboard" ? (
            <Overview live={live} dark={dark} go={go} />
          ) : page === "devices" ? (
            <Devices live={live} />
          ) : page === "packets" ? (
            <Packets />
          ) : page === "speed" ? (
            <Speed />
          ) : page === "history" ? (
            <Reports live={live} dark={dark} />
          ) : page === "alerts" ? (
            <Alerts />
          ) : (
            <Preferences
              user={user}
              live={live}
              dark={dark}
              setDark={setDark}
              logout={async () => {
                await post("/auth/logout");
                onLogout();
              }}
            />
          )}
        </div>
      </main>
    </div>
  );
}
export default function App() {
  const [user, setUser] = useState<User | null | undefined>(undefined),
    [error, setError] = useState(""),
    [refresh, setRefresh] = useState(0);
  const [dark, setDark] = useState(
    () => localStorage.getItem("netscope-theme") === "dark",
  );
  useEffect(() => {
    document.documentElement.dataset.theme = dark ? "dark" : "light";
    localStorage.setItem("netscope-theme", dark ? "dark" : "light");
  }, [dark]);
  useEffect(() => {
    const ctl = new AbortController();
    const ended = () => setUser(null);
    window.addEventListener("netscope-session-ended", ended);
    api<User>("/auth/me", { signal: ctl.signal })
      .then((u) => {
        if (!ctl.signal.aborted) setUser(u);
      })
      .catch((e) => {
        if (ctl.signal.aborted) return;
        if (e instanceof ApiError && e.status === 401) setUser(null);
        else setError(errorText(e));
      });
    return () => {
      ctl.abort();
      window.removeEventListener("netscope-session-ended", ended);
    };
  }, [refresh]);
  if (user === undefined)
    return (
      <main className="loading-shell">
        <Mark size={45} />
        {error ? (
          <>
            <Notice>{error}</Notice>
            <button
              className="btn"
              onClick={() => {
                setError("");
                setRefresh((v) => v + 1);
              }}
            >
              重新连接
            </button>
          </>
        ) : (
          <Empty busy title="正在连接本地工作台" />
        )}
      </main>
    );
  return user ? (
    <Workbench
      user={user}
      onLogout={() => setUser(null)}
      dark={dark}
      setDark={setDark}
    />
  ) : (
    <Auth onUser={setUser} />
  );
}
