// ============================================================
// 订阅到期提醒 · Cloudflare Workers 单文件版（v16）
// ------------------------------------------------------------
// 功能：订阅到期管理面板；到期前按「通知时间」起连发 N 天提醒
//   （Telegram / Server 酱），连发完自动回待提醒，改结束时间即新一轮
// 部署：整份粘贴到 Workers 编辑器 → 保存并部署
// 必需配置：D1 数据库绑定（变量名 DB）；环境变量 ADMIN_PASSWORD_HASH
//   （密码的 SHA-256，生成方法见初始化页）
// 建议 Cron：0 * * * *（每小时整点检查）
// ============================================================

// 版本号：页脚与测试弹窗携带，用于确认线上版本
const APP_VERSION = 'v15';

const SCHEMA_SUBS = `
CREATE TABLE IF NOT EXISTS subs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  remark TEXT DEFAULT '',
  price TEXT DEFAULT '',
  cycle TEXT DEFAULT '',
  expire_at TEXT NOT NULL,
  notify_before INTEGER DEFAULT 3,
  remind_after INTEGER DEFAULT 0,
  renew_url TEXT DEFAULT '',
  status TEXT DEFAULT 'pending',
  last_notified TEXT,
  notify_count INTEGER DEFAULT 0,
  done_at TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
)`;

const SCHEMA_CONFIG = `
CREATE TABLE IF NOT EXISTS config (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
)`;

const SCHEMA_SESSIONS = `
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  ip TEXT DEFAULT ''
)`;

const SCHEMA_LOGIN_LOCK = `
CREATE TABLE IF NOT EXISTS login_lock (
  ip TEXT PRIMARY KEY,
  fails INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL DEFAULT 0
)`;

const SECRET_KEYS = ['BOT_TOKEN', 'CHAT_ID', 'SERVER_CHAN_KEY'];
const TOGGLE_KEYS = ['TG_ENABLED', 'SC_ENABLED'];
const TZ_OFFSET = 8 * 3600 * 1000; // 北京时间 UTC+8
const VALID_STATUS = ['pending', 'notifying', 'done'];

// ---------- 基础工具 ----------
function escHtml(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, m => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[m]));
}

// 北京时间今天的 YYYY-MM-DD（日界 = 北京午夜）
function todayStr() {
  return new Date(Date.now() + TZ_OFFSET).toISOString().slice(0, 10);
}

function daysLeft(dateStr) {
  const target = new Date(String(dateStr || '').slice(0, 10) + 'T00:00:00Z').getTime();
  const today = new Date(todayStr() + 'T00:00:00Z').getTime();
  if (isNaN(target)) return 0;
  return Math.round((target - today) / 86400000);
}

function isValidDate(s) {
  const str = String(s || '').trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(str)) return false;
  const t = new Date(str + 'T00:00:00Z').getTime();
  return !isNaN(t) && str === new Date(t).toISOString().slice(0, 10);
}

function fmtResult(r) {
  if (r.ok) return '✅ 发送成功';
  if (r.off) return '⏭ 开关已关闭';
  if (r.skipped) return '⏭ ' + r.error;
  return '❌ ' + r.error;
}

function getCookie(request, name) {
  const c = request.headers.get('Cookie') || '';
  const m = c.match(new RegExp('(?:^|;\\s*)' + name + '=([^;]*)'));
  return m ? decodeURIComponent(m[1]) : null;
}

// ---------- 安全工具 ----------
const SESSION_TTL = 10 * 24 * 3600 * 1000;
const LOCK_MAX_FAILS = 5;
const LOCK_DURATION = 10 * 60 * 1000;
const PW_COOKIE = 'sid';

async function sha256Hex(text) {
  const data = new TextEncoder().encode(String(text));
  const buf = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function randomToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function sessionCookie(token) {
  return PW_COOKIE + '=' + encodeURIComponent(token) + '; Path=/; Max-Age=' + Math.floor(SESSION_TTL / 1000) + '; SameSite=Lax; HttpOnly; Secure';
}

function clearSessionCookie() {
  return PW_COOKIE + '=; Path=/; Max-Age=0; SameSite=Lax; HttpOnly; Secure';
}

// 取客户端 IP（Cloudflare 透传头）
function clientIp(request) {
  return request.headers.get('CF-Connecting-IP') || 'unknown';
}

async function lockRemaining(env, ip) {
  const row = await env.DB.prepare('SELECT locked_until FROM login_lock WHERE ip=?').bind(ip).first();
  if (!row) return 0;
  const left = Math.ceil((row.locked_until - Date.now()) / 1000);
  if (left <= 0) return 0;
  return left;
}

async function recordLoginFail(env, ip) {
  const now = Date.now();
  // UPSERT 原子累加，避免并发丢更新；超锁定时长视为新一轮
  await env.DB.prepare(
    'INSERT INTO login_lock (ip, fails, locked_until, updated_at) VALUES (?, 1, 0, ?) ' +
    'ON CONFLICT(ip) DO UPDATE SET ' +
    'fails = CASE WHEN ? - login_lock.updated_at > ? THEN 1 ELSE login_lock.fails + 1 END, ' +
    'locked_until = CASE WHEN (CASE WHEN ? - login_lock.updated_at > ? THEN 1 ELSE login_lock.fails + 1 END) >= ? THEN ? + ? ELSE 0 END, ' +
    'updated_at = excluded.updated_at'
  ).bind(ip, now, now, LOCK_DURATION, now, LOCK_DURATION, LOCK_MAX_FAILS, now, LOCK_DURATION).run();
  const row = await env.DB.prepare('SELECT fails, locked_until FROM login_lock WHERE ip=?').bind(ip).first();
  return { fails: (row && row.fails) || 0, locked: !!row && row.locked_until > now };
}

async function clearLoginFails(env, ip) {
  await env.DB.prepare('DELETE FROM login_lock WHERE ip=?').bind(ip).run();
}

async function createSession(env, ip) {
  const token = randomToken();
  const now = Date.now();
  await env.DB.prepare('DELETE FROM sessions WHERE expires_at < ?').bind(now).run();
  await env.DB.prepare(
    'INSERT INTO sessions (token, created_at, expires_at, ip) VALUES (?,?,?,?)'
  ).bind(token, now, now + SESSION_TTL, ip).run();
  return token;
}

async function validSession(env, token) {
  if (!token || typeof token !== 'string' || !/^[0-9a-f]{64}$/.test(token)) return false;
  const row = await env.DB.prepare('SELECT expires_at FROM sessions WHERE token=?').bind(token).first();
  if (!row) return false;
  if (Date.now() > row.expires_at) {
    await env.DB.prepare('DELETE FROM sessions WHERE token=?').bind(token).run();
    return false;
  }
  return true;
}

async function destroySession(env, token) {
  if (token) await env.DB.prepare('DELETE FROM sessions WHERE token=?').bind(token).run();
}

// 密码校验：优先 HASH，旧明文 ADMIN_PASSWORD 仅作兼容
async function checkPassword(input, env) {
  const raw = String(input || '');
  if (env.ADMIN_PASSWORD_HASH) {
    const expect = String(env.ADMIN_PASSWORD_HASH).trim().toLowerCase();
    const got = await sha256Hex(raw);
    // 常数时间比较，防时序侧信道
    if (got.length !== expect.length) return false;
    let diff = 0;
    for (let i = 0; i < got.length; i++) diff |= got.charCodeAt(i) ^ expect.charCodeAt(i);
    return diff === 0;
  }
  if (env.ADMIN_PASSWORD) {
    return raw === env.ADMIN_PASSWORD;
  }
  return false;
}

function hasPasswordConfig(env) {
  return !!(env.ADMIN_PASSWORD_HASH || env.ADMIN_PASSWORD);
}

// 全站安全响应头（HTML 另加禁缓存）
const SEC_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer'
};

function htmlResponse(html, status) {
  return new Response(html, {
    status: status || 200,
    headers: Object.assign({ 'Content-Type': 'text/html;charset=utf-8', 'Cache-Control': 'no-store' }, SEC_HEADERS)
  });
}

function jsonResponse(obj, status) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: Object.assign({ 'Content-Type': 'application/json;charset=utf-8' }, SEC_HEADERS)
  });
}

// 响应头一次性构造（Workers 响应不可变）
function redirect(location, setCookie) {
  const headers = { Location: location };
  if (setCookie) headers['Set-Cookie'] = setCookie;
  return new Response(null, { status: 302, headers });
}

// ---------- 通知周期 ----------
// 起点 = 到期日 - 提前天数；连发天数 = 「连续通知」所填值（1~365）
function notifyPlan(sub) {
  const nb = Math.max(0, Number(sub.notify_before) || 0);
  const chain = Math.max(1, Number(sub.remind_after) || 0);
  return { nb, chain };
}

// 日期 → 「10月25日 周日」格式（北京时间）；与当前不同年时自动带年份
function fmtCnDate(dateStr) {
  const d = new Date(String(dateStr || '').slice(0, 10) + 'T00:00:00Z');
  if (isNaN(d.getTime())) return String(dateStr || '');
  const y = d.getUTCFullYear();
  const nowY = new Date(Date.now() + TZ_OFFSET).getUTCFullYear();
  return (y === nowY ? '' : y + '年') + (d.getUTCMonth() + 1) + '月' + d.getUTCDate() + '日 ' +
    ['周日', '周一', '周二', '周三', '周四', '周五', '周六'][d.getUTCDay()];
}

// 日期 - N 天 → YYYY-MM-DD（N 为负即加）
function dateMinusDaysLocal(dateStr, days) {
  const s = String(dateStr || '').slice(0, 10);
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(s);
  if (!m) return String(dateStr || '');
  const d = new Date(Date.UTC(+m[1], +m[2] - 1, +m[3]));
  if (isNaN(d.getTime())) return String(dateStr || '');
  d.setUTCDate(d.getUTCDate() - (Number(days) || 0));
  return d.toISOString().slice(0, 10);
}

// 两个日期差（b − a，天）；/add /edit 换算提前天数用
function diffDays(a, b) {
  const pa = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(a || '').slice(0, 10));
  const pb = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(b || '').slice(0, 10));
  if (!pa || !pb) return null;
  const ta = Date.UTC(+pa[1], +pa[2] - 1, +pa[3]);
  const tb = Date.UTC(+pb[1], +pb[2] - 1, +pb[3]);
  if (isNaN(ta) || isNaN(tb)) return null;
  return Math.round((tb - ta) / 86400000);
}

// 紧急度图标：超期 ⚫ / 当天 🔴 / 一周内 🟠 / 其余 🔔（状态行与汇总共用）
function stageEmoji(d) {
  if (d < 0) return '⚫';
  if (d === 0) return '🔴';
  if (d <= 7) return '🟠';
  return '🔔';
}

// 推送首行状态：谁 + 多急（Telegram 加粗显示，通知栏只露这一行）
function subStatusLine(sub) {
  const d = daysLeft(sub.expire_at);
  const emoji = stageEmoji(d);
  if (d === 0) return emoji + ' ' + sub.name + ' ｜ 今天到期！';
  if (d < 0) return emoji + ' ' + sub.name + ' ｜ 已超期 ' + Math.abs(d) + ' 天';
  if (d <= 7) return emoji + ' ' + sub.name + ' ｜ ⚠️ 只剩 ' + d + ' 天';
  return emoji + ' ' + sub.name + ' ｜ 距到期还有 ' + d + ' 天';
}

// 订阅事实行：结束时间 / 本次提醒区间 / 备注（cron 正文与合并测试共用）
function subFacts(sub, dayNo) {
  const plan = notifyPlan(sub);
  const start = dateMinusDaysLocal(sub.expire_at, plan.nb);
  const end = dateMinusDaysLocal(sub.expire_at, plan.nb - plan.chain + 1);
  return '结束时间：<b>' + fmtCnDate(sub.expire_at) + '</b>\n' +
    '本次提醒：第 <b>' + dayNo + '/' + plan.chain + '</b> 天（' + start + ' → ' + end + '）' +
    (sub.remark ? '\n备注：' + escHtml(sub.remark) : '');
}

// 推送正文：事实 + 行动行；首行状态在标题（subStatusLine）
function buildSubMessage(sub, isTest) {
  const plan = notifyPlan(sub);
  const d = daysLeft(sub.expire_at);
  const dayNo = isTest
    ? Math.min(plan.chain, Math.max(1, plan.nb - Math.max(d, 0) + 1)) // 测试预览按今天所处位置推算，钳制在 1~chain
    : Math.max(1, (Number(sub.notify_count) || 0) + 1);
  const remain = plan.chain - dayNo;
  let action;
  if (isTest) {
    action = '测试消息 · 非真实提醒';
  } else if (remain === 0) {
    action = '明天起不再提醒 · 处理完请在后台标记「已完成」';
  } else {
    action = '处理完请在后台标记「已完成」';
  }
  return subFacts(sub, dayNo) + '\n\n' + action;
}

// HTML → Markdown（Server 酱 desp 用）
function htmlToMarkdown(html) {
  return String(html == null ? '' : html)
    .replace(/<a\s+href="([^"]*)"[^>]*>(.*?)<\/a>/gi, '[$2]($1)')
    .replace(/<\/?(b|strong)>/gi, '**')
    .replace(/<\/?(i|em)>/gi, '*')
    .replace(/<\/?(code|pre)>/gi, '`')
    .replace(/<[^>]+>/g, '')
    .replace(/\*\*\*\*/g, '')
    .replace(/\*\s*\*\*/g, '**')
    .replace(/\*\*\s*\*/g, '**');
}

// ---------- 登录页（不依赖数据库） ----------
function renderLoginPage(errorMsg, warning) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>登录 · 订阅到期提醒</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#eef2ff,#f5f7fb 50%,#eef6ff);padding:20px}
.login{background:#fff;border:1px solid #e7ebf3;border-radius:18px;padding:40px 36px;width:380px;max-width:100%;box-shadow:0 12px 40px rgba(30,41,80,.08)}
.logo{width:56px;height:56px;border-radius:16px;background:linear-gradient(135deg,#3b82f6,#6366f1);display:flex;align-items:center;justify-content:center;font-size:26px;margin:0 auto 16px;box-shadow:0 8px 20px rgba(99,102,241,.35)}
.login h1{font-size:20px;text-align:center;color:#1e2430;margin-bottom:6px}
.login .sub{font-size:13px;color:#8a94a8;text-align:center;margin-bottom:24px}
.login input{width:100%;padding:12px 14px;border:1px solid #d8dee9;border-radius:10px;font-size:15px;margin-bottom:14px;background:#fbfcfe;transition:.15s}
.login input:focus{outline:none;border-color:#93c0fd;box-shadow:0 0 0 3px rgba(59,130,246,.15);background:#fff}
.login button{width:100%;padding:12px;border:none;border-radius:10px;font-size:15px;font-weight:600;color:#fff;cursor:pointer;background:linear-gradient(135deg,#3b82f6,#5a7cf7);box-shadow:0 6px 16px rgba(59,130,246,.35);transition:.15s}
.login button:hover{transform:translateY(-1px);box-shadow:0 8px 20px rgba(59,130,246,.45)}
.error{color:#dc2626;font-size:13px;text-align:center;margin-bottom:12px;background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:8px}
.warning{background:#fffbeb;border:1px solid #fde68a;color:#92400e;font-size:12.5px;border-radius:8px;padding:10px 12px;margin-bottom:14px;line-height:1.7}
</style>
</head>
<body>
<div class="login">
  <div class="logo">📋</div>
  <h1>订阅到期提醒</h1>
  <p class="sub">请输入管理密码登录</p>
  ${warning ? `<div class="warning">${warning}</div>` : ''}
  ${errorMsg ? `<div class="error">${escHtml(errorMsg)}</div>` : ''}
  <form method="POST" action="/login">
    <input type="password" name="password" placeholder="管理密码" autocomplete="current-password" autofocus required>
    <button type="submit">进入管理后台</button>
  </form>
</div>
</body>
</html>`;
}

// 登录页 · 哈希生成指南（未配置密码相关变量时显示）
function renderHashGuide() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>初始化 · 订阅到期提醒</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#eef2ff,#f5f7fb 50%,#eef6ff);padding:20px}
.box{background:#fff;border:1px solid #e7ebf3;border-radius:18px;padding:36px;width:640px;max-width:100%;box-shadow:0 12px 40px rgba(30,41,80,.08)}
.box h1{font-size:19px;color:#1e2430;margin-bottom:6px}
.box .sub{font-size:13px;color:#8a94a8;margin-bottom:20px}
.step{font-size:13.5px;color:#3d465a;line-height:2;margin-bottom:8px}
.step b{color:#1e2430}
.code{background:#f6f8fc;border:1px solid #e7ebf3;border-radius:10px;padding:12px 16px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px;color:#3b5bdb;word-break:break-all;margin:10px 0 18px;user-select:all;cursor:pointer}
.tip{font-size:12px;color:#9aa3b5;line-height:1.8;margin-top:6px}
.hintbox{background:#fffbeb;border:1px solid #fde68a;color:#92400e;font-size:12.5px;border-radius:10px;padding:12px 14px;margin-bottom:18px;line-height:1.8}
</style>
</head>
<body>
<div class="box">
  <h1>🔐 安全初始化</h1>
  <p class="sub">本版本不再使用明文密码，请按以下 3 步完成配置</p>
  <div class="hintbox">💡 你的密码将转换为 SHA-256 哈希存储——服务器永远不知道你的原密码，抓包也抓不到</div>
  <div class="step"><b>第 1 步</b>：在本机 PowerShell（CMD 不行）执行下面命令，把「你的密码」换成实际密码：</div>
  <div class="code" onclick="copyCode(this)" title="点击复制">-join ([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes('你的密码')) | ForEach-Object { $_.ToString('x2') })</div>
  <div class="step"><b>第 2 步</b>：复制输出的 64 位十六进制串</div>
  <div class="step"><b>第 3 步</b>：Workers → 设置 → 环境变量 → 添加 <b>ADMIN_PASSWORD_HASH</b> = 那串哈希（建议勾选加密）→ 重新部署</div>
  <p class="tip">· 兼容提示：暂时不想换的话，旧的 ADMIN_PASSWORD 明文变量仍可继续用，但强烈建议尽快迁移<br>· 上面是 PowerShell（Windows 10+ 自带）写法；装了 Git Bash 的话也可以用 echo -n "你的密码" | sha256sum<br>· 忘记密码 = 无法找回，只能重设环境变量（哈希不可逆）</p>
</div>
<script>
function copyCode(el){try{navigator.clipboard.writeText(el.textContent.trim());el.style.outline='2px solid #3b5bdb';setTimeout(function(){el.style.outline='';},400)}catch(e){}}
</script>
</body>
</html>`;
}

// ---------- 错误提示页 ----------
function renderErrorPage(title, detail) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>提示 · 订阅到期提醒</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#fef2f2,#f8fafc);padding:20px}
.errbox{background:#fff;border:1px solid #fecaca;border-radius:16px;padding:32px;width:560px;max-width:100%;box-shadow:0 10px 30px rgba(153,27,27,.08)}
.errbox h1{font-size:18px;color:#b91c1c;margin-bottom:14px}
.errbox .detail{background:#fef2f2;border-radius:10px;padding:14px;font-size:13.5px;color:#7f1d1d;line-height:1.7;margin-bottom:16px;word-break:break-all}
.errbox ul{font-size:13px;color:#5b6478;line-height:2.1;padding-left:18px}
.errbox b{color:#1e2430}
</style>
</head>
<body>
<div class="errbox">
  <h1>⚠️ ${escHtml(title)}</h1>
  <div class="detail">${escHtml(detail)}</div>
  <ul>
    <li>检查 Workers → 设置 → 绑定：D1 数据库的<b>变量名必须是 DB</b></li>
    <li>检查 Workers → 设置 → 环境变量：已添加 <b>ADMIN_PASSWORD_HASH</b>（或旧版 ADMIN_PASSWORD）</li>
    <li>修改配置后需要<b>重新部署</b>并强制刷新（Ctrl+F5）</li>
    <li>仍有问题请把本页错误信息发给我们</li>
  </ul>
</div>
</body>
</html>`;
}

// ---------- 管理面板 ----------
function renderHTML(subsRaw, message, configRaw, pageRaw) {
  const page = pageRaw === 'config' ? 'config' : 'main';
  const subs = Array.isArray(subsRaw) ? subsRaw : [];
  const config = configRaw || {};

  const tgOn = config.TG_ENABLED !== '0';
  const scOn = config.SC_ENABLED !== '0';
  const tgReady = !!(config.BOT_TOKEN && config.CHAT_ID);
  const scReady = !!config.SERVER_CHAN_KEY;

  const STATUS = [
    { v: 'pending', l: '⏳ 待提醒' },
    { v: 'notifying', l: '🔔 通知中' },
    { v: 'done', l: '✅ 已完成' }
  ];
  const SM = {};
  STATUS.forEach(s => { SM[s.v] = s; });

  const ORDER = { pending: 0, notifying: 1, done: 2 };
  // 排序：状态优先 → 通知开始时间升序
  const sortKey = s => dateMinusDaysLocal(s.expire_at, Math.max(0, Number(s.notify_before) || 0));
  const sorted = subs.slice().sort((a, b) => {
    const oa = ORDER[a.status] !== undefined ? ORDER[a.status] : 5;
    const ob = ORDER[b.status] !== undefined ? ORDER[b.status] : 5;
    if (oa !== ob) return oa - ob;
    return String(sortKey(a)).localeCompare(String(sortKey(b)));
  });

  const stats = { pending: 0, notifying: 0, done: 0 };
  subs.forEach(s => { if (stats[s.status] !== undefined) stats[s.status]++; });

  let cfgWarn = '';
  const warnParts = [];
  if (tgOn && !tgReady) warnParts.push('Telegram');
  if (scOn && !scReady) warnParts.push('Server 酱');
  if (!tgOn && !scOn) {
    cfgWarn = '<div class="msg err">🔕 所有通知渠道的开关均已关闭：订阅到期后将不会推送任何提醒。请到 <a href="/?page=config" style="color:#991b1b;font-weight:600">通知设置</a> 打开需要的渠道</div>';
  } else if (warnParts.length) {
    cfgWarn = '<div class="msg err">⚠️ ' + warnParts.join('、') + ' 渠道已开启但尚未配置完成：请到 <a href="/?page=config" style="color:#991b1b;font-weight:600">通知设置</a> 填写，否则不会推送提醒</div>';
  }

  const rows = sorted.map(s => {
    const st = SM[s.status] || { l: '未知' };
    // 链长统一走 notifyPlan（与消息体、cron SQL 同一份逻辑）
    const plan = notifyPlan(s);
    const notifyDate = dateMinusDaysLocal(s.expire_at, plan.nb);
    // 通知结束日 = 开始 + 连发天数 - 1
    const notifyEnd = dateMinusDaysLocal(s.expire_at, plan.nb - plan.chain + 1);
    // 到期倒计时徽标（超期/一周内高亮）
    const dl = daysLeft(s.expire_at);
    const dlTxt = dl > 0 ? '剩 ' + dl + ' 天' : (dl === 0 ? '今天到期' : '超期 ' + Math.abs(dl) + ' 天');
    const dlCls = dl < 0 ? 'dl-red' : (dl <= 7 ? 'dl-orange' : 'dl-gray');
    // 通知时间下的「提前 N 天」标签
    const nbTag = plan.nb === 0 ? '到期当天' : '提前 ' + plan.nb + ' 天';

    return `<tr data-status="${escHtml(s.status)}">
      <td class="chkcell"><input type="checkbox" class="rowchk" value="${escHtml(s.id)}" onchange="updateCount()" title="勾选后可批量测试"></td>
      <td><div class="cname">${escHtml(s.name)}</div>${s.remark ? '<div class="subname">' + escHtml(s.remark) + '</div>' : ''}</td>
      <td><span class="badge b-${escHtml(s.status)}">${st.l}</span></td>
      <td class="mono"><div><span class="dl-lab">开始</span>${notifyDate}</div><div><span class="dl-lab">结束</span>${notifyEnd}</div><div class="dlchip dl-blue">${nbTag}</div></td>
      <td class="mono">${escHtml(s.expire_at)}<div class="dlchip ${dlCls}">${dlTxt}</div></td>
      <td class="mono">${plan.chain} 天</td>
      <td>
        <div class="ops">
          <form method="POST" action="/setstatus" class="inline">
            <input type="hidden" name="id" value="${escHtml(s.id)}">
            <select name="status" class="mini" onchange="this.form.submit()">
              ${STATUS.map(o => '<option value="' + o.v + '"' + (s.status === o.v ? ' selected' : '') + '>' + o.l.replace(/[^\w\u4e00-\u9fa5（ ）]/g, '') + '</option>').join('')}
            </select>
          </form>
          <button type="button" class="linkbtn edit" title="编辑" onclick="openEdit(${escHtml(s.id)})">✎</button>
          <button type="button" class="linkbtn test" title="测试此条提醒" onclick="testSubs([${escHtml(s.id)}])">🧪</button>
          <form method="POST" action="/delete" class="inline" onsubmit="return confirm('确定删除这条订阅？')">
            <input type="hidden" name="id" value="${escHtml(s.id)}">
            <button type="submit" class="linkbtn del" title="删除">✕</button>
          </form>
        </div>
      </td>
    </tr>`;
  }).join('');

  // 一次性提示弹窗（成功/校验错误/测试结果）
  const msgModal = message ? `
<div id="msgModal" class="modal">
  <div class="modal-box">
    <div class="msg ${message.type}" style="margin-bottom:14px">${message.text}</div>
    <div class="modal-actions"><button type="button" class="btn btn-blue" onclick="closeMsgModal()">知道了</button></div>
  </div>
</div>` : '';

  const mainHtml = page !== 'config' ? `
<div class="stats">
  <div class="stat s0"><div class="ico">⏳</div><div><div class="num">${stats.pending}</div><div class="lbl">待提醒</div></div></div>
  <div class="stat s1"><div class="ico">🔔</div><div><div class="num">${stats.notifying}</div><div class="lbl">通知中</div></div></div>
  <div class="stat s2"><div class="ico">✅</div><div><div class="num">${stats.done}</div><div class="lbl">已完成</div></div></div>
</div>
${cfgWarn}
<div class="card">
  <h2>➕ 添加订阅</h2>
  <form class="form-row" method="POST" action="/add" id="addForm">
    <label>名称 *<input type="text" name="name" required maxlength="50" placeholder="如 Netflix"></label>
    <label>备注<input type="text" name="remark" maxlength="100" placeholder="如 合租账号"></label>
    <label>通知时间 *<input type="date" name="notify_start" required id="add_notify_start" onchange="syncAddPlan()" title="从哪天开始提醒你，需在结束时间之前"></label>
    <label>结束时间 *<input type="date" name="expire_at" required id="add_expire_at" min="${todayStr()}" onchange="syncAddPlan()"></label>
    <label>连续通知<input type="number" name="remind_after" value="5" min="1" max="365" step="1" id="add_remind_after" oninput="syncAddPlan()" title="从通知时间起连续提醒多少天（1~365 天）"></label>
    <button type="submit" class="btn btn-blue" id="addSubmitBtn">添 加</button>
  </form>
  <p class="formtip" id="add_plan_hint">通知时间 = 从哪天开始提醒你（要在结束时间之前，提前预警用） ｜ 连续通知 = 从通知时间起连续提醒几天（1~365 天）</p>
</div>
<div class="card">
  <h2>📂 订阅列表 <span class="count">共 ${subs.length} 项</span></h2>
  <div class="testbar">
    <label class="selall"><input type="checkbox" id="selAll" onchange="toggleAll(this.checked)"> 全选</label>
    <span class="selcount" id="selCount">未选择</span>
    <span class="bar-actions">
      <button type="button" class="btn btn-blue sm" onclick="testSelected()">🧪 测试选中</button>
      <button type="button" class="btn btn-ghost sm" onclick="testAll()">🧪 测试全部</button>
      <form method="POST" action="/deletemulti" class="inline" onsubmit="return submitDeleteSelected()">
        <button type="submit" class="btn btn-danger sm">🗑 删除选中</button>
      </form>
    </span>
    <span class="bar-note">勾选订阅后可批量测试或删除</span>
  </div>
  <div class="table-wrap">
  <table>
    <thead><tr><th class="chkcell"><input type="checkbox" id="selAllHead" onchange="toggleAll(this.checked)" title="全选 / 取消全选"></th><th>名称</th><th>状态</th><th>通知时间</th><th>结束时间</th><th>连续通知</th><th>操作</th></tr></thead>
    <tbody>${rows || '<tr><td colspan="7" class="empty">暂无订阅，在上方添加第一条吧</td></tr>'}</tbody>
  </table>
  </div>
</div>
  <div class="legend">💡 <b>待提醒</b> 未到通知期，或连发完等待下一轮 ｜ <b>通知中</b> 连发期内每天推送（只推已开启渠道） ｜ <b>已完成</b> 已续费/已处理 ｜ ${APP_VERSION}</div>

<div id="editModal" class="modal">
  <div class="modal-box">
    <h3>✎ 编辑订阅</h3>
    <form method="POST" action="/edit">
      <input type="hidden" name="id" id="edit_id">
      <div class="field"><label>名称</label><input type="text" name="name" id="edit_name" required maxlength="50"></div>
      <div class="field"><label>备注</label><input type="text" name="remark" id="edit_remark" maxlength="100"></div>
      <div class="field"><label>通知时间</label><input type="date" name="notify_start" id="edit_notify_start" onchange="onStartInput()" title="从哪天开始提醒你，需在结束时间之前"></div>
      <div class="field"><label>结束时间</label><input type="date" name="expire_at" id="edit_expire_at" required onchange="onExpireInput()"></div>
      <div class="field"><label>连续通知（从通知时间起连发几天，1~365 天）</label><input type="number" name="remind_after" id="edit_remind_after" min="1" max="365" value="5" oninput="syncNotifyPlan()"></div>
      <div class="plan-summary" id="edit_plan_summary"></div>
      <div class="field"><label>状态</label><select name="status" id="edit_status"><option value="pending">待提醒</option><option value="notifying">通知中</option><option value="done">已完成</option></select></div>
      <div class="modal-actions">
        <button type="submit" class="btn btn-blue" id="editSubmitBtn">保存修改</button>
        <button type="button" class="btn btn-ghost" onclick="closeEdit()">取消</button>
      </div>
    </form>
  </div>
</div>

<div id="testModal" class="modal">
  <div class="modal-box">
    <h3 id="testModalTitle">🧪 测试提醒</h3>
    <div id="testModalBody" class="test-result"></div>
    <div class="modal-actions">
      <button type="button" class="btn btn-blue" onclick="closeTestModal()">知道了</button>
    </div>
  </div>
</div>
<script>
async function openEdit(id) {
  try {
    var r = await fetch('/getsub?id=' + id);
    var sub = await r.json();
    if (!sub) return;
    document.getElementById('edit_id').value = sub.id;
    document.getElementById('edit_name').value = sub.name || '';
    document.getElementById('edit_remark').value = sub.remark || '';
    // 通知时间回显：优先用服务端算好的值
    var nbLoaded = Math.max(0, Math.min(365, sub.notify_before || 0));
    document.getElementById('edit_notify_start').value =
      sub.notify_start_display || dateMinusDays(sub.expire_at, nbLoaded);
    document.getElementById('edit_expire_at').value = sub.expire_at || '';
    document.getElementById('edit_remind_after').value = Math.max(1, sub.remind_after || 0);
    document.getElementById('edit_status').value = sub.status || 'pending';
    syncNotifyPlan();
    document.getElementById('editModal').classList.add('show');
  } catch (e) { alert('加载订阅信息失败，请刷新页面重试'); }
}
// 日期 - N 天 → YYYY-MM-DD
function dateMinusDays(dateStr, days) {
  try {
    var s = String(dateStr || '').slice(0, 10);
    var m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(s);
    if (!m) return '';
    var d = new Date(Date.UTC(+m[1], +m[2] - 1, +m[3]));
    if (isNaN(d.getTime())) return '';
    d.setUTCDate(d.getUTCDate() - (Number(days) || 0));
    return d.toISOString().slice(0, 10);
  } catch (e) { return ''; }
}
// 两日期相差天数（b - a）
function daysBetween(a, b) {
  try {
    var da = new Date(String(a).slice(0, 10) + 'T00:00:00Z').getTime();
    var db = new Date(String(b).slice(0, 10) + 'T00:00:00Z').getTime();
    if (isNaN(da) || isNaN(db)) return null;
    return Math.round((db - da) / 86400000);
  } catch (e) { return null; }
}
// 结束时间变更 → 通知时间保持"提前天数"不变，跟随重算
function onExpireInput() {
  var expireEl = document.getElementById('edit_expire_at');
  var startEl = document.getElementById('edit_notify_start');
  if (!expireEl || !startEl) return;
  var expire = expireEl.value;
  var start = startEl.value;
  if (!expire || !start) { syncNotifyPlan(); return; }
  var gap = daysBetween(start, expire);
  if (gap === null || gap < 0) gap = 0;
  startEl.value = dateMinusDays(expire, gap);
  syncNotifyPlan();
}
function onStartInput() {
  syncNotifyPlan();
}
// 编辑弹窗联动：校验 + 汇总条（连发天数与列表同口径）
function syncNotifyPlan() {
  var expireEl = document.getElementById('edit_expire_at');
  var startEl = document.getElementById('edit_notify_start');
  var chainEl = document.getElementById('edit_remind_after');
  var sumEl = document.getElementById('edit_plan_summary');
  var btn = document.getElementById('editSubmitBtn');
  if (!expireEl || !startEl || !chainEl || !sumEl) return;
  var expire = expireEl.value;
  var start = startEl.value;
  var chain = parseInt(chainEl.value, 10);
  chainEl.setCustomValidity('');

  // 连续通知校验：1~365
  if (isNaN(chain) || chain < 1 || chain > 365) {
    sumEl.textContent = '⚠️ 连续通知应为 1~365 天';
    sumEl.style.color = '#b45309';
    if (btn) btn.disabled = true;
    return;
  }
  sumEl.style.color = '';
  if (btn) btn.disabled = false;

  if (!expire) { sumEl.textContent = '请先选择结束时间'; return; }
  if (!start) { sumEl.textContent = '请先选择通知时间'; return; }
  var gap = daysBetween(start, expire);
  if (gap === null || gap < 0) {
    sumEl.textContent = '⚠️ 通知开始的那天（' + start + '）比结束日（' + expire + '）还晚——提醒要提前预警才有用。请把通知时间改到 ' + expire + ' 之前，或把结束时间改晚。';
    sumEl.style.color = '#b91c1c';
    if (btn) btn.disabled = true;
    return;
  }

  var lastDay = dateMinusDays(start, -(chain - 1));
  var sum = '📣 ' + start + (gap === 0 ? '（到期当天开始）' : '') + ' 起连发 ' + chain + ' 天 · 最后一次 ' + lastDay;
  sumEl.textContent = sum;
}
// 编辑提交前最终拦截
(function(){
  var form = document.querySelector('#editModal form');
  if (form) form.addEventListener('submit', function(ev) {
    var expire = document.getElementById('edit_expire_at').value;
    var start = document.getElementById('edit_notify_start').value;
    var chain = parseInt(document.getElementById('edit_remind_after').value, 10);
    if (!expire || !start) { ev.preventDefault(); alert('请填完通知时间和结束时间'); return; }
    if (isNaN(chain) || chain < 1 || chain > 365) { ev.preventDefault(); alert('连续通知应为 1~365 天'); return; }
    var gap = daysBetween(start, expire);
    if (gap === null || gap < 0) { ev.preventDefault(); alert('通知时间比结束时间还晚，提醒就失去意义了。请把通知时间改到结束时间之前。'); return; }
  });
})();
// Esc 关闭弹窗
document.addEventListener('keydown', function(e) {
  if (e.key === 'Escape') { closeEdit(); closeTestModal(); }
});
// 添加表单联动：校验 + 计划提示
function syncAddPlan() {
  var expireEl = document.getElementById('add_expire_at');
  var startEl = document.getElementById('add_notify_start');
  var chainEl = document.getElementById('add_remind_after');
  var hintEl = document.getElementById('add_plan_hint');
  var btn = document.getElementById('addSubmitBtn');
  if (!expireEl || !startEl || !chainEl || !hintEl) return;
  var expire = expireEl.value;
  var start = startEl.value;
  var chain = parseInt(chainEl && chainEl.value, 10);
  hintEl.style.color = '';
  if (chainEl) chainEl.setCustomValidity('');

  // 连续通知校验：1~365
  if (isNaN(chain) || chain < 1) {
    hintEl.textContent = '⚠️ 连续通知至少 1 天';
    hintEl.style.color = '#b45309';
    if (btn) btn.disabled = true;
    return;
  }
  if (chain > 365) {
    hintEl.textContent = '⚠️ 连续通知最多 365 天（当前 ' + chain + '）';
    hintEl.style.color = '#b45309';
    if (chainEl) chainEl.setCustomValidity('连续通知最多 365 天');
    if (btn) btn.disabled = true;
    return;
  }

  if (!expire) { hintEl.textContent = '先选结束时间'; if (btn) btn.disabled = false; return; }

  // 通知时间校验：必须 ≤ 结束时间
  if (!start) { hintEl.textContent = '再选通知时间（提醒从哪天开始，要在结束时间之前）'; if (btn) btn.disabled = false; return; }
  var gap = daysBetween(start, expire);
  if (gap === null || gap < 0) {
    hintEl.textContent = '⚠️ 通知开始日（' + start + '）比结束日（' + expire + '）还晚——提醒是提前预警，得在结束前开始。请改到 ' + expire + ' 之前';
    hintEl.style.color = '#b91c1c';
    if (startEl) startEl.setCustomValidity('通知时间需在结束时间之前');
    if (btn) btn.disabled = true;
    return;
  }
  if (startEl) startEl.setCustomValidity('');

  var lastDay = dateMinusDays(start, -(chain - 1));
  var expireTag = gap === 0 ? '（到期当天开始）' : '';
  hintEl.textContent = '📣 ' + start + expireTag + ' 起连发 ' + chain + ' 天 · 最后一次 ' + lastDay;
  if (btn) btn.disabled = false;
}
// 添加提交前最终拦截
(function(){
  var form = document.getElementById('addForm');
  if (form) form.addEventListener('submit', function(ev) {
    var expire = document.getElementById('add_expire_at').value;
    var start = document.getElementById('add_notify_start').value;
    var chain = parseInt(document.getElementById('add_remind_after').value, 10);
    if (!expire || !start) { ev.preventDefault(); alert('请填完结束时间和通知时间'); return; }
    if (isNaN(chain) || chain < 1 || chain > 365) { ev.preventDefault(); alert('连续通知应为 1~365 天'); return; }
    var gap = daysBetween(start, expire);
    if (gap === null || gap < 0) { ev.preventDefault(); alert('通知时间比结束时间还晚，提醒就失去意义了。请把通知时间改到结束时间之前。'); return; }
  });
})();
function closeEdit() {
  document.getElementById('editModal').classList.remove('show');
}
document.getElementById('editModal').addEventListener('click', function(e) {
  if (e.target === this) closeEdit();
});
function toggleAll(state) {
  document.querySelectorAll('.rowchk').forEach(function(c) { c.checked = state; });
  var head = document.getElementById('selAll');
  var head2 = document.getElementById('selAllHead');
  if (head) head.checked = state;
  if (head2) head2.checked = state;
  updateCount();
}
function updateCount() {
  var n = document.querySelectorAll('.rowchk:checked').length;
  var total = document.querySelectorAll('.rowchk').length;
  var el = document.getElementById('selCount');
  if (el) el.textContent = n ? ('已选 ' + n + ' / ' + total + ' 项') : '未选择';
  var head = document.getElementById('selAll');
  var head2 = document.getElementById('selAllHead');
  var all = n > 0 && n === total;
  if (head) head.checked = all;
  if (head2) head2.checked = all;
}
function getCheckedIds() {
  return Array.prototype.slice.call(document.querySelectorAll('.rowchk:checked')).map(function(c) { return c.value; });
}
function testSelected() {
  var ids = getCheckedIds();
  if (!ids.length) { alert('请先勾选要测试的订阅'); return; }
  testSubs(ids);
}
function testAll() {
  testSubs(null);
}
// 删除选中
function submitDeleteSelected() {
  var ids = getCheckedIds();
  if (!ids.length) { alert('请先勾选要删除的订阅'); return false; }
  if (!confirm('确定删除选中的 ' + ids.length + ' 条订阅？此操作不可撤销')) return false;
  var form = document.querySelector('form[action="/deletemulti"]');
  if (!form) return false;
  form.querySelectorAll('input[name="subids"]').forEach(function(el) { el.remove(); });
  ids.forEach(function(id) {
    var inp = document.createElement('input');
    inp.type = 'hidden';
    inp.name = 'subids';
    inp.value = id;
    form.appendChild(inp);
  });
  return true;
}
async function testSubs(ids) {
  var m = document.getElementById('testModal');
  var t = document.getElementById('testModalTitle');
  var b = document.getElementById('testModalBody');
  t.textContent = '🧪 测试提醒';
  b.innerHTML = '<div class="tr-loading">正在发送测试消息，请稍候…</div>';
  m.classList.add('show');
  try {
    var fd = new FormData();
    if (ids) { ids.forEach(function(id) { fd.append('subids', id); }); }
    else { fd.append('all', '1'); }
    var r = await fetch('/testsub?fmt=json', { method: 'POST', body: fd });
    var data = await r.json();
    t.textContent = data.title || '🧪 测试提醒';
    b.innerHTML = data.html || '';
  } catch (e) {
    b.innerHTML = '<div class="tr-line">❌ 请求失败：' + (e && e.message ? e.message : e) + '</div>';
  }
}
function closeTestModal() {
  document.getElementById('testModal').classList.remove('show');
}
document.getElementById('testModal').addEventListener('click', function(e) {
  if (e.target === this) closeTestModal();
});
updateCount();
</script>` : `
<div class="card narrow">
  <h2>⚙️ 通知设置</h2>
  <p class="hint">每个渠道可独立开关与测试；到期提醒只推送到已开启的渠道（配置保存在数据库中）</p>
  <form method="POST" action="/saveconfig">
    <input type="hidden" name="cfgform" value="1">

    <div class="chan${tgOn ? '' : ' off'}">
      <div class="chan-head">
        <div class="chan-title">✈️ Telegram</div>
        <label class="switch" title="开关">
          <input type="checkbox" name="TG_ENABLED" value="1"${tgOn ? ' checked' : ''}>
          <span class="slider"></span>
        </label>
      </div>
      <div class="chan-body">
        <label class="cfg">Bot Token<input type="text" name="BOT_TOKEN" value="${escHtml(config.BOT_TOKEN || '')}" placeholder="格式 123456789:AAHfkQ2x...（从 @BotFather 复制完整一条）"></label>
        <label class="cfg">Chat ID<input type="text" name="CHAT_ID" value="${escHtml(config.CHAT_ID || '')}" placeholder="个人纯数字 / 群组频道 -100 开头"></label>
        <div class="chan-foot">
          <span class="chan-note">${tgOn ? (tgReady ? '🟢 已开启 · 到期提醒将推送到该渠道' : '🟢 已开启 · 待配置完成') : '⚫ 已关闭 · 到期提醒不会推送该渠道'}</span>
          <button type="submit" formaction="/testnotify" name="channel" value="tg" class="btn btn-blue sm">🔔 测试</button>
        </div>
      </div>
    </div>

    <div class="chan${scOn ? '' : ' off'}">
      <div class="chan-head">
        <div class="chan-title">💚 Server 酱</div>
        <label class="switch" title="开关">
          <input type="checkbox" name="SC_ENABLED" value="1"${scOn ? ' checked' : ''}>
          <span class="slider"></span>
        </label>
      </div>
      <div class="chan-body">
        <label class="cfg">SendKey<input type="text" name="SERVER_CHAN_KEY" value="${escHtml(config.SERVER_CHAN_KEY || '')}" placeholder="从 sct.ftqq.com 获取"></label>
        <div class="chan-foot">
          <span class="chan-note">${scOn ? (scReady ? '🟢 已开启 · 到期提醒将推送到微信' : '🟢 已开启 · 待配置完成') : '⚫ 已关闭 · 到期提醒不会推送该渠道'}</span>
          <button type="submit" formaction="/testnotify" name="channel" value="sc" class="btn btn-blue sm">🔔 测试</button>
        </div>
      </div>
    </div>

    <div class="btn-row">
      <button type="submit" class="btn btn-green">💾 保存设置</button>
      <button type="submit" formaction="/testnotify" name="channel" value="all" class="btn btn-blue">🔔 测试全部渠道</button>
    </div>
    <p class="tip">💡 Bot Token：<a href="https://t.me/BotFather" target="_blank">@BotFather</a> 创建（数字:AA 开头长串） ｜ Chat ID：<a href="https://t.me/userinfobot" target="_blank">@userinfobot</a> 查询 ｜ Server 酱：<a href="https://sct.ftqq.com" target="_blank">sct.ftqq.com</a> 获取<br>测试前请先在 Telegram 里向你的 Bot 发送过 /start（频道需将 Bot 设为管理员）</p>
  </form>
</div>`;

  const navMain = page === 'main' ? ' active' : '';
  const navCfg = page === 'config' ? ' active' : '';

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>订阅到期提醒</title>
<style>
:root{--line:#e7ebf3;--text:#1e2430;--muted:#8a94a8;--blue:#3b82f6}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'PingFang SC','Microsoft YaHei',sans-serif;background:linear-gradient(180deg,#f6f8fc,#f1f4fa);color:var(--text);padding:26px 20px 44px;max-width:1080px;margin:0 auto;min-height:100vh}
.topbar{display:flex;align-items:center;justify-content:space-between;gap:14px;margin-bottom:22px;flex-wrap:wrap}
.brand{font-size:19px;font-weight:800;display:flex;align-items:center;gap:11px}
.brand .logo{width:38px;height:38px;border-radius:11px;background:linear-gradient(135deg,#3b82f6,#6366f1);display:flex;align-items:center;justify-content:center;font-size:19px;box-shadow:0 6px 16px rgba(99,102,241,.35)}
nav{display:flex;gap:8px}
.nav{padding:8px 17px;border-radius:999px;text-decoration:none;font-size:13px;font-weight:600;color:#5b6478;background:#fff;border:1px solid var(--line);transition:.15s}
.nav:hover{color:var(--blue);border-color:#bfd4fe}
.nav.active{background:linear-gradient(135deg,#3b82f6,#6366f1);color:#fff;border-color:transparent;box-shadow:0 4px 12px rgba(59,130,246,.35)}
.nav.logout{color:#9aa3b5}
.nav.logout:hover{color:#dc2626;border-color:#fecaca}
button.nav{font-family:inherit;cursor:pointer}
.msg{padding:12px 16px;border-radius:11px;margin-bottom:16px;font-size:13.5px;line-height:1.8;border:1px solid}
.msg.ok{background:#ecfdf5;border-color:#a7f3d0;color:#065f46}
.msg.err{background:#fef2f2;border-color:#fecaca;color:#991b1b}
.msg a{color:inherit}
.dlchip{display:inline-block;margin-top:3px;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:600}
.dl-gray{background:#f1f4f9;color:#6b7280}
.dl-orange{background:#fffbeb;color:#b45309}
.dl-red{background:#fef2f2;color:#b91c1c}
.dl-blue{background:#eff6ff;color:#2563eb}
.dl-lab{display:inline-block;width:26px;color:#8a94a8;font-size:11px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:18px}
.stat{display:flex;align-items:center;gap:12px;background:#fff;border:1px solid var(--line);border-radius:14px;padding:13px 16px;box-shadow:0 1px 2px rgba(16,24,40,.04)}
.stat .ico{width:40px;height:40px;border-radius:11px;display:flex;align-items:center;justify-content:center;font-size:18px;flex:none}
.stat .num{font-size:20px;font-weight:800;line-height:1.15}
.stat .lbl{font-size:12px;color:var(--muted);margin-top:1px}
.stat.s0 .ico{background:#eff6ff}.stat.s0 .num{color:#2563eb}
.stat.s1 .ico{background:#fffbeb}.stat.s1 .num{color:#b45309}
.stat.s2 .ico{background:#ecfdf5}.stat.s2 .num{color:#047857}
.card{background:#fff;border:1px solid var(--line);border-radius:16px;padding:22px;margin-bottom:18px;box-shadow:0 1px 3px rgba(16,24,40,.05)}
.card h2{font-size:15px;font-weight:700;color:#2a3245;margin-bottom:16px;display:flex;align-items:center;gap:8px}
.card h2 .count{font-size:12px;color:var(--muted);font-weight:500}
.form-row{display:grid;grid-template-columns:1.4fr 1.4fr 1.2fr 1fr 1fr auto;gap:12px;align-items:end}
.form-row label{font-size:12px;font-weight:600;color:#5b6478;display:flex;flex-direction:column;gap:6px}
.formtip{font-size:11.5px;color:#9aa3b5;margin-top:10px;line-height:1.7}
input,select{padding:9px 11px;border:1px solid #d8dee9;border-radius:9px;font-size:13.5px;font-family:inherit;background:#fbfcfe;transition:border .15s,box-shadow .15s;width:100%}
input:focus,select:focus{outline:none;border-color:#93c0fd;box-shadow:0 0 0 3px rgba(59,130,246,.14);background:#fff}
input[type=checkbox]{width:15px;height:15px;accent-color:#3b82f6;cursor:pointer;padding:0}
.btn{padding:9px 20px;border:none;border-radius:9px;font-size:13.5px;font-weight:600;cursor:pointer;transition:.15s;height:38px;font-family:inherit}
.btn.sm{height:32px;padding:6px 14px;font-size:12.5px}
.btn-blue{background:linear-gradient(135deg,#3b82f6,#5a7cf7);color:#fff;box-shadow:0 3px 10px rgba(59,130,246,.3)}
.btn-blue:hover{transform:translateY(-1px);box-shadow:0 5px 14px rgba(59,130,246,.42)}
.btn-green{background:linear-gradient(135deg,#10b981,#0ea5a0);color:#fff;box-shadow:0 3px 10px rgba(16,185,129,.3)}
.btn-green:hover{transform:translateY(-1px);box-shadow:0 5px 14px rgba(16,185,129,.42)}
.btn-ghost{background:#f1f4f9;color:#5b6478}
.btn-ghost:hover{background:#e8edf5}
.btn-danger{background:linear-gradient(135deg,#ef4444,#dc2626);color:#fff;box-shadow:0 3px 10px rgba(220,38,38,.3)}
.btn-danger:hover{transform:translateY(-1px);box-shadow:0 5px 14px rgba(220,38,38,.42)}
.testbar{display:flex;align-items:center;gap:12px;flex-wrap:wrap;background:#f5f8ff;border:1px solid #dbe7ff;border-radius:11px;padding:10px 14px;margin-bottom:14px}
.selall{display:flex;align-items:center;gap:6px;font-size:12.5px;font-weight:600;color:#3b5bdb;cursor:pointer;user-select:none}
.selcount{font-size:12px;color:#8a94a8;min-width:76px}
.bar-actions{display:flex;gap:8px}
.bar-note{font-size:11.5px;color:#9aa3b5;margin-left:auto}
.table-wrap{overflow-x:auto;border:1px solid var(--line);border-radius:12px}
table{width:100%;border-collapse:collapse;font-size:13.5px;white-space:nowrap}
th{background:#f8fafd;color:#6b7689;font-weight:600;font-size:12px;padding:11px 14px;text-align:left;border-bottom:1px solid var(--line)}
td{padding:12px 14px;border-bottom:1px solid #f0f3f8;vertical-align:middle}
tbody tr:last-child td{border-bottom:none}
tbody tr{transition:background .12s}
tbody tr:hover{background:#f7faff}
tr[data-status="done"] td{opacity:.55}
.chkcell{width:36px;text-align:center}
.cname{font-weight:600}
.subname{font-size:12px;color:var(--muted);margin-top:2px}
.mono{font-variant-numeric:tabular-nums;color:#3d465a}
.badge{display:inline-flex;align-items:center;gap:6px;padding:3px 10px;border-radius:999px;font-size:11.5px;font-weight:600}
.badge::before{content:'';width:6px;height:6px;border-radius:50%;background:currentColor}
.b-pending{background:#eff6ff;color:#2563eb}
.b-notifying{background:#fffbeb;color:#b45309}
.b-done{background:#ecfdf5;color:#047857}
.muted2{color:var(--muted)}
.ops{display:flex;align-items:center;gap:7px}
.inline{display:inline-flex}
select.mini{padding:5px 8px;border-radius:8px;border:1px solid #d8dee9;font-size:12px;background:#fff;width:auto}
.linkbtn{border:none;background:#f2f5fa;width:29px;height:29px;border-radius:8px;cursor:pointer;font-size:13px;color:#5b6478;transition:.15s;display:inline-flex;align-items:center;justify-content:center}
.linkbtn.edit:hover{background:#dbeafe;color:#2563eb}
.linkbtn.test:hover{background:#ede9fe;color:#7c3aed}
.linkbtn.del:hover{background:#fee2e2;color:#dc2626}
.empty{padding:46px 0;text-align:center;color:#9aa3b5;font-size:13.5px}
.legend{text-align:center;color:#9aa3b5;font-size:12px;margin-top:20px;line-height:1.9;padding:0 10px}
.narrow{max-width:560px;margin:0 auto}
.hint{font-size:13px;color:var(--muted);margin-bottom:16px}
.chan{border:1px solid var(--line);border-radius:13px;padding:16px 18px;margin-bottom:14px;background:#fcfdff}
.chan-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:13px}
.chan-title{font-size:14px;font-weight:700;color:#2a3245}
.chan-body{display:flex;flex-direction:column}
.chan.off .chan-body{opacity:.55}
.chan-foot{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-top:2px;flex-wrap:wrap}
.chan-note{font-size:12px;color:var(--muted)}
label.cfg{display:flex;flex-direction:column;gap:6px;font-size:12.5px;font-weight:600;color:#5b6478;margin-bottom:12px}
.switch{position:relative;display:inline-block;width:42px;height:24px;flex:none;cursor:pointer}
.switch input{opacity:0;width:0;height:0;position:absolute}
.slider{position:absolute;inset:0;background:#d3dae6;border-radius:999px;transition:.2s}
.slider::before{content:'';position:absolute;width:18px;height:18px;left:3px;top:3px;background:#fff;border-radius:50%;transition:.2s;box-shadow:0 1px 3px rgba(0,0,0,.25)}
.switch input:checked + .slider{background:linear-gradient(135deg,#3b82f6,#6366f1)}
.switch input:checked + .slider::before{transform:translateX(18px)}
.btn-row{display:flex;gap:10px;margin-top:6px;flex-wrap:wrap}
.tip{font-size:12px;color:var(--muted);margin-top:16px;line-height:2}
.tip a{color:var(--blue)}
.modal{display:none;position:fixed;inset:0;background:rgba(15,23,42,.45);backdrop-filter:blur(3px);z-index:100;align-items:center;justify-content:center;padding:20px}
.modal.show{display:flex}
.modal-box{background:#fff;border-radius:16px;padding:26px;width:100%;max-width:440px;max-height:85vh;overflow-y:auto;animation:pop .18s ease}
@keyframes pop{from{opacity:0;transform:translateY(10px) scale(.98)}to{opacity:1;transform:none}}
.modal-box h3{font-size:16px;font-weight:700;margin-bottom:16px;color:#2a3245}
.field{margin-bottom:13px}
.field label{display:block;font-size:12px;font-weight:600;color:#5b6478;margin-bottom:6px}
.plan-summary{background:#f5f8ff;border:1px solid #dbe7ff;border-radius:9px;padding:10px 12px;font-size:12.5px;color:#3b5bdb;line-height:1.7;margin-top:2px;min-height:0}
.plan-summary:empty{display:none}
.modal-actions{display:flex;gap:10px;margin-top:18px}
.test-result{font-size:13.5px;line-height:2}
.tr-loading{color:#8a94a8;text-align:center;padding:18px 0}
.tr-line{display:flex;align-items:center;gap:8px}
.tr-line .chan-name{font-weight:600;color:#3d465a;min-width:70px}
.tr-ok{color:#047857}
.tr-err{color:#b91c1c}
.tr-skip{color:#8a94a8}
.tr-divider{border-top:1px dashed #e7ebf3;margin:10px 0}
@media (max-width:760px){
  .form-row{grid-template-columns:1fr 1fr}
  .form-row .btn{grid-column:span 2}
  .bar-note{display:none}
}
</style>
</head>
<body>
<div class="topbar">
  <div class="brand"><div class="logo">📋</div>订阅到期提醒</div>
  <nav>
    <a class="nav${navMain}" href="/">订阅管理</a>
    <a class="nav${navCfg}" href="/?page=config">通知设置</a>
    <form method="POST" action="/logout" style="display:inline;margin:0"><button type="submit" class="nav logout">退出</button></form>
  </nav>
</div>
${mainHtml}
${msgModal}
<script>
function closeMsgModal(){var m=document.getElementById('msgModal');if(m)m.classList.remove('show');}
(function(){
  var m=document.getElementById('msgModal');
  if(!m)return;
  m.classList.add('show');
  m.addEventListener('click',function(e){if(e.target===m)closeMsgModal();});
  document.addEventListener('keydown',function(e){if(e.key==='Escape')closeMsgModal();});
  // 成功提示 2 秒自动消失；错误提示文字较长，需手动关闭
  if(m.querySelector('.msg.ok'))setTimeout(closeMsgModal,2000);
  // 关闭后清掉地址栏的 saved 参数，避免刷新时重复弹窗（保留 page 等其他参数）
  try{var u=new URL(location.href);if(u.searchParams.has('saved')){u.searchParams.delete('saved');history.replaceState(null,'',u.pathname+(u.search||''));}}catch(e){}
})();
</script>
</body>
</html>`;
}

// ---------- 数据层 ----------
// isolate 内只初始化一次
let dbReady = false;
async function ensureDB(env) {
  if (dbReady) return;
  await env.DB.prepare(SCHEMA_SUBS).run();
  await env.DB.prepare(SCHEMA_CONFIG).run();
  await env.DB.prepare(SCHEMA_SESSIONS).run();
  await env.DB.prepare(SCHEMA_LOGIN_LOCK).run();

  const info = await env.DB.prepare('PRAGMA table_info(subs)').all();
  const have = new Set(((info && info.results) || []).map(c => c.name));
  const defs = {
    remark: "TEXT DEFAULT ''",
    price: "TEXT DEFAULT ''",
    cycle: "TEXT DEFAULT ''",
    renew_url: "TEXT DEFAULT ''",
    status: "TEXT DEFAULT 'pending'",
    notify_count: 'INTEGER DEFAULT 0',
    done_at: 'TEXT',
    remind_after: 'INTEGER DEFAULT 0'
  };
  for (const col of Object.keys(defs)) {
    if (!have.has(col)) {
      try { await env.DB.prepare('ALTER TABLE subs ADD COLUMN ' + col + ' ' + defs[col]).run(); } catch (e) {}
    }
  }
  // 旧状态归位：已忽略→已完成；已过期→待提醒（保留计数）
  await env.DB.prepare("UPDATE subs SET status='done' WHERE status='ignored'").run();
  await env.DB.prepare("UPDATE subs SET status='pending' WHERE status='expired'").run();
  dbReady = true;
}

async function setConfig(env, key, value) {
  await env.DB.prepare(
    'INSERT INTO config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value'
  ).bind(key, value).run();
}

// 一次性加载全部配置（DB 优先，环境变量兜底）
async function loadAllConfig(env) {
  const res = await env.DB.prepare('SELECT key, value FROM config').all();
  const cfg = {};
  for (const r of (res && res.results) || []) cfg[r.key] = r.value;
  for (const k of SECRET_KEYS) if (!cfg[k]) cfg[k] = env[k] || null;
  for (const k of TOGGLE_KEYS) if (cfg[k] === undefined || cfg[k] === null) cfg[k] = '1';
  return cfg;
}

async function listSubs(env) {
  const res = await env.DB.prepare('SELECT * FROM subs ORDER BY expire_at ASC').all();
  return (res && res.results) || [];
}

// ---------- 推送 ----------
async function tgSend(env, cfg, text) {
  if (cfg.TG_ENABLED === '0') return { ok: false, off: true, error: '开关已关闭' };
  const token = cfg.BOT_TOKEN;
  const chat = cfg.CHAT_ID;
  if (!token || !chat) return { ok: false, skipped: true, error: '未配置（Bot Token / Chat ID 缺失）' };
  try {
    const r = await fetch('https://api.telegram.org/bot' + token + '/sendMessage', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chat, text: text, parse_mode: 'HTML', disable_web_page_preview: true }),
      signal: AbortSignal.timeout(10000)
    });
    const data = await r.json().catch(() => ({}));
    if (data && data.ok) return { ok: true };
    return { ok: false, error: (data && data.description) || ('HTTP ' + r.status) };
  } catch (e) {
    return { ok: false, error: (e && e.message) || String(e) };
  }
}

async function scPush(env, cfg, title, content) {
  if (cfg.SC_ENABLED === '0') return { ok: false, off: true, error: '开关已关闭' };
  const key = cfg.SERVER_CHAN_KEY;
  if (!key) return { ok: false, skipped: true, error: '未配置（SendKey 缺失）' };
  try {
    const r = await fetch('https://sctapi.ftqq.com/' + key + '.send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title: title, desp: htmlToMarkdown(content) }),
      signal: AbortSignal.timeout(10000)
    });
    const data = await r.json().catch(() => ({}));
    if (data && (data.code === 0 || data.errno === 0)) return { ok: true };
    return { ok: false, error: (data && (data.message || data.errmsg)) || ('HTTP ' + r.status) };
  } catch (e) {
    return { ok: false, error: (e && e.message) || String(e) };
  }
}

// title 纯文本：TG 侧负责转义；返回两渠道结果供调用方判断计数推进
async function notifyAll(env, cfg, title, body) {
  return await Promise.all([
    tgSend(env, cfg, '<b>' + escHtml(title) + '</b>\n' + body),
    scPush(env, cfg, title, body)
  ]);
}

// ---------- Cron：状态流转 + 连续每日通知（北京时间日界） ----------
// 连发完自动回到「待提醒」并保留计数（改结束时间即开启新一轮）
async function runScheduled(env) {
  await ensureDB(env);
  const today = todayStr(); // 北京日期
  const cfg = await loadAllConfig(env); // 一轮只加载一次

  // 清理过期会话与限速记录
  const nowMs = Date.now();
  await env.DB.prepare('DELETE FROM sessions WHERE expires_at < ?').bind(nowMs).run();
  await env.DB.prepare('DELETE FROM login_lock WHERE updated_at < ? AND locked_until < ?')
    .bind(nowMs - 7 * 86400000, nowMs).run();

  // 待提醒 → 通知中：仅计数为 0 时进入（连发完回来保留计数，防重复轰炸）
  await env.DB.prepare(
    "UPDATE subs SET status='notifying', updated_at=datetime('now') WHERE status='pending' AND COALESCE(notify_count,0) = 0 AND julianday(expire_at) - julianday(?) <= notify_before"
  ).bind(today).run();

  // 通知中 → 待提醒：连发完自动回来，保留计数
  await env.DB.prepare(
    "UPDATE subs SET status='pending', updated_at=datetime('now') WHERE status='notifying' AND (julianday(?) - (julianday(expire_at) - COALESCE(notify_before,0)) + 1) > MAX(COALESCE(remind_after,0), 1)"
  ).bind(today).run();

  // 处于连发窗口内且今天未通知过的，推送
  const res = await env.DB.prepare(
    "SELECT * FROM subs WHERE status='notifying' AND (julianday(?) - (julianday(expire_at) - COALESCE(notify_before,0)) + 1) BETWEEN 1 AND MAX(COALESCE(remind_after,0), 1) AND (last_notified IS NULL OR last_notified != ?)"
  ).bind(today, today).all();

  for (const sub of (res && res.results) || []) {
    const results = await notifyAll(env, cfg, subStatusLine(sub), buildSubMessage(sub));
    // 有渠道成功（或渠道未启用）才推进计数；全部发送失败则下轮重试
    const anyOk = results[0].ok || results[1].ok;
    const anyAttempted = results.some(r => !r.off && !r.skipped);
    if (anyOk || !anyAttempted) {
      await env.DB.prepare(
        'UPDATE subs SET last_notified=?, notify_count=COALESCE(notify_count,0)+1, updated_at=datetime(\'now\') WHERE id=?'
      ).bind(today, sub.id).run();
    } else {
      console.error('notify failed for sub ' + sub.id + ':', JSON.stringify(results));
    }
  }
}

// ---------- HTTP ----------
async function handleRequest(request, env) {
  const url = new URL(request.url);
  const method = request.method;

  // 跨站 POST 防护：仅拦 Sec-Fetch-Site: cross-site（浏览器强制携带，无法伪造）；
  // Cookie SameSite=Lax 兜底；不比对 Origin（镜像/代理访问会误伤）
  if (method === 'POST' && request.headers.get('Sec-Fetch-Site') === 'cross-site') {
    return htmlResponse(renderErrorPage('请求被拒绝',
      '该请求被识别为跨站请求（CSRF 防护）。请直接在本站页面内操作，或刷新页面后重试'), 403);
  }

  // ---- 密码自检：未配置则显示初始化指南 ----
  if (!hasPasswordConfig(env)) {
    return htmlResponse(renderHashGuide());
  }

  // ---- 登录 / 登出 / 会话校验 ----
  if (env.DB) {
    try {
      await ensureDB(env);
    } catch (e) {
      // 建表失败则降级跳过，不挡登录
      console.error('ensureDB (login stage) failed:', e && e.message);
    }
  }

  const sid = getCookie(request, PW_COOKIE);

  // 登出仅 POST（防外链触发登出）
  if (url.pathname === '/logout') {
    if (method === 'POST') {
      if (env.DB && sid) {
        try { await destroySession(env, sid); } catch (e) {}
      }
      return redirect(url.origin + '/', clearSessionCookie());
    }
    return redirect(url.origin + '/');
  }

  const loggedIn = env.DB
    ? await validSession(env, sid).catch(() => false)
    : false;

  if (!loggedIn) {
    if (method === 'POST' && url.pathname === '/login') {
      if (!env.DB) {
        return htmlResponse(renderErrorPage('未检测到 D1 数据库',
          '登录需要 D1 存储 Session。请到 Workers → 设置 → 绑定 → 添加 D1 数据库（变量名 DB），保存后重新部署'));
      }
      const ip = clientIp(request);

      // 限速检查失败时跳过，不挡登录
      let lockLeft = 0;
      try {
        lockLeft = await lockRemaining(env, ip);
      } catch (e) {
        console.error('lockRemaining failed:', e && e.message);
      }
      if (lockLeft > 0) {
        return htmlResponse(renderLoginPage('尝试次数过多，已锁定。请 ' + lockLeft + ' 秒后再试'));
      }

      const fd = await request.formData();
      const ok = await checkPassword(fd.get('password'), env);
      if (ok) {
        try { await clearLoginFails(env, ip); } catch (e) {}
        const token = await createSession(env, ip);
        return redirect(url.origin + '/', sessionCookie(token));
      }
      let r = { fails: 0, locked: false };
      try {
        r = await recordLoginFail(env, ip);
      } catch (e) {
        console.error('recordLoginFail failed:', e && e.message);
      }
      if (r.locked) {
        return htmlResponse(renderLoginPage('密码错误次数过多，已锁定 10 分钟'));
      }
      return htmlResponse(renderLoginPage('密码错误，请重试'));
    }
    return htmlResponse(renderLoginPage());
  }

  // ---- D1 自检 ----
  if (!env.DB) {
    return htmlResponse(renderErrorPage('未检测到 D1 数据库',
      '请到 Workers → 设置 → 绑定 → 添加 D1 数据库，变量名必须填 DB（大写），保存后重新部署并刷新页面'));
  }

  await ensureDB(env);

  // ---- POST ----
  if (method === 'POST') {
    const fd = await request.formData();
    // 主页面校验失败提示统一渲染（添加/编辑共用）
    const mainError = async (text) => htmlResponse(
      renderHTML(await listSubs(env), { type: 'err', text }, await loadAllConfig(env), 'main'));

    if (url.pathname === '/add') {
      const name = String(fd.get('name') || '').trim();
      const expire = String(fd.get('expire_at') || '').trim();
      const start = String(fd.get('notify_start') || '').trim();
      if (!name || !isValidDate(expire) || !isValidDate(start)) {
        return mainError('名称不能为空，日期格式应为 YYYY-MM-DD');
      }
      // 结束时间在过去则一条提醒都发不出
      if (expire < todayStr()) {
        return mainError('结束时间不能早于今天——过去的订阅无法提醒');
      }
      // 提前天数由服务端从两个日期换算
      const gap = diffDays(start, expire);
      if (gap === null || gap < 0) {
        return mainError('通知时间需在结束时间之前（含当天）');
      }
      if (gap > 365) {
        return mainError('通知时间最多提前 365 天——再远就失去提醒意义了，请把通知时间改近一些');
      }
      // 连发天数 = remind_after 所填值（1~365），从通知时间起算，不再校正
      const nbIn = gap;
      let raIn = parseInt(fd.get('remind_after'), 10);
      if (isNaN(raIn) || raIn < 1) raIn = 1;
      if (raIn > 365) raIn = 365;
      await env.DB.prepare(
        'INSERT INTO subs (name, remark, expire_at, notify_before, remind_after) VALUES (?,?,?,?,?)'
      ).bind(
        name,
        String(fd.get('remark') || '').trim().slice(0, 100),
        expire,
        nbIn,
        raIn
      ).run();
      return redirect(url.origin + '/?saved=added');
    }

    if (url.pathname === '/delete') {
      const id = fd.get('id');
      if (id) await env.DB.prepare('DELETE FROM subs WHERE id=?').bind(id).run();
      return redirect(url.origin + '/');
    }

    // 批量删除（D1 单语句参数上限 100，需分批）
    if (url.pathname === '/deletemulti') {
      const ids = fd.getAll('subids') || [];
      for (let i = 0; i < ids.length; i += 100) {
        const chunk = ids.slice(i, i + 100);
        const ph = chunk.map(() => '?').join(',');
        await env.DB.prepare('DELETE FROM subs WHERE id IN (' + ph + ')').bind(...chunk).run();
      }
      return redirect(url.origin + '/?saved=deleted');
    }

    if (url.pathname === '/setstatus') {
      const id = fd.get('id');
      const status = String(fd.get('status') || '');
      if (id && VALID_STATUS.includes(status)) {
        const doneCol = status === 'done' ? ', done_at=?' : '';
        // 置回待提醒时清零计数（开启新一轮）
        const resetCol = status === 'pending' ? ', notify_count=0, last_notified=NULL' : '';
        const params = [status];
        if (status === 'done') params.push(todayStr());
        params.push(id);
        await env.DB.prepare(
          "UPDATE subs SET status=?, updated_at=datetime('now')" + doneCol + resetCol + " WHERE id=?"
        ).bind(...params).run();
      }
      return redirect(url.origin + '/?saved=status');
    }

    if (url.pathname === '/edit') {
      const id = fd.get('id');
      const name = String(fd.get('name') || '').trim();
      const expire = String(fd.get('expire_at') || '').trim();
      const start = String(fd.get('notify_start') || '').trim();
      const status = String(fd.get('status') || 'pending');
      if (!id || !name || !isValidDate(expire) || !isValidDate(start) || !VALID_STATUS.includes(status)) {
        return mainError('编辑失败：名称不能为空，日期格式应为 YYYY-MM-DD');
      }
      if (expire < todayStr()) {
        return mainError('编辑失败：结束时间不能早于今天');
      }
      // 提前天数由服务端从两个日期换算
      const gap = diffDays(start, expire);
      if (gap === null || gap < 0) {
        return mainError('编辑失败：通知时间需在结束时间之前（含当天）');
      }
      const old = await env.DB.prepare('SELECT expire_at FROM subs WHERE id=?').bind(id).first();
      if (gap > 365) {
        return mainError('编辑失败：通知时间最多提前 365 天');
      }
      const nbEd = gap;
      let raEd = parseInt(fd.get('remind_after'), 10);
      if (isNaN(raEd) || raEd < 1) raEd = 1;
      if (raEd > 365) raEd = 365;
      await env.DB.prepare(
        "UPDATE subs SET name=?, remark=?, expire_at=?, notify_before=?, remind_after=?, status=?, updated_at=datetime('now') WHERE id=?"
      ).bind(
        name,
        String(fd.get('remark') || '').trim().slice(0, 100),
        expire,
        nbEd,
        raEd,
        status,
        id
      ).run();
      // 到期日被改动 → 开启新一轮提醒周期，计数归零
      if (old && old.expire_at !== expire) {
        await env.DB.prepare('UPDATE subs SET notify_count=0, last_notified=NULL WHERE id=?').bind(id).run();
      }
      return redirect(url.origin + '/?saved=updated');
    }

    // 仅设置页表单才写入，防误清空
    const saveConfigIfForm = async () => {
      if (fd.get('cfgform') !== '1') return;
      for (const k of SECRET_KEYS) {
        await setConfig(env, k, String(fd.get(k) || '').trim());
      }
      await setConfig(env, 'TG_ENABLED', fd.get('TG_ENABLED') ? '1' : '0');
      await setConfig(env, 'SC_ENABLED', fd.get('SC_ENABLED') ? '1' : '0');
    };

    if (url.pathname === '/saveconfig') {
      await saveConfigIfForm();
      return redirect(url.origin + '/?page=config&saved=1');
    }

    // 渠道测试：channel = tg / sc / all
    if (url.pathname === '/testnotify') {
      await saveConfigIfForm();
      const channel = String(fd.get('channel') || 'all');
      const cfg = await loadAllConfig(env);

      const lines = [];
      let tested = 0, okCnt = 0;

      if (channel === 'tg' || channel === 'all') {
        const r = await tgSend(env, cfg, '🧪 <b>测试通知 · Telegram</b>\n收到这条消息，说明 Telegram 渠道配置正确 ✅');
        tested++; if (r.ok) okCnt++;
        lines.push('Telegram：' + escHtml(fmtResult(r)));
      }
      if (channel === 'sc' || channel === 'all') {
        const r = await scPush(env, cfg, '🧪 测试通知 · Server 酱', '收到这条消息，说明 Server 酱渠道配置正确 ✅');
        tested++; if (r.ok) okCnt++;
        lines.push('Server 酱：' + escHtml(fmtResult(r)));
      }

      let msgText, msgType;
      if (tested === 0) {
        msgText = '未知渠道'; msgType = 'err';
      } else if (okCnt === tested) {
        msgText = '🎉 测试消息已发出，请前往对应应用查收！<br>' + lines.join('<br>'); msgType = 'ok';
      } else if (okCnt === 0) {
        const allOff = lines.every(l => l.indexOf('开关已关闭') >= 0);
        msgText = (allOff ? '🔕 该渠道开关已关闭，到期提醒不会推送。请打开开关后再测试。<br>' : '测试未成功（配置已保存）：<br>') + lines.join('<br>');
        msgType = 'err';
      } else {
        msgText = '测试结果（部分成功，配置已保存）：<br>' + lines.join('<br>'); msgType = 'err';
      }

      return htmlResponse(renderHTML([], { type: msgType, text: msgText }, cfg, 'config'));
    }

    // 订阅测试：subids 多选 / all=1；fmt=json 返回弹窗数据
    if (url.pathname === '/testsub') {
      const wantJson = url.searchParams.get('fmt') === 'json';
      const all = String(fd.get('all') || '') === '1';
      let targets = [];
      if (all) {
        targets = await listSubs(env);
      } else {
        const ids = fd.getAll('subids') || [];
        // D1 单语句绑定参数上限 100，勾选过多时需分批执行
        for (let i = 0; i < ids.length; i += 100) {
          const chunk = ids.slice(i, i + 100);
          const ph = chunk.map(() => '?').join(',');
          const res = await env.DB.prepare('SELECT * FROM subs WHERE id IN (' + ph + ')').bind(...chunk).all();
          targets = targets.concat((res && res.results) || []);
        }
      }

      const cfg = await loadAllConfig(env);

      if (!targets.length) {
        if (wantJson) {
          return jsonResponse({
            title: '🧪 测试提醒',
            html: '<div class="tr-line">🔖 后端 ' + APP_VERSION + '</div><div class="tr-line tr-err">没有可测试的订阅' + (all ? '，请先添加' : '，请先勾选') + '</div>'
          });
        }
        return htmlResponse(renderHTML(await listSubs(env),
          { type: 'err', text: '没有可测试的订阅' + (all ? '，请先添加' : '，请先勾选') }, cfg, 'main'));
      }

      // 构造消息：单条 → 卡片；多条 → 合并一条
      let title, body, mode;
      if (targets.length === 1) {
        mode = '单条完整提醒';
        title = '🧪 ' + subStatusLine(targets[0]);
        body = buildSubMessage(targets[0], true);
      } else {
        mode = '合并为一条完整提醒';
        title = '🧪 测试提醒汇总 · ' + targets.length + ' 条';
        // 每条订阅输出完整卡片（状态行 + 事实），合并进一条消息；多张时标注顺序
        body = targets.map((s, i) => {
          const plan = notifyPlan(s);
          const d = daysLeft(s.expire_at);
          const dayNo = Math.min(plan.chain, Math.max(1, plan.nb - Math.max(d, 0) + 1));
          return subStatusLine(s) + ' ｜ ' + (i + 1) + '/' + targets.length + '\n' + subFacts(s, dayNo);
        }).join('\n\n━━━━━━━━━━━━━━━\n\n') + '\n\n测试消息 · 非真实提醒';
      }

      // TG 侧标题整体转义（名称可能含 < > &）；Server 酱标题用纯文本
      const tgR = await tgSend(env, cfg, '<b>' + escHtml(title) + '</b>\n' + body);
      const scR = await scPush(env, cfg, title, body);
      const anyOk = tgR.ok || scR.ok;

      if (wantJson) {
        const cls = r => r.ok ? 'tr-ok' : (r.off || r.skipped ? 'tr-skip' : 'tr-err');
        const icon = r => r.ok ? '✅' : (r.off || r.skipped ? '⏭' : '❌');
        const detail = r => r.ok ? '发送成功' : (r.off ? '开关已关闭' : (r.skipped ? r.error : r.error));
        const html =
          '<div class="tr-line"><span class="chan-name">🔖 版本</span><span>后端 ' + APP_VERSION + '</span></div>' +
          '<div class="tr-line"><span class="chan-name">📋 测试</span><span>已测试 ' + targets.length + ' 条订阅（' + escHtml(mode) + '）</span></div>' +
          '<div class="tr-divider"></div>' +
          '<div class="tr-line"><span class="chan-name">Telegram</span><span class="' + cls(tgR) + '">' + icon(tgR) + ' ' + escHtml(detail(tgR)) + '</span></div>' +
          '<div class="tr-line"><span class="chan-name">Server 酱</span><span class="' + cls(scR) + '">' + icon(scR) + ' ' + escHtml(detail(scR)) + '</span></div>' +
          (anyOk ? '' : '<div class="tr-divider"></div><div class="tr-line"><span class="tr-err">💡 请检查「通知设置」中的渠道配置与开关</span></div>');
        return jsonResponse({ title: title, html: html });
      }

      const lines = [];
      lines.push('📋 已测试 ' + targets.length + ' 条订阅（' + escHtml(mode) + '）');
      lines.push('Telegram：' + escHtml(fmtResult(tgR)));
      lines.push('Server 酱：' + escHtml(fmtResult(scR)));

      const msgText = (anyOk ? '🎉 测试提醒已发出，请前往对应应用查收！<br>' : '测试未成功：<br>') + lines.join('<br>');
      return htmlResponse(renderHTML(await listSubs(env),
        { type: anyOk ? 'ok' : 'err', text: msgText }, cfg, 'main'));
    }

    return redirect(url.origin + '/');
  }

  // ---- GET ----
  if (url.pathname === '/getsub') {
    const id = url.searchParams.get('id');
    const sub = id ? await env.DB.prepare('SELECT * FROM subs WHERE id=?').bind(id).first() : null;
    if (sub) {
      // 通知时间回显值由服务端算好
      sub.notify_start_display = dateMinusDaysLocal(
        sub.expire_at, Math.max(0, Math.min(365, Number(sub.notify_before) || 0)));
    }
    return jsonResponse(sub || null);
  }

  const page = url.searchParams.get('page') === 'config' ? 'config' : 'main';
  const saved = url.searchParams.get('saved');
  const subs = await listSubs(env);
  const cfg = await loadAllConfig(env);

  // 操作成功提示（保存设置 / 批量删除）
  let message = null;
  if (saved === '1') {
    message = { type: 'ok', text: '💾 通知设置已保存并生效' };
  } else if (saved === 'deleted') {
    message = { type: 'ok', text: '🗑 选中的订阅已删除' };
  } else if (saved === 'added') {
    message = { type: 'ok', text: '✅ 订阅已添加' };
  } else if (saved === 'updated') {
    message = { type: 'ok', text: '✅ 修改已保存' };
  } else if (saved === 'status') {
    message = { type: 'ok', text: '✅ 状态已更新' };
  }

  const html = renderHTML(subs, message, cfg, page);

  return htmlResponse(html);
}

// ---------- 入口 ----------
export default {
  async fetch(request, env, ctx) {
    try {
      return await handleRequest(request, env);
    } catch (e) {
      console.error('worker error:', e);
      const msg = String((e && e.message) || e);
      try {
        return htmlResponse(renderErrorPage('发生内部错误', msg), 500);
      } catch (e2) {
        return new Response('Internal Error', { status: 500 });
      }
    }
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(
      runScheduled(env).catch(e => console.error('cron error:', e && (e.message || e)))
    );
  }
};
