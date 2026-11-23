require('dotenv').config();

const express       = require('express');
const cors          = require('cors');
const compression   = require('compression');
const helmet        = require('helmet');
const rateLimit     = require('express-rate-limit');
const { Pool }      = require('pg');
const crypto        = require('crypto');

const app  = express();
const PORT = Number(process.env.PORT) || 3000;

app.set('trust proxy', 1);

// ─── Tunables ─────────────────────────────────────────────
const CAPTURE_TIMEOUT      = Number(process.env.CAPTURE_TIMEOUT)   || 15_000;
const CAPTURE_CONCURRENCY  = Number(process.env.CAPTURE_CONCURRENCY) || 6;
const QUEUE_TIMEOUT        = Number(process.env.QUEUE_TIMEOUT)     || 30_000;
const MEM_CACHE_MAX        = Number(process.env.MEM_CACHE_MAX)     || 2000;
const CACHE_TTL            = Number(process.env.CACHE_TTL)         || 30 * 60_000;
const NEGATIVE_CACHE_TTL   = Number(process.env.NEGATIVE_CACHE_TTL)|| 60_000;
const THUMBNAIL_RETRY_MS   = Number(process.env.THUMBNAIL_RETRY_MS)|| 5 * 60_000;
const DB_POOL_MAX          = Number(process.env.DB_POOL_MAX)       || 10;
const RATE_LIMIT_MAX       = Number(process.env.RATE_LIMIT_MAX)    || 120;
const LOG_LEVEL            = (process.env.LOG_LEVEL  || 'info').toLowerCase();
const LOG_JSON             = process.env.LOG_JSON === 'true';
const LOG_COLOR            = process.env.LOG_COLOR !== 'false' && process.stdout.isTTY;

// ─── Freshness / refresh tunables ─────────────────────────
const REFRESH_ENABLED            = process.env.REFRESH_ENABLED !== 'false';
const REFRESH_INTERVAL_MS        = Number(process.env.REFRESH_INTERVAL_MS) || 24 * 60 * 60_000;
const REFRESH_CONCURRENCY        = Number(process.env.REFRESH_CONCURRENCY) || 1;
const REFRESH_BATCH              = Number(process.env.REFRESH_BATCH)       || 100;
const REFRESH_BOOT_DELAY         = Number(process.env.REFRESH_BOOT_DELAY)  || 60_000;
const REFRESH_RETRY_TTL          = Number(process.env.REFRESH_RETRY_TTL)   || 5 * 60_000;
const REFRESH_INTER_REQUEST_DELAY_MS = Number(process.env.REFRESH_INTER_REQUEST_DELAY_MS) || 1000;
const ADMIN_TOKEN                = process.env.ADMIN_TOKEN || '';

// ─── vidbolt.st API config ────────────────────────────────
const VIDBOLT_BASE              = (process.env.VIDBOLT_BASE || 'https://vidbolt.st').replace(/\/+$/, '');
const VIDBOLT_TIMEOUT           = Number(process.env.VIDBOLT_TIMEOUT) || 15_000;
const VIDBOLT_HEVC              = (process.env.VIDBOLT_HEVC === '1') ? '1' : '0';
const VIDBOLT_UA                = process.env.VIDBOLT_UA ||
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36';
const VIDBOLT_SEC_CH_UA         = process.env.VIDBOLT_SEC_CH_UA ||
  '"Not-A.Brand";v="99", "Google Chrome";v="157", "Chromium";v="157"';

// ─── Thumbnail proxy config ───────────────────────────────
const PROXY_PUBLIC_BASE         = (process.env.PROXY_PUBLIC_BASE || '').replace(/\/+$/, '');
const THUMB_SIGNING_SECRET      = process.env.THUMB_SIGNING_SECRET || ADMIN_TOKEN || crypto.randomBytes(32).toString('hex');
const THUMB_PROXY_TIMEOUT       = Number(process.env.THUMB_PROXY_TIMEOUT) || 15_000;
const THUMB_RATE_LIMIT_MAX      = Number(process.env.THUMB_RATE_LIMIT_MAX) || 3000;

// ─── Upstream rate limiting ───────────────────────────────
const VIDBOLT_MIN_INTERVAL_MS   = Number(process.env.VIDBOLT_MIN_INTERVAL_MS)   || 1000;
const VIDBOLT_BACKOFF_BASE_MS   = Number(process.env.VIDBOLT_BACKOFF_BASE_MS)   || 30_000;
const VIDBOLT_BACKOFF_MAX_MS    = Number(process.env.VIDBOLT_BACKOFF_MAX_MS)    || 10 * 60_000;

const EFFECTIVE_QUEUE_TIMEOUT = Math.min(QUEUE_TIMEOUT, CAPTURE_TIMEOUT);

// ─── CORS allow-list ──────────────────────────────────────
const ALLOWED_ORIGINS = (
  process.env.ALLOWED_ORIGINS ||
  [
    'https://moonflix.website',
    'https://www.moonflix.website',
    'https://player.moonflix.website',
    'https://embed.moonflix.info',
    'https://moonflix.info',
    'https://www.moonflix.info',
    'http://localhost:3000',
    'http://localhost:5173',
    'http://localhost:4000',
    'http://localhost:3001'
  ].join(',')
).split(',').map(s => s.trim().toLowerCase()).filter(Boolean);

const ALLOWED_HOSTS = new Set(
  ALLOWED_ORIGINS.map(o => {
    try { return new URL(o).hostname.toLowerCase(); }
    catch { return o.replace(/^https?:\/\//, '').split('/')[0].toLowerCase(); }
  })
);

function hostOf(value) {
  if (!value || value === 'null') return null;
  try { return new URL(value).hostname.toLowerCase(); }
  catch { return null; }
}
function isAllowedOrigin(origin) {
  const h = hostOf(origin);
  return !!h && ALLOWED_HOSTS.has(h);
}
function isAllowedReferer(referer) {
  const h = hostOf(referer);
  return !!h && ALLOWED_HOSTS.has(h);
}

// ═══════════════════════════════════════════════════════════════
//  LOGGER
// ═══════════════════════════════════════════════════════════════
const C = LOG_COLOR ? {
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
  red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m', blue: '\x1b[34m',
  magenta: '\x1b[35m', cyan: '\x1b[36m', white: '\x1b[37m', gray: '\x1b[90m',
} : new Proxy({}, { get: () => '' });

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };
const LEVEL_MIN = LEVELS[LOG_LEVEL] || 20;

const LEVEL_META = {
  debug: { icon: '🔍', color: C.gray,    label: 'DEBUG' },
  info:  { icon: 'ℹ️ ', color: C.cyan,    label: 'INFO ' },
  ok:    { icon: '✅', color: C.green,   label: 'OK   ' },
  warn:  { icon: '⚠️ ', color: C.yellow,  label: 'WARN ' },
  error: { icon: '❌', color: C.red,     label: 'ERROR' },
};

const TAG_STYLE = {
  db:        { icon: '💾', color: C.magenta },
  fetch:     { icon: '🛰️ ', color: C.blue },
  cache:     { icon: '⚡', color: C.yellow },
  capture:   { icon: '🎯', color: C.cyan },
  server:    { icon: '🚀', color: C.green },
  http:      { icon: '🌐', color: C.white },
  proxy:     { icon: '🎬', color: C.magenta },
  thumb:     { icon: '🖼️ ', color: C.cyan },
  queue:     { icon: '⏳', color: C.yellow },
  refresh:   { icon: '♻️ ', color: C.cyan },
  shutdown:  { icon: '🛑', color: C.red },
  ready:     { icon: '✨', color: C.green },
};

function ts() {
  const d = new Date();
  const p = n => String(n).padStart(2, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}
function fmtVal(v) {
  if (v === null || v === undefined) return '';
  if (typeof v === 'object') return JSON.stringify(v);
  return String(v);
}
function log(level, tag, msg, extra) {
  if (LOG_JSON) {
    const line = JSON.stringify({
      t: new Date().toISOString(), level,
      tag: tag || 'app', msg, ...(extra || {}),
    });
    (level === 'error' || level === 'warn' ? process.stderr : process.stdout).write(line + '\n');
    return;
  }
  const lvl = LEVELS[level] ?? 20;
  if (lvl < LEVEL_MIN) return;

  const meta = LEVEL_META[level] || LEVEL_META.info;
  const tstyle = TAG_STYLE[tag] || { icon: '·', color: C.gray };

  let extras = '';
  if (extra && typeof extra === 'object') {
    const parts = [];
    for (const [k, v] of Object.entries(extra)) {
      const val = fmtVal(v);
      if (val === '') continue;
      parts.push(`${C.gray}${k}${C.reset}${C.dim}=${C.reset}${C.white}${val}${C.reset}`);
    }
    if (parts.length) extras = '  ' + parts.join(' ');
  }

  const line =
    `${C.gray}${ts()}${C.reset}  ` +
    `${meta.color}${meta.icon}${C.reset}  ` +
    `${tstyle.color}${String(tag || 'app').padEnd(8)}${C.reset} ` +
    `${C.white}${msg}${C.reset}` +
    extras;

  (level === 'error' || level === 'warn' ? process.stderr : process.stdout).write(line + '\n');
}
function banner() {
  if (LOG_JSON) return;
  const lines = [
    '',
    `${C.cyan}  ╭─────────────────────────────────────────────────────────────╮${C.reset}`,
    `${C.cyan}  │${C.reset}  ${C.bold}🎬  filmu.in stream proxy${C.reset}                                  ${C.cyan}│${C.reset}`,
    `${C.cyan}  │${C.reset}  ${C.gray}v3.9 · vidbolt.st · rate-limited · thumbnail proxy${C.reset}    ${C.cyan}│${C.reset}`,
    `${C.cyan}  ╰─────────────────────────────────────────────────────────────╯${C.reset}`,
    '',
  ];
  process.stdout.write(lines.join('\n') + '\n');
}
function divider(label) {
  if (LOG_JSON) return;
  const w = 62;
  const mid = ` ${label} `;
  const left = Math.floor((w - mid.length) / 2);
  const right = w - mid.length - left;
  process.stdout.write(
    `\n${C.gray}  ${'─'.repeat(left)}${C.reset}${C.bold}${mid}${C.reset}${C.gray}${'─'.repeat(right)}${C.reset}\n`
  );
}

// ═══════════════════════════════════════════════════════════════
//  THUMBNAIL PROXY (signing + VTT rewriting)
// ═══════════════════════════════════════════════════════════════
function thumbSig(upstreamUrl) {
  return crypto.createHmac('sha256', THUMB_SIGNING_SECRET)
    .update(upstreamUrl, 'utf8')
    .digest('base64url');
}

function buildThumbProxyUrl(upstreamUrl, req) {
  if (!upstreamUrl || typeof upstreamUrl !== 'string') return upstreamUrl;
  let base = PROXY_PUBLIC_BASE;
  if (!base && req) {
    const proto = req.protocol || 'https';
    const host  = req.get('host') || req.hostname;
    if (host) base = `${proto}://${host}`;
  }
  if (!base) return upstreamUrl;
  const u = Buffer.from(upstreamUrl, 'utf8').toString('base64url');
  const s = thumbSig(upstreamUrl);
  return `${base}/api/thumb?u=${u}&s=${s}`;
}

function guessMime(pathname) {
  const p = (pathname || '').toLowerCase();
  if (p.endsWith('.jpg') || p.endsWith('.jpeg')) return 'image/jpeg';
  if (p.endsWith('.png'))  return 'image/png';
  if (p.endsWith('.webp')) return 'image/webp';
  if (p.endsWith('.gif'))  return 'image/gif';
  if (p.endsWith('.avif')) return 'image/avif';
  if (p.endsWith('.vtt'))  return 'text/vtt; charset=utf-8';
  return null;
}

const VTT_TIMESTAMP_RE = /^\s*\d{1,2}:\d{2}:\d{2}[.,]\d{3}\s*-->\s*\d{1,2}:\d{2}:\d{2}[.,]\d{3}/;
const VTT_PAYLOAD_RE   = /^(\s*)([^\s#]+?)(#\S+)?(\s*)$/;
const IMG_EXT_RE       = /\.(?:jpe?g|png|webp|gif|avif)(?:$|[?#])/i;

function rewriteVtt(text, vttUrl, req) {
  const lines = text.split(/\r?\n/);
  const out = [];
  let inCuePayload = false;

  for (const line of lines) {
    if (VTT_TIMESTAMP_RE.test(line)) {
      out.push(line);
      inCuePayload = true;
      continue;
    }
    if (line.trim() === '') {
      inCuePayload = false;
      out.push(line);
      continue;
    }
    if (inCuePayload) {
      const m = VTT_PAYLOAD_RE.exec(line);
      if (m) {
        const rawRel = m[2];
        if (IMG_EXT_RE.test(rawRel)) {
          try {
            const abs = new URL(rawRel, vttUrl).toString();
            out.push(`${m[1]}${buildThumbProxyUrl(abs, req)}${m[3] || ''}${m[4]}`);
            continue;
          } catch { /* fall through */ }
        }
      }
    }
    out.push(line);
  }
  return out.join('\n');
}

async function proxyThumb(req, res) {
  const { u, s } = req.query;
  if (typeof u !== 'string' || typeof s !== 'string' || !u || !s) {
    return res.status(400).json({ error: 'bad_request' });
  }

  let upstreamUrl;
  try { upstreamUrl = Buffer.from(u, 'base64url').toString('utf8'); }
  catch { return res.status(400).json({ error: 'bad_url' }); }

  let parsed;
  try { parsed = new URL(upstreamUrl); }
  catch { return res.status(400).json({ error: 'bad_url' }); }

  if (!/^https?:$/.test(parsed.protocol)) {
    return res.status(400).json({ error: 'bad_protocol' });
  }

  // Constant-time signature verification
  const expected = Buffer.from(thumbSig(upstreamUrl), 'utf8');
  const provided = Buffer.from(s, 'utf8');
  if (expected.length !== provided.length || !crypto.timingSafeEqual(expected, provided)) {
    log('warn', 'thumb', 'sig mismatch', { url: upstreamUrl.slice(0, 120) });
    return res.status(403).json({ error: 'forbidden' });
  }

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), THUMB_PROXY_TIMEOUT);

  try {
    const upstreamRes = await fetch(upstreamUrl, {
      headers: {
        'accept': '*/*',
        'accept-language': 'en-US,en;q=0.9',
        'accept-encoding': 'gzip, deflate, br',
        // Must be vidbolt.st — the CDN 403s any other Origin/Referer
        'origin':  VIDBOLT_BASE,
        'referer': `${VIDBOLT_BASE}/`,
        'user-agent': VIDBOLT_UA,
        'sec-ch-ua': VIDBOLT_SEC_CH_UA,
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'cross-site',
      },
      redirect: 'follow',
      signal: ctrl.signal,
    });

    if (!upstreamRes.ok) {
      log('warn', 'thumb', 'upstream non-ok', { status: upstreamRes.status, url: upstreamUrl.slice(0, 120) });
      return res.status(upstreamRes.status).json({ error: `upstream_${upstreamRes.status}` });
    }

    const buf = Buffer.from(await upstreamRes.arrayBuffer());
    const upstreamCt = (upstreamRes.headers.get('content-type') || '').toLowerCase();
    const headAscii  = buf.slice(0, 6).toString('ascii');
    const isVtt      = upstreamCt.includes('text/vtt') || headAscii === 'WEBVTT' || /\.vtt($|\?)/i.test(upstreamUrl);

    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', '*');
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
    res.setHeader('X-Content-Type-Options', 'nosniff');

    if (isVtt) {
      const rewritten = rewriteVtt(buf.toString('utf8'), upstreamUrl, req);
      res.setHeader('Content-Type', 'text/vtt; charset=utf-8');
      res.setHeader('Cache-Control', 'public, max-age=3600');
      return res.send(rewritten);
    }

    const ct = upstreamRes.headers.get('content-type') || guessMime(parsed.pathname) || 'application/octet-stream';
    res.setHeader('Content-Type', ct);
    const cc = upstreamRes.headers.get('cache-control');
    res.setHeader('Cache-Control', cc || 'public, max-age=86400');
    const etag = upstreamRes.headers.get('etag');
    if (etag) res.setHeader('ETag', etag);
    const lm = upstreamRes.headers.get('last-modified');
    if (lm) res.setHeader('Last-Modified', lm);
    res.setHeader('Content-Length', String(buf.length));
    return res.end(buf);

  } catch (err) {
    log('warn', 'thumb', 'fetch error', { err: err.message, url: upstreamUrl.slice(0, 120) });
    return res.status(502).json({ error: 'upstream_failed' });
  } finally {
    clearTimeout(timer);
  }
}

// ═══════════════════════════════════════════════════════════════
//  EXPRESS
// ═══════════════════════════════════════════════════════════════
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(compression());

const corsOptions = {
  origin(origin, cb) {
    if (!origin) return cb(null, false);
    if (isAllowedOrigin(origin)) return cb(null, true);
    log('warn', 'http', 'cors origin rejected', { origin });
    return cb(null, false);
  },
  credentials: true,
  methods: ['GET', 'HEAD', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Accept', 'Origin', 'X-Requested-With'],
  exposedHeaders: [
    'x-cache-source',
    'x-data-outcome',
    'x-data-stale',
    'x-data-verified',
    'x-data-updated',
    'x-data-matched',
    'x-data-updated-at',
    'Retry-After',
  ],
  maxAge: 86_400,
  optionsSuccessStatus: 204,
};
app.use(cors(corsOptions));
app.use(express.json({ limit: '64kb' }));

app.use((req, res, next) => {
  req.id = crypto.randomBytes(4).toString('hex');
  req._t0 = process.hrtime.bigint();

  const q = { ...req.query };
  delete q.type;
  delete q.u; // don't log signed thumbnail URLs (noisy)
  delete q.s;
  const queryStr = Object.entries(q)
    .map(([k, v]) => `${C.gray}${k}${C.reset}${C.dim}=${C.reset}${C.white}${v}${C.reset}`)
    .join('  ');

  log('info', 'http', `${C.cyan}→${C.reset}  ${C.bold}${req.method}${C.reset}  ${req.path}${queryStr ? '  ' + queryStr : ''}`, { id: req.id });

  res.on('finish', () => {
    const ms = Number(process.hrtime.bigint() - req._t0) / 1e6;
    const statusColor =
      res.statusCode >= 500 ? C.red :
      res.statusCode >= 400 ? C.yellow :
      res.statusCode >= 300 ? C.cyan :
      C.green;
    const msColor = ms < 100 ? C.green : ms < 1000 ? C.cyan : ms < 3000 ? C.yellow : C.red;
    const tag = res.getHeader('x-cache-source') || '';
    const outcome = res.getHeader('x-data-outcome') || '';

    log('info', 'http',
      `${statusColor}← ${res.statusCode}${C.reset}  ${C.bold}${req.path}${C.reset}  ` +
      `${msColor}${ms.toFixed(0)}ms${C.reset}` +
      (tag ? `  ${C.gray}via ${C.reset}${C.magenta}${tag}${C.reset}` : '') +
      (outcome ? `  ${C.gray}[${C.reset}${C.cyan}${outcome}${C.reset}${C.gray}]${C.reset}` : '')
    , { id: req.id });
  });
  next();
});

app.use('/api', rateLimit({
  windowMs: 60_000,
  max: RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  // Sprite sheets can be many per VTT — they have their own limiter below.
  skip: (req) => req.originalUrl.startsWith('/api/thumb'),
}));

const thumbLimiter = rateLimit({
  windowMs: 60_000,
  max: THUMB_RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
});

// Thumbnail proxy — registered AFTER the /api rate limit but skipped above,
// then throttled by its own generous limiter.
app.get('/api/thumb', thumbLimiter, proxyThumb);

// ═══════════════════════════════════════════════════════════════
//  DB POOL + STATE
// ═══════════════════════════════════════════════════════════════
function buildPoolConfig() {
  const ssl = { rejectUnauthorized: false };
  if (process.env.DATABASE_URL) {
    const cleanUrl = process.env.DATABASE_URL
      .replace(/([?&])sslmode=[^&]*&?/g, '$1').replace(/[?&]$/, '');
    return {
      connectionString: cleanUrl, ssl,
      max: DB_POOL_MAX, min: 2,
      idleTimeoutMillis: 30_000, connectionTimeoutMillis: 10_000,
      statement_timeout: 5_000, query_timeout: 5_000,
      application_name: 'filmu-proxy',
    };
  }
  return {
    host: process.env.PGHOST, port: Number(process.env.PGPORT) || 5432,
    user: process.env.PGUSER, password: process.env.PGPASSWORD,
    database: process.env.PGDATABASE || 'defaultdb', ssl,
    max: DB_POOL_MAX, min: 2,
    idleTimeoutMillis: 30_000, connectionTimeoutMillis: 10_000,
    statement_timeout: 5_000, query_timeout: 5_000,
    application_name: 'filmu-proxy',
  };
}

const pool = new Pool(buildPoolConfig());
pool.on('error', (err) => log('error', 'db', 'idle client error', { err: err.message }));
pool.on('connect', () => log('debug', 'db', 'new client connected'));

const dbState = {
  ready: false, indexOk: null,
  initAttempts: 0, lastInitAt: null, lastInitError: null, retryScheduledAt: null,
  stats: {
    insertsOk: 0, insertsNoop: 0, insertsFailed: 0,
    updatesOk: 0, updatesFailed: 0,
    touchesOk: 0, touchesFailed: 0,
    legacyFieldsStripped: 0,
    thumbnailForcedRefreshes: 0,
    lastSaveError: null, lastSaveErrorAt: null,
    lastUpdateError: null, lastUpdateErrorAt: null,
  },
};

// ═══════════════════════════════════════════════════════════════
//  UPSTREAM RATE LIMITER — global gate for every vidbolt call
// ═══════════════════════════════════════════════════════════════
let _lastUpstreamAt    = 0;
let _upstreamPausedUntil = 0;
let _consecutive429    = 0;

function parseRetryAfter(h) {
  if (!h) return 0;
  const n = Number(h);
  if (Number.isFinite(n) && n >= 0) return n * 1000;
  const d = new Date(h);
  if (!isNaN(d.getTime())) return Math.max(0, d.getTime() - Date.now());
  return 0;
}

function noteUpstreamSuccess() {
  if (_consecutive429 > 0) {
    log('ok', 'fetch', 'upstream healthy — 429 streak cleared', { was: _consecutive429 });
  }
  _consecutive429 = 0;
}

function noteUpstream429(retryAfterMs) {
  _consecutive429++;
  const exp = Math.min(_consecutive429 - 1, 5);
  const raw = Math.max(VIDBOLT_BACKOFF_BASE_MS, retryAfterMs || 0) * Math.pow(2, exp);
  const backoff = Math.min(VIDBOLT_BACKOFF_MAX_MS, raw);
  _upstreamPausedUntil = Math.max(_upstreamPausedUntil, Date.now() + backoff);
  log('warn', 'capture', '429 — pausing upstream', {
    consecutive: _consecutive429,
    backoffSec: Math.round(backoff / 1000),
    retryAfterMs: retryAfterMs || 0,
  });
}

function isUpstreamPaused() {
  return Date.now() < _upstreamPausedUntil;
}

// ═══════════════════════════════════════════════════════════════
//  PAYLOAD SANITIZER (whitelist-only)
// ═══════════════════════════════════════════════════════════════
const PAYLOAD_KEEP = ['available', 'type', 'server', 'thumbnails', 'resolvedAt',
                      'error', 'message', 'reason', 'tmdb', 'season', 'episode'];
const SOURCE_KEEP  = ['url', 'quality'];

function sanitizePayload(payload) {
  if (!payload || typeof payload !== 'object') return payload;
  let stripped = 0;
  const out = {};
  for (const k of PAYLOAD_KEEP) if (k in payload) out[k] = payload[k];
  for (const k of Object.keys(payload)) {
    if (k !== 'sources' && !PAYLOAD_KEEP.includes(k)) stripped++;
  }
  out.sources = [];
  if (Array.isArray(payload.sources)) {
    for (const s of payload.sources) {
      if (!s || typeof s !== 'object' || typeof s.url !== 'string' || !s.url) continue;
      const o = { url: s.url };
      if (typeof s.quality === 'string' && s.quality) o.quality = s.quality;
      for (const k of Object.keys(s)) if (!SOURCE_KEEP.includes(k)) stripped++;
      out.sources.push(o);
    }
  }
  if (stripped > 0) dbState.stats.legacyFieldsStripped += stripped;
  return out;
}

// ═══════════════════════════════════════════════════════════════
//  DB READ / WRITE
// ═══════════════════════════════════════════════════════════════
let _dbRetryTimer = null;
let _lastWarnedNotReady = 0;
function warnNotReady(where) {
  const now = Date.now();
  if (now - _lastWarnedNotReady > 60_000) {
    _lastWarnedNotReady = now;
    log('warn', 'db', `skipping ${where} — database not ready`, {
      reason: dbState.lastInitError || 'unknown',
    });
  }
}

async function getFromDb(mediaType, tmdb, season, episode) {
  if (!dbState.ready) { warnNotReady('getFromDb'); return null; }
  try {
    const { rows } = await pool.query(
      `SELECT payload, updated_at FROM stream_cache
       WHERE media_type = $1 AND tmdb = $2 AND season = $3 AND episode = $4
       LIMIT 1`,
      [mediaType, String(tmdb), Number(season), Number(episode)]
    );
    if (!rows.length) return null;
    log('debug', 'db', 'hit', { key: `${mediaType} ${tmdb}|${season}|${episode}` });
    return { payload: sanitizePayload(rows[0].payload), updatedAt: rows[0].updated_at };
  } catch (err) {
    log('error', 'db', 'query failed', { err: err.message });
    return null;
  }
}

async function saveToDb(mediaType, tmdb, season, episode, payload) {
  if (!dbState.ready) { warnNotReady('saveToDb'); return false; }
  const key = `${mediaType} ${tmdb}|${season}|${episode}`;
  try {
    const clean = sanitizePayload(payload);
    const { rowCount } = await pool.query(
      `INSERT INTO stream_cache (media_type, tmdb, season, episode, payload, updated_at)
       VALUES ($1, $2, $3, $4, $5::jsonb, NOW())
       ON CONFLICT (media_type, tmdb, season, episode) DO NOTHING`,
      [mediaType, String(tmdb), Number(season), Number(episode), JSON.stringify(clean)]
    );
    if (rowCount > 0) {
      dbState.stats.insertsOk++;
      log('ok', 'db', 'insert ok', { key });
      return 'inserted';
    }
    dbState.stats.insertsNoop++;
    log('debug', 'db', 'insert noop — row existed', { key });
    return 'existed';
  } catch (err) {
    dbState.stats.insertsFailed++;
    dbState.stats.lastSaveError = err.message;
    dbState.stats.lastSaveErrorAt = new Date();
    log('error', 'db', 'INSERT FAILED', { err: err.message, key });
    return false;
  }
}

async function updateDb(mediaType, tmdb, season, episode, payload) {
  if (!dbState.ready) { warnNotReady('updateDb'); return false; }
  const key = `${mediaType} ${tmdb}|${season}|${episode}`;
  try {
    const clean = sanitizePayload(payload);
    const { rowCount } = await pool.query(
      `UPDATE stream_cache
          SET payload = $5::jsonb, updated_at = NOW()
        WHERE media_type = $1 AND tmdb = $2 AND season = $3 AND episode = $4`,
      [mediaType, String(tmdb), Number(season), Number(episode), JSON.stringify(clean)]
    );
    if (rowCount > 0) {
      dbState.stats.updatesOk++;
      log('ok', 'db', 'row refreshed', { key });
      return true;
    }
    dbState.stats.updatesFailed++;
    log('warn', 'db', 'refresh target missing', { key });
    return false;
  } catch (err) {
    dbState.stats.updatesFailed++;
    dbState.stats.lastUpdateError = err.message;
    dbState.stats.lastUpdateErrorAt = new Date();
    log('error', 'db', 'update failed', { err: err.message, key });
    return false;
  }
}

async function touchDb(mediaType, tmdb, season, episode) {
  if (!dbState.ready) { warnNotReady('touchDb'); return false; }
  const key = `${mediaType} ${tmdb}|${season}|${episode}`;
  try {
    const { rowCount } = await pool.query(
      `UPDATE stream_cache SET updated_at = NOW()
        WHERE media_type = $1 AND tmdb = $2 AND season = $3 AND episode = $4`,
      [mediaType, String(tmdb), Number(season), Number(episode)]
    );
    if (rowCount > 0) { dbState.stats.touchesOk++; return true; }
    dbState.stats.touchesFailed++;
    return false;
  } catch (err) {
    dbState.stats.touchesFailed++;
    log('error', 'db', 'touch failed', { err: err.message, key });
    return false;
  }
}

// ═══════════════════════════════════════════════════════════════
//  DB INIT (self-healing)
// ═══════════════════════════════════════════════════════════════
function parseIndexColumns(def) {
  if (!def) return [];
  const m = def.match(/\(([^)]*)\)\s*$/);
  if (!m) return [];
  return m[1].split(',').map(s => s.trim().toLowerCase());
}

async function ensureUniqueIndex() {
  const expected = ['media_type', 'tmdb', 'season', 'episode'];
  const { rows } = await pool.query(`
    SELECT i.indisunique AS is_unique, pg_get_indexdef(i.indexrelid) AS def
    FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
    WHERE c.relname = 'stream_cache_unique'
  `);
  if (rows.length === 1) {
    const { is_unique, def } = rows[0];
    const cols = parseIndexColumns(def);
    const colsOk = cols.length === expected.length && expected.every(c => cols.includes(c));
    if (is_unique && colsOk) {
      dbState.indexOk = true;
      log('ok', 'db', 'unique index verified', { cols: cols.join(',') });
      return;
    }
  }
  await pool.query(`ALTER TABLE stream_cache DROP CONSTRAINT IF EXISTS stream_cache_unique`);
  await pool.query(`DROP INDEX IF EXISTS stream_cache_unique`);
  const dup = await pool.query(`
    SELECT count(*)::int AS c FROM (
      SELECT 1 FROM stream_cache
      GROUP BY media_type, tmdb, season, episode HAVING count(*) > 1
    ) x
  `);
  if (dup.rows[0].c > 0) {
    log('warn', 'db', 'duplicate rows — deduping', { groups: dup.rows[0].c });
    await pool.query(`
      DELETE FROM stream_cache a USING stream_cache b
      WHERE a.id < b.id
        AND a.media_type = b.media_type AND a.tmdb = b.tmdb
        AND a.season = b.season AND a.episode = b.episode
    `);
  }
  await pool.query(`CREATE UNIQUE INDEX stream_cache_unique
    ON stream_cache (media_type, tmdb, season, episode)`);
  dbState.indexOk = true;
  log('ok', 'db', 'unique index created');
}

async function initDb() {
  dbState.initAttempts++;
  dbState.lastInitAt = new Date();
  await pool.query(`
    CREATE TABLE IF NOT EXISTS stream_cache (
      id          SERIAL PRIMARY KEY,
      media_type  TEXT        NOT NULL DEFAULT 'tv',
      tmdb        TEXT        NOT NULL,
      season      INTEGER     NOT NULL,
      episode     INTEGER     NOT NULL,
      payload     JSONB       NOT NULL,
      created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  await pool.query(`ALTER TABLE stream_cache ADD COLUMN IF NOT EXISTS media_type TEXT NOT NULL DEFAULT 'tv'`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_stream_cache_lookup ON stream_cache (tmdb, season, episode)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_stream_cache_updated_at ON stream_cache (updated_at)`);
  await ensureUniqueIndex();
  dbState.ready = true;
  dbState.lastInitError = null;
  log('ok', 'db', 'database ready', { attempts: dbState.initAttempts, indexOk: dbState.indexOk });
}

async function ensureDb() {
  if (dbState.ready) return true;
  try { await initDb(); return true; }
  catch (err) {
    dbState.ready = false;
    dbState.lastInitError = err.message;
    log('error', 'db', 'init failed — retry in 30s', { err: err.message });
    if (!_dbRetryTimer) {
      dbState.retryScheduledAt = new Date(Date.now() + 30_000);
      _dbRetryTimer = setTimeout(() => {
        _dbRetryTimer = null;
        dbState.retryScheduledAt = null;
        ensureDb().catch(() => {});
      }, 30_000);
      _dbRetryTimer.unref?.();
    }
    return false;
  }
}

// ═══════════════════════════════════════════════════════════════
//  LRU CACHE
// ═══════════════════════════════════════════════════════════════
class LRUCache {
  constructor(maxSize) { this.max = maxSize; this.map = new Map(); }
  get(key) {
    const v = this.map.get(key);
    if (!v) return null;
    if (Date.now() > v.expires) { this.map.delete(key); return null; }
    this.map.delete(key); this.map.set(key, v); return v.data;
  }
  set(key, data, ttlMs) {
    if (this.map.has(key)) this.map.delete(key);
    this.map.set(key, { data, expires: Date.now() + ttlMs });
    if (this.map.size > this.max) this.map.delete(this.map.keys().next().value);
  }
  get size() { return this.map.size; }
}
const cache = new LRUCache(MEM_CACHE_MAX);
function memSet(key, payload, updatedAt, ttlMs) {
  cache.set(key, { payload: sanitizePayload(payload), updatedAt: updatedAt ? toDate(updatedAt) : null }, ttlMs);
}
function memGet(key) { return cache.get(key); }
function toDate(v) {
  if (!v) return null;
  if (v instanceof Date) return isNaN(v.getTime()) ? null : v;
  const d = new Date(v);
  return isNaN(d.getTime()) ? null : d;
}

// ═══════════════════════════════════════════════════════════════
//  SEMAPHORE + SINGLE-FLIGHT
// ═══════════════════════════════════════════════════════════════
class Semaphore {
  constructor(max, timeoutMs) {
    this.max = max; this.timeoutMs = timeoutMs;
    this.current = 0; this.queue = [];
  }
  _makeReleaser() {
    let done = false;
    return () => {
      if (done) return; done = true;
      this.current--;
      const next = this.queue.shift();
      if (next) { clearTimeout(next.timer); this.current++; next.resolve(this._makeReleaser()); }
    };
  }
  acquire() {
    if (this.current < this.max) { this.current++; return Promise.resolve(this._makeReleaser()); }
    return new Promise((resolve, reject) => {
      const entry = { resolve, reject, timer: null };
      entry.timer = setTimeout(() => {
        const i = this.queue.indexOf(entry);
        if (i >= 0) this.queue.splice(i, 1);
        reject(new Error('queue_timeout'));
      }, this.timeoutMs);
      this.queue.push(entry);
    });
  }
  stats() { return { current: this.current, queued: this.queue.length, max: this.max }; }
}
const captureSem = new Semaphore(CAPTURE_CONCURRENCY, EFFECTIVE_QUEUE_TIMEOUT);

const inflight = new Map();
function singleFlight(key, fn) {
  const existing = inflight.get(key);
  if (existing) { log('debug', 'cache', 'single-flight join', { key }); return existing; }
  const p = (async () => fn())().finally(() => inflight.delete(key));
  inflight.set(key, p);
  return p;
}

// ═══════════════════════════════════════════════════════════════
//  VIDBOLT.ST FETCHER
// ═══════════════════════════════════════════════════════════════
function buildVidboltReferer(mediaType, tmdb, s, e) {
  return mediaType === 'tv'
    ? `${VIDBOLT_BASE}/tv/${tmdb}/${s}/${e}?theme=E50914&autoPlay=true`
    : `${VIDBOLT_BASE}/movie/${tmdb}?theme=E50914&autoPlay=true`;
}

async function fetchFromVidbolt(mediaType, tmdb, s, e, budgetMs) {
  const startedAt = Date.now();
  const deadline = startedAt + (budgetMs || VIDBOLT_TIMEOUT);

  if (isUpstreamPaused()) {
    return { available: false, reason: 'upstream_backoff', pausedUntil: _upstreamPausedUntil };
  }

  const sinceLast = Date.now() - _lastUpstreamAt;
  if (sinceLast < VIDBOLT_MIN_INTERVAL_MS) {
    const wait = VIDBOLT_MIN_INTERVAL_MS - sinceLast;
    if (Date.now() + wait >= deadline) {
      return { available: false, reason: 'capture_timeout' };
    }
    log('debug', 'capture', 'throttle wait', { waitMs: wait });
    await new Promise(r => setTimeout(r, wait));
    if (isUpstreamPaused()) {
      return { available: false, reason: 'upstream_backoff', pausedUntil: _upstreamPausedUntil };
    }
  }

  _lastUpstreamAt = Date.now();
  const remaining = Math.max(1, deadline - Date.now());
  const httpTimeout = Math.max(1, Math.min(VIDBOLT_TIMEOUT, remaining));
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), httpTimeout);

  try {
    const u = new URL(`${VIDBOLT_BASE}/api/resolve`);
    u.searchParams.set('type', mediaType);
    u.searchParams.set('id', String(tmdb));
    if (mediaType === 'tv') {
      u.searchParams.set('season', String(Number(s)));
      u.searchParams.set('episode', String(Number(e)));
    }
    u.searchParams.set('hevc', VIDBOLT_HEVC);

    log('debug', 'fetch', 'vidbolt GET', { url: u.toString(), timeout: httpTimeout, hevc: VIDBOLT_HEVC });

    const res = await fetch(u, {
      headers: {
        accept: '*/*',
        'accept-language': 'en-US,en;q=0.9',
        'accept-encoding': 'gzip, deflate, br',
        referer: buildVidboltReferer(mediaType, tmdb, s, e),
        'user-agent': VIDBOLT_UA,
        'sec-ch-ua': VIDBOLT_SEC_CH_UA,
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
      },
      redirect: 'follow',
      signal: ctrl.signal,
    });

    const text = await res.text();

    if (res.status === 429) {
      const ra = parseRetryAfter(res.headers.get('retry-after'));
      noteUpstream429(ra);
      return { available: false, reason: 'http_429', status: 429, retryAfterMs: ra };
    }
    if (!res.ok) {
      log('warn', 'fetch', 'non-200', { status: res.status, body: text.slice(0, 120) });
      return { available: false, reason: `http_${res.status}`, status: res.status };
    }

    noteUpstreamSuccess();

    let json;
    try { json = JSON.parse(text); }
    catch { return { available: false, reason: 'bad_json' }; }

    const payload = normalizeVidbolt(json);
    if (!payload) return { available: false, reason: 'no_source' };

    const took = Date.now() - startedAt;
    log('ok', 'fetch', 'hit', {
      server: payload.server,
      sources: payload.sources.length,
      thumbnails: !!payload.thumbnails,
      took: `${took}ms`,
    });
    return { available: true, data: payload, from: u.toString() };

  } catch (err) {
    log('warn', 'fetch', 'error', { err: err.message });
    return { available: false, reason: err.message };
  } finally {
    clearTimeout(timer);
  }
}

// Whittle to { server, sources:[{url,quality}], thumbnails, resolvedAt }
// NOTE: `thumbnails` is kept as the ORIGINAL upstream URL in storage.
//       It is rewritten to a signed proxy URL only at response-build time.
function normalizeVidbolt(json) {
  if (!json || typeof json !== 'object') return null;
  const stream = json.stream || json;
  if (!stream || !Array.isArray(stream.sources) || !stream.sources.length) return null;
  const ok = stream.sources.filter(s => s && typeof s.url === 'string' && s.url.length > 0);
  if (!ok.length) return null;
  const server = stream.server || (typeof json.server === 'string' ? json.server : 'vidbolt');
  const thumbnails =
    (typeof stream.thumbnails === 'string' && stream.thumbnails) ||
    (typeof json.thumbnails === 'string' && json.thumbnails) || null;
  const sources = ok.map(s => {
    const o = { url: s.url };
    if (typeof s.quality === 'string' && s.quality) o.quality = s.quality;
    return o;
  });
  return { server, sources, thumbnails, resolvedAt: Number(stream.resolvedAt) || Date.now() };
}

function buildUpstreamPayload(mediaType, cap) {
  return sanitizePayload({
    available: true,
    type: mediaType,
    server: cap.data.server,
    sources: cap.data.sources,
    thumbnails: cap.data.thumbnails,
    resolvedAt: cap.data.resolvedAt,
  });
}

function sourceUrls(payload) {
  if (!payload || !Array.isArray(payload.sources)) return [];
  return payload.sources.filter(s => s && typeof s.url === 'string').map(s => s.url).sort();
}
function thumbOf(payload) {
  return (payload && typeof payload.thumbnails === 'string' && payload.thumbnails) ? payload.thumbnails : null;
}
function payloadsEquivalent(oldP, freshP) {
  const ua = sourceUrls(oldP), ub = sourceUrls(freshP);
  if (ua.length === 0 || ub.length === 0 || ua.length !== ub.length) return false;
  for (let i = 0; i < ua.length; i++) if (ua[i] !== ub[i]) return false;
  return thumbOf(oldP) === thumbOf(freshP);
}

function fetchFreshUpstream(mediaType, tmdb, s, e) {
  const flightKey = `fetch|${mediaType}|${tmdb}|${s}|${e}`;
  return singleFlight(flightKey, async () => {
    if (isUpstreamPaused()) {
      return { available: false, reason: 'upstream_backoff', pausedUntil: _upstreamPausedUntil };
    }
    const deadline = Date.now() + CAPTURE_TIMEOUT;
    const release = await captureSem.acquire();
    try {
      const remaining = deadline - Date.now();
      if (remaining <= 0) return { available: false, reason: 'capture_timeout' };
      return await fetchFromVidbolt(mediaType, tmdb, s, e, remaining);
    } finally {
      release();
    }
  });
}

// ═══════════════════════════════════════════════════════════════
//  RESOLVE
// ═══════════════════════════════════════════════════════════════
async function resolveStream(mediaType, tmdb, s, e, key) {
  const mem = memGet(key);
  if (mem) {
    return {
      payload: mem.payload, servedFrom: 'memory', outcome: 'memory_hit',
      negative: mem.payload.available === false,
      updated: false, matched: false, stale: false, verified: false,
      updatedAt: mem.updatedAt,
    };
  }

  const dbHit = await getFromDb(mediaType, tmdb, s, e);
  if (dbHit) {
    const updatedAt = toDate(dbHit.updatedAt);
    const ageMs = updatedAt ? Date.now() - updatedAt.getTime() : Infinity;
    const baseStale = !updatedAt || ageMs >= REFRESH_INTERVAL_MS;
    const hasSources = Array.isArray(dbHit.payload.sources) && dbHit.payload.sources.length > 0;
    const missingThumbs = hasSources && !dbHit.payload.thumbnails;
    const thumbsExpired = missingThumbs && ageMs > THUMBNAIL_RETRY_MS;
    const isStale = baseStale || thumbsExpired;

    if (!isStale) {
      log('ok', 'cache', 'db hit (fresh)', { key, ageH: (ageMs / 3_600_000).toFixed(2) });
      memSet(key, dbHit.payload, updatedAt, CACHE_TTL);
      return {
        payload: dbHit.payload, servedFrom: 'database', outcome: 'db_fresh_hit',
        negative: dbHit.payload.available === false,
        updated: false, matched: false, stale: false, verified: false,
        updatedAt,
      };
    }

    if (baseStale) log('info', 'cache', 'db hit (STALE) — refreshing', { key, ageH: (ageMs / 3_600_000).toFixed(2) });
    else {
      dbState.stats.thumbnailForcedRefreshes++;
      log('info', 'cache', 'db hit (missing thumbnails) — refreshing', { key, ageMin: Math.round(ageMs / 60_000) });
    }

    const cap = await fetchFreshUpstream(mediaType, tmdb, s, e);
    const usable = cap.available && cap.data && Array.isArray(cap.data.sources) && cap.data.sources.length > 0;

    if (usable) {
      const freshPayload = buildUpstreamPayload(mediaType, cap);
      if (payloadsEquivalent(dbHit.payload, freshPayload)) {
        const touched = await touchDb(mediaType, tmdb, s, e);
        if (touched) {
          const now = new Date();
          memSet(key, dbHit.payload, now, CACHE_TTL);
          log('ok', 'refresh', 'sources+thumbnails unchanged — kept as-is', { key });
          return {
            payload: dbHit.payload, servedFrom: 'database', outcome: 'upstream_matched_kept',
            negative: dbHit.payload.available === false,
            updated: false, matched: true, stale: false, verified: true,
            updatedAt: now,
          };
        }
      }
      const ok = await updateDb(mediaType, tmdb, s, e, freshPayload);
      if (ok) {
        const now = new Date();
        memSet(key, freshPayload, now, CACHE_TTL);
        log('ok', 'refresh', 'stale row refreshed on-demand', { key, thumbnails: !!freshPayload.thumbnails });
        return {
          payload: freshPayload, servedFrom: 'refresh', outcome: 'upstream_updated',
          negative: false, updated: true, matched: false, stale: false, verified: false,
          updatedAt: now,
        };
      }
    }

    log('warn', 'refresh', 'refresh failed — serving stale', { key, reason: cap.reason || 'db_update_failed' });
    memSet(key, dbHit.payload, updatedAt, REFRESH_RETRY_TTL);
    return {
      payload: dbHit.payload, servedFrom: 'database-stale', outcome: 'upstream_failed_served_stale',
      negative: dbHit.payload.available === false,
      updated: false, matched: false, stale: true, verified: false,
      updatedAt,
    };
  }

  log('info', 'cache', 'miss — fetching from vidbolt.st', { key });
  const cap = await fetchFreshUpstream(mediaType, tmdb, s, e);

  if (!cap.available) {
    const body = sanitizePayload({
      available: false, error: 'Not available',
      message: 'This movie / episode is not available on this server.',
      reason: cap.reason, type: mediaType, tmdb, season: s, episode: e, sources: [],
    });
    const now = new Date();
    memSet(key, body, now, NEGATIVE_CACHE_TTL);
    return {
      payload: body, servedFrom: 'fetch', outcome: 'upstream_negative',
      negative: true, updated: false, matched: false, stale: false, verified: false,
      updatedAt: now,
    };
  }

  const payload = buildUpstreamPayload(mediaType, cap);
  const now = new Date();
  const saved = await saveToDb(mediaType, tmdb, s, e, payload);

  if (saved === 'inserted') {
    memSet(key, payload, now, CACHE_TTL);
    return {
      payload, servedFrom: 'fetch', outcome: 'upstream_new',
      negative: false, updated: true, matched: false, stale: false, verified: false,
      updatedAt: now,
    };
  }
  if (saved === 'existed') {
    const existing = await getFromDb(mediaType, tmdb, s, e);
    if (existing) {
      const updatedAt = toDate(existing.updatedAt);
      memSet(key, existing.payload, updatedAt, CACHE_TTL);
      log('info', 'cache', 'race — served existing DB row', { key });
      return {
        payload: existing.payload, servedFrom: 'database', outcome: 'race_existed_served_db',
        negative: existing.payload.available === false,
        updated: false, matched: false, stale: false, verified: false,
        updatedAt,
      };
    }
  }
  memSet(key, payload, now, 5_000);
  return {
    payload, servedFrom: 'fetch', outcome: 'upstream_new_unsaved',
    negative: false, updated: true, matched: false, stale: false, verified: false,
    updatedAt: now,
  };
}

// ═══════════════════════════════════════════════════════════════
//  META / RESPONSE
// ═══════════════════════════════════════════════════════════════
function mapCached(servedFrom) {
  if (servedFrom === 'memory') return 'memory';
  if (servedFrom === 'database' || servedFrom === 'database-stale') return 'database';
  return false;
}
function buildMeta(result) {
  const updatedAt = toDate(result.updatedAt);
  const ageSeconds = updatedAt ? Math.max(0, Math.round((Date.now() - updatedAt.getTime()) / 1000)) : null;
  const resolvedAtMs = result.payload && Number(result.payload.resolvedAt);
  const sourceCount = Array.isArray(result.payload && result.payload.sources) ? result.payload.sources.length : 0;
  return {
    servedFrom: result.servedFrom || 'unknown',
    outcome: result.outcome || null,
    updated: !!result.updated,
    matched: !!result.matched,
    stale: !!result.stale,
    verified: !!result.verified,
    server: (result.payload && result.payload.server) || null,
    sourceCount,
    hasThumbnails: !!(result.payload && result.payload.thumbnails),
    resolvedAt: resolvedAtMs ? new Date(resolvedAtMs).toISOString() : null,
    updatedAt: updatedAt ? updatedAt.toISOString() : null,
    ageSeconds,
    staleAfterHours: +(REFRESH_INTERVAL_MS / 3_600_000).toFixed(2),
  };
}

// Rewrites the upstream `thumbnails` URL to a signed proxy URL for the client,
// while DB/cache continue to hold the original upstream URL.
function buildResponse(result, req) {
  const clean = sanitizePayload(result.payload);
  if (typeof clean.thumbnails === 'string' && clean.thumbnails) {
    clean.thumbnails = buildThumbProxyUrl(clean.thumbnails, req);
  }
  return {
    ...clean,
    _cached: mapCached(result.servedFrom),
    _meta: buildMeta({ ...result, payload: clean }),
  };
}

// ═══════════════════════════════════════════════════════════════
//  BACKGROUND SWEEP
// ═══════════════════════════════════════════════════════════════
const refreshState = {
  running: false,
  lastStartedAt: null, lastFinishedAt: null,
  lastTotal: 0, lastUpdated: 0, lastKept: 0, lastFailed: 0,
  lastError: null,
  lastAbortedReason: null,
  lastRetryScheduledAt: null,
};

let refreshTimer = null;
let refreshBootTimer = null;
let refreshRetryTimer = null;

function scheduleRefreshRetry(delayMs) {
  if (refreshRetryTimer) clearTimeout(refreshRetryTimer);
  refreshState.lastRetryScheduledAt = new Date(Date.now() + delayMs);
  refreshRetryTimer = setTimeout(() => {
    refreshRetryTimer = null;
    refreshState.lastRetryScheduledAt = null;
    log('info', 'refresh', 'auto-retry starting', {});
    runRefreshCycle().catch(() => {});
  }, delayMs);
  refreshRetryTimer.unref?.();
  log('info', 'refresh', 'cycle auto-retry scheduled', { inSec: Math.round(delayMs / 1000) });
}

async function refreshOne(row) {
  const mediaType = row.media_type;
  const tmdb = row.tmdb;
  const season = Number(row.season);
  const episode = Number(row.episode);
  const key = `${mediaType}|${tmdb}|${season}|${episode}`;
  const oldPayload = sanitizePayload(row.payload);

  if (isUpstreamPaused()) return 'paused';

  let cap;
  try { cap = await fetchFreshUpstream(mediaType, tmdb, season, episode); }
  catch (err) {
    log('warn', 'refresh', 'fetch error — keeping old links', { key, err: err.message });
    return false;
  }

  if (!cap.available) {
    if (cap.reason === 'upstream_backoff') return 'paused';
    if (cap.reason === 'http_429') return 'paused';
    log('warn', 'refresh', 'upstream unavailable — keeping old links', { key, reason: cap.reason });
    return false;
  }

  const payload = buildUpstreamPayload(mediaType, cap);
  if (!Array.isArray(payload.sources) || payload.sources.length === 0) {
    log('warn', 'refresh', 'upstream returned 0 sources — keeping old links', { key });
    return false;
  }

  if (payloadsEquivalent(oldPayload, payload)) {
    const ok = await touchDb(mediaType, tmdb, season, episode);
    if (ok) {
      memSet(key, oldPayload, new Date(), CACHE_TTL);
      log('ok', 'refresh', 'sources+thumbnails unchanged — kept as-is', { key });
    }
    return ok ? 'kept' : false;
  }

  const ok = await updateDb(mediaType, tmdb, season, episode, payload);
  if (ok) {
    memSet(key, payload, new Date(), CACHE_TTL);
    log('ok', 'refresh', 'links updated', {
      key, sources: payload.sources.length, server: payload.server, thumbnails: !!payload.thumbnails,
    });
    return 'updated';
  }
  return false;
}

async function runRefreshCycle() {
  if (!dbState.ready) { log('warn', 'refresh', 'skipped — database not ready'); return; }
  if (refreshState.running) { log('warn', 'refresh', 'cycle already running'); return; }

  refreshState.running = true;
  refreshState.lastStartedAt = new Date();
  refreshState.lastTotal = 0;
  refreshState.lastUpdated = 0;
  refreshState.lastKept = 0;
  refreshState.lastFailed = 0;
  refreshState.lastError = null;
  refreshState.lastAbortedReason = null;

  const cutoff = new Date(Date.now() - REFRESH_INTERVAL_MS);
  const t0 = Date.now();
  let lastId = 0;
  let abortedByBackoff = false;

  log('info', 'refresh', 'cycle start', {
    olderThan: cutoff.toISOString(),
    concurrency: REFRESH_CONCURRENCY,
    interDelayMs: REFRESH_INTER_REQUEST_DELAY_MS,
    minIntervalMs: VIDBOLT_MIN_INTERVAL_MS,
  });

  try {
    outer: while (true) {
      if (isUpstreamPaused()) {
        abortedByBackoff = true;
        log('warn', 'refresh', 'upstream paused — stopping cycle', {
          resumeInSec: Math.ceil((_upstreamPausedUntil - Date.now()) / 1000),
        });
        break;
      }

      const { rows } = await pool.query(
        `SELECT id, media_type, tmdb, season, episode, payload
           FROM stream_cache
          WHERE updated_at < $1 AND id > $2
          ORDER BY id LIMIT $3`,
        [cutoff, lastId, REFRESH_BATCH]
      );
      if (!rows.length) break;

      lastId = rows[rows.length - 1].id;
      refreshState.lastTotal += rows.length;

      const chunks = [];
      const chunkSize = Math.max(1, REFRESH_CONCURRENCY);
      for (let i = 0; i < rows.length; i += chunkSize) chunks.push(rows.slice(i, i + chunkSize));

      for (const chunk of chunks) {
        if (isUpstreamPaused()) {
          abortedByBackoff = true;
          log('warn', 'refresh', 'upstream paused mid-cycle — stopping', {
            resumeInSec: Math.ceil((_upstreamPausedUntil - Date.now()) / 1000),
          });
          break outer;
        }
        await Promise.all(chunk.map(async (row) => {
          const status = await refreshOne(row);
          if (status === 'updated') refreshState.lastUpdated++;
          else if (status === 'kept') refreshState.lastKept++;
          else if (status === 'paused') { /* skip — aborted flag will trigger */ }
          else refreshState.lastFailed++;
        }));
        if (REFRESH_INTER_REQUEST_DELAY_MS > 0 && chunks.length > 1) {
          await new Promise(r => setTimeout(r, REFRESH_INTER_REQUEST_DELAY_MS));
        }
        if (isUpstreamPaused()) {
          abortedByBackoff = true;
          log('warn', 'refresh', 'upstream paused — stopping cycle', {
            resumeInSec: Math.ceil((_upstreamPausedUntil - Date.now()) / 1000),
          });
          break outer;
        }
      }
    }

    const dur = ((Date.now() - t0) / 1000).toFixed(1);
    if (abortedByBackoff) {
      refreshState.lastAbortedReason = 'upstream_backoff';
      log('warn', 'refresh', 'cycle aborted (429 backoff)', {
        total: refreshState.lastTotal,
        updated: refreshState.lastUpdated,
        kept: refreshState.lastKept,
        failed: refreshState.lastFailed,
        took: `${dur}s`,
      });
    } else {
      log('ok', 'refresh', 'cycle complete', {
        total: refreshState.lastTotal,
        updated: refreshState.lastUpdated,
        kept: refreshState.lastKept,
        failed: refreshState.lastFailed,
        took: `${dur}s`,
      });
    }
  } catch (err) {
    refreshState.lastError = err.message;
    log('error', 'refresh', 'cycle failed', { err: err.message });
  } finally {
    refreshState.running = false;
    refreshState.lastFinishedAt = new Date();
  }

  if (abortedByBackoff) {
    const wait = Math.max(60_000, _upstreamPausedUntil - Date.now() + 30_000);
    scheduleRefreshRetry(wait);
  }
}

function startRefreshScheduler() {
  if (!REFRESH_ENABLED) {
    log('info', 'refresh', 'background sweep disabled (REFRESH_ENABLED=false)');
    return;
  }
  refreshBootTimer = setTimeout(() => runRefreshCycle().catch(() => {}), REFRESH_BOOT_DELAY);
  refreshTimer = setInterval(() => runRefreshCycle().catch(() => {}), REFRESH_INTERVAL_MS);
  refreshBootTimer.unref?.(); refreshTimer.unref?.();

  log('info', 'refresh', 'background sweep armed', {
    every: `${(REFRESH_INTERVAL_MS / 3_600_000).toFixed(1)}h`,
    bootDelay: `${(REFRESH_BOOT_DELAY / 1000).toFixed(0)}s`,
    concurrency: REFRESH_CONCURRENCY,
    interDelayMs: REFRESH_INTER_REQUEST_DELAY_MS,
    minIntervalMs: VIDBOLT_MIN_INTERVAL_MS,
    batch: REFRESH_BATCH,
  });
}

function stopRefreshScheduler() {
  if (refreshBootTimer) clearTimeout(refreshBootTimer);
  if (refreshTimer) clearInterval(refreshTimer);
  if (refreshRetryTimer) clearTimeout(refreshRetryTimer);
  refreshBootTimer = refreshTimer = refreshRetryTimer = null;
}

// ═══════════════════════════════════════════════════════════════
//  ROUTES
// ═══════════════════════════════════════════════════════════════
async function streamHandler(req, res) {
  const tmdb = req.query.tmdb || req.query.id;
  const rawType = String(req.query.type || '').toLowerCase();
  const mediaType =
    rawType === 'movie' ? 'movie'
    : rawType === 'tv' ? 'tv'
    : req.path.startsWith('/api/movie') ? 'movie'
    : 'tv';

  if (!tmdb) return res.status(400).json({ error: 'Missing tmdb (or id)' });

  const isMovie = mediaType === 'movie';
  const s = isMovie ? 0 : Number(req.query.s ?? 1);
  const e = isMovie ? 0 : Number(req.query.e ?? 1);
  const key = `${mediaType}|${tmdb}|${s}|${e}`;

  try {
    const result = await singleFlight(key, () => resolveStream(mediaType, tmdb, s, e, key));
    const meta = buildMeta(result);
    res.setHeader('x-cache-source', result.servedFrom);
    res.setHeader('x-data-outcome', result.outcome || '');
    res.setHeader('x-data-stale', meta.stale ? '1' : '0');
    res.setHeader('x-data-verified', meta.verified ? '1' : '0');
    res.setHeader('x-data-updated', meta.updated ? '1' : '0');
    res.setHeader('x-data-matched', meta.matched ? '1' : '0');
    if (meta.updatedAt) res.setHeader('x-data-updated-at', meta.updatedAt);

    // ← pass req so thumbnails get rewritten to signed proxy URLs
    const body = buildResponse(result, req);
    if (result.negative) return res.status(404).json(body);
    return res.json(body);

  } catch (err) {
    if (err.message === 'queue_timeout') {
      res.set('Retry-After', '5');
      log('warn', 'queue', 'full — rejecting', { key, ...captureSem.stats() });
      return res.status(503).json({
        available: false, error: 'Server busy', reason: 'queue_timeout', retryAfter: 5,
      });
    }
    log('error', 'proxy', 'stream error', { err: err.message, key });
    return res.status(502).json({ available: false, error: 'Fetch failed', message: err.message });
  }
}

app.get('/api/stream', streamHandler);
app.get('/api/movie', streamHandler);

app.post('/api/admin/refresh', async (req, res) => {
  if (!ADMIN_TOKEN) return res.status(404).json({ error: 'Not found' });
  const token = req.get('x-admin-token') || req.query.token;
  if (token !== ADMIN_TOKEN) return res.status(401).json({ error: 'Unauthorized' });
  if (refreshState.running) return res.status(409).json({ ok: false, reason: 'already_running', state: refreshState });
  runRefreshCycle().catch(() => {});
  return res.status(202).json({ ok: true, started: true });
});

app.get('/api/admin/db-status', async (req, res) => {
  if (!ADMIN_TOKEN) return res.status(404).json({ error: 'Not found' });
  const token = req.get('x-admin-token') || req.query.token;
  if (token !== ADMIN_TOKEN) return res.status(401).json({ error: 'Unauthorized' });
  const out = { ok: true, state: { ...dbState, stats: { ...dbState.stats } } };
  try {
    const idx = await pool.query(`
      SELECT pg_get_indexdef(i.indexrelid) AS def, i.indisunique AS is_unique
      FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
      WHERE c.relname = 'stream_cache_unique'
    `);
    out.index = idx.rows[0] || null;
    const cnt = await pool.query(`SELECT count(*)::int AS c FROM stream_cache`);
    out.rowCount = cnt.rows[0].c;
    const age = await pool.query(`
      SELECT
        count(*) FILTER (WHERE created_at > now() - interval '1 hour')::int AS inserted_last_hour,
        count(*) FILTER (WHERE created_at > now() - interval '1 day')::int  AS inserted_last_day,
        count(*) FILTER (WHERE updated_at > now() - interval '1 hour')::int AS updated_last_hour,
        count(*) FILTER (WHERE updated_at > now() - interval '1 day')::int  AS updated_last_day,
        max(created_at) AS latest_insert, max(updated_at) AS latest_update
      FROM stream_cache
    `);
    out.traffic = age.rows[0];
  } catch (err) { out.error = err.message; }
  return res.json(out);
});

app.get('/health', async (_req, res) => {
  let dbOk = false;
  try { if (dbState.ready) { await pool.query('SELECT 1'); dbOk = true; } } catch {}

  res.json({
    ok: true,
    uptime: Math.round(process.uptime()),
    vidboltBase: VIDBOLT_BASE,
    vidboltHevc: VIDBOLT_HEVC,
    memoryCache: cache.size,
    memoryCacheMax: MEM_CACHE_MAX,
    capture: captureSem.stats(),
    inflight: inflight.size,
    rateLimit: {
      minIntervalMs: VIDBOLT_MIN_INTERVAL_MS,
      paused: isUpstreamPaused(),
      pausedUntil: isUpstreamPaused() ? new Date(_upstreamPausedUntil).toISOString() : null,
      pauseRemainingSec: isUpstreamPaused() ? Math.ceil((_upstreamPausedUntil - Date.now()) / 1000) : 0,
      consecutive429: _consecutive429,
      backoffBaseMs: VIDBOLT_BACKOFF_BASE_MS,
      backoffMaxMs: VIDBOLT_BACKOFF_MAX_MS,
    },
    db: {
      ready: dbState.ready, reachable: dbOk, indexOk: dbState.indexOk,
      initAttempts: dbState.initAttempts, lastInitAt: dbState.lastInitAt,
      lastInitError: dbState.lastInitError, retryScheduledAt: dbState.retryScheduledAt,
      stats: dbState.stats,
    },
    thumbnails: {
      proxyBase: PROXY_PUBLIC_BASE || '(derived from request)',
      signing:  'hmac-sha256',
      rateLimitPerMin: THUMB_RATE_LIMIT_MAX,
      upstreamTimeoutMs: THUMB_PROXY_TIMEOUT,
      rewritesVtt: true,
    },
    mem: process.memoryUsage().rss,
    storage: {
      payloadFields: PAYLOAD_KEEP,
      sourceFields: SOURCE_KEEP,
      persistsMaster: false,
      persistsThumbnails: true,
      stripsLegacyOnRead: true,
      thumbnailRetryMinutes: Math.round(THUMBNAIL_RETRY_MS / 60_000),
    },
    freshness: {
      refreshIntervalHours: +(REFRESH_INTERVAL_MS / 3_600_000).toFixed(2),
      onDemand: true,
      retryTtlSeconds: Math.round(REFRESH_RETRY_TTL / 1000),
      keepAsIsOnMatch: 'urls+thumbnails',
      interRequestDelayMs: REFRESH_INTER_REQUEST_DELAY_MS,
      refreshConcurrency: REFRESH_CONCURRENCY,
    },
    backgroundSweep: {
      enabled: REFRESH_ENABLED,
      running: refreshState.running,
      lastStartedAt: refreshState.lastStartedAt,
      lastFinishedAt: refreshState.lastFinishedAt,
      lastTotal: refreshState.lastTotal,
      lastUpdated: refreshState.lastUpdated,
      lastKept: refreshState.lastKept,
      lastFailed: refreshState.lastFailed,
      lastError: refreshState.lastError,
      lastAbortedReason: refreshState.lastAbortedReason,
      lastRetryScheduledAt: refreshState.lastRetryScheduledAt,
    },
  });
});

// ═══════════════════════════════════════════════════════════════
//  BOOT + SHUTDOWN
// ═══════════════════════════════════════════════════════════════
let shuttingDown = false;

(async () => {
  banner();
  await ensureDb();

  const server = app.listen(PORT, () => {
    log('ok', 'server', `listening on ${C.bold}http://localhost:${PORT}${C.reset}`);
    log('info', 'server', 'config', {
      concurrency: CAPTURE_CONCURRENCY,
      queueTimeout: `${EFFECTIVE_QUEUE_TIMEOUT / 1000}s`,
      captureTimeout: `${CAPTURE_TIMEOUT / 1000}s`,
      vidboltTimeout: `${VIDBOLT_TIMEOUT / 1000}s`,
      vidboltMinInterval: `${VIDBOLT_MIN_INTERVAL_MS}ms`,
      backoffBase: `${VIDBOLT_BACKOFF_BASE_MS / 1000}s`,
      backoffMax: `${VIDBOLT_BACKOFF_MAX_MS / 1000}s`,
      memCache: MEM_CACHE_MAX,
      dbPool: DB_POOL_MAX,
      logLevel: LOG_LEVEL,
      vidboltBase: VIDBOLT_BASE,
      vidboltHevc: VIDBOLT_HEVC,
      refreshEvery: `${(REFRESH_INTERVAL_MS / 3_600_000).toFixed(1)}h`,
      refreshConcurrency: REFRESH_CONCURRENCY,
      refreshInterDelayMs: REFRESH_INTER_REQUEST_DELAY_MS,
      onDemandRefresh: true,
      keepAsIsOnMatch: 'urls+thumbnails',
      persistsMaster: false,
      dbReady: dbState.ready,
      dbIndexOk: dbState.indexOk,
      thumbProxyBase: PROXY_PUBLIC_BASE || '(derived from request)',
      thumbSigning: 'hmac-sha256',
    });
    log('info', 'server', 'cors allow-list', { hosts: [...ALLOWED_HOSTS].join(', ') });

    if (!dbState.ready) {
      log('error', 'db',
        '⚠️  RUNNING WITHOUT DATABASE — new rows will NOT be saved until init succeeds',
        { err: dbState.lastInitError });
    }

    startRefreshScheduler();
    log('ready', 'proxy', 'ready — waiting for requests');
    process.stdout.write('\n');
  });

  server.keepAliveTimeout = 65_000;
  server.headersTimeout = 66_000;
  server.requestTimeout = 120_000;

  async function shutdown(sig) {
    if (shuttingDown) return;
    shuttingDown = true;
    stopRefreshScheduler();
    divider(`shutting down (${sig})`);
    log('info', 'shutdown', 'closing HTTP server');
    server.close(() => log('ok', 'shutdown', 'HTTP closed'));
    const force = setTimeout(() => { log('warn', 'shutdown', 'forcing exit after 10s'); process.exit(1); }, 10_000);
    force.unref();
    try { await pool.end(); log('ok', 'shutdown', 'db pool drained'); } catch {}
    clearTimeout(force);
    log('ok', 'shutdown', 'done');
    process.exit(0);
  }

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('unhandledRejection', e => log('error', 'proxy', 'unhandledRejection', { err: String(e) }));
  process.on('uncaughtException', e => log('error', 'proxy', 'uncaughtException', { err: String(e) }));
})();
