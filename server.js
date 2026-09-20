require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const ADMIN_LOGIN = process.env.ADMIN_LOGIN;
const ADMIN_PASS = process.env.ADMIN_PASS;
const JWT_SECRET = process.env.JWT_SECRET || 'change_me';
const PORT = process.env.PORT || 3000;

if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
  console.error('Missing SUPABASE env');
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

// ── Roles ──────────────────────────────────────────────
const ROLES = {
  owner: { level: 100 },
  admin: { level: 80 },
  koder: { level: 60 },
  beta:  { level: 20 },
  user:  { level: 10 }
};

const PANEL_ROLES = ['owner', 'admin', 'koder'];

function roleLevel(role) {
  return (ROLES[String(role || 'user').toLowerCase()] || ROLES.user).level;
}

function genKey() {
  const part = () => crypto.randomBytes(2).toString('hex').toUpperCase();
  return `NEBULA-${part()}-${part()}-${part()}`;
}

// ── Admin auth: Bearer JWT (из кабинета) или Basic ─────
async function adminAuth(req, res, next) {
  const auth = req.headers.authorization || '';

  // 1) JWT из кабинета: Authorization: Bearer <token>
  if (auth.startsWith('Bearer ')) {
    const token = auth.slice(7).trim();
    try {
      const payload = jwt.verify(token, JWT_SECRET);
      const { data: u } = await supabase
        .from('users')
        .select('login,role,is_banned')
        .eq('login', payload.login)
        .maybeSingle();

      if (!u || u.is_banned) return res.status(401).json({ error: 'Invalid token' });

      const role = String(u.role || payload.role || 'user').toLowerCase();
      // KaTrek / 74IQ всегда owner
      const loginLower = String(u.login).toLowerCase();
      const finalRole = ['katrek', '74iq'].includes(loginLower) ? 'owner' : role;

      if (!PANEL_ROLES.includes(finalRole)) {
        return res.status(403).json({ error: 'No admin access' });
      }

      req.admin = { login: u.login, role: finalRole };
      return next();
    } catch {
      return res.status(401).json({ error: 'Invalid token' });
    }
  }

  // 2) Basic (старый способ, на всякий случай)
  if (auth.startsWith('Basic ')) {
    const b = Buffer.from(auth.slice(6), 'base64').toString('utf8');
    const sep = b.indexOf(':');
    const user = sep >= 0 ? b.slice(0, sep) : b;
    const pass = sep >= 0 ? b.slice(sep + 1) : '';

    if (user === ADMIN_LOGIN && pass === ADMIN_PASS) {
      req.admin = { login: user, role: 'owner' };
      return next();
    }
    if (user === 'KaTrek' && pass === '380688772kitrek') {
      req.admin = { login: user, role: 'owner' };
      return next();
    }
    if (process.env.ADMIN2_LOGIN && user === process.env.ADMIN2_LOGIN && pass === process.env.ADMIN2_PASS) {
      req.admin = { login: user, role: 'owner' };
      return next();
    }

    try {
      const { data: u } = await supabase
        .from('users')
        .select('login,password_hash,role,is_banned')
        .eq('login', user)
        .maybeSingle();

      if (!u || u.is_banned) return res.status(401).json({ error: 'Invalid admin credentials' });

      const role = String(u.role || 'user').toLowerCase();
      if (!PANEL_ROLES.includes(role)) {
        return res.status(403).json({ error: 'No admin access' });
      }

      const ok = await bcrypt.compare(pass, u.password_hash);
      if (!ok) return res.status(401).json({ error: 'Invalid admin credentials' });

      req.admin = { login: u.login, role };
      return next();
    } catch (e) {
      return res.status(500).json({ error: e.message });
    }
  }

  return res.status(401).json({ error: 'Auth required' });
}

// ── Health ─────────────────────────────────────────────
app.get('/api/health', (req, res) => res.json({ ok: true }));

// ── Register ───────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  let { login, password } = req.body || {};
  login = (login || '').trim();
  password = (password || '').trim();
  if (login.length < 3 || login.length > 20) return res.status(400).json({ error: 'Login 3-20 chars' });
  if (!/^[a-zA-Z0-9_]+$/.test(login)) return res.status(400).json({ error: 'Login a-z0-9_' });
  if (password.length < 4 || password.length > 32) return res.status(400).json({ error: 'Password 4-32 chars' });

  const { data: exists } = await supabase.from('users').select('login').eq('login', login).maybeSingle();
  if (exists) return res.status(409).json({ error: 'Login taken' });

  const hash = await bcrypt.hash(password, 10);
  const { error } = await supabase.from('users').insert({
    login,
    password_hash: hash,
    valid_until: null,
    role: 'user'
  });
  if (error) return res.status(500).json({ error: error.message });
  return res.json({ ok: true });
});

// ── Login ──────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  let { login, password, hwid } = req.body || {};
  login = (login || '').trim();
  password = (password || '').trim();
  hwid = (hwid || '').trim();
  const isBrowser = hwid === 'browser';

  if (!login || !password) return res.status(400).json({ error: 'Missing fields' });
  if (!hwid && !isBrowser) return res.status(400).json({ error: 'Missing HWID' });

  const { data: user, error } = await supabase.from('users').select('*').eq('login', login).maybeSingle();
  if (error) return res.status(500).json({ error: error.message });
  if (!user) return res.status(401).json({ error: 'Invalid login' });
  if (user.is_banned) return res.status(403).json({ error: 'Banned' });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid password' });

  // Подписка НЕ обязательна — можно войти и активировать ключ в кабинете
  const hasSub = !!(user.valid_until && new Date(user.valid_until) > new Date());

  // HWID биндим только если есть подписка (иначе просто web-сессия)
  if (!isBrowser && hasSub) {
    if (!user.hwid || user.hwid === '') {
      await supabase.from('users').update({ hwid }).eq('login', login);
      user.hwid = hwid;
    } else if (user.hwid !== hwid) {
      return res.status(403).json({ error: 'HWID mismatch', code: 'HWID_MISMATCH' });
    }
  }

  const role = String(user.role || 'user').toLowerCase();
  // токен на 30 дней (или до конца подписки, если она дольше)
  let expMs = Date.now() + 30 * 24 * 3600 * 1000;
  if (hasSub) {
    const subMs = new Date(user.valid_until).getTime();
    if (subMs > expMs) expMs = subMs;
  }
  const exp = Math.floor(expMs / 1000);
  const token = jwt.sign(
    { login: user.login, hwid: isBrowser ? (user.hwid || 'browser') : hwid, role, exp },
    JWT_SECRET
  );

  return res.json({
    token,
    login: user.login,
    valid_until: user.valid_until,
    hwid: user.hwid,
    role,
    is_admin: PANEL_ROLES.includes(role),
    has_sub: hasSub
  });
});

// ── Verify ─────────────────────────────────────────────
app.post('/api/verify', async (req, res) => {
  const { token, hwid } = req.body || {};
  if (!token) return res.status(400).json({ error: 'No token' });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (hwid && hwid !== 'browser' && payload.hwid && payload.hwid !== hwid && payload.hwid !== 'browser') {
      return res.status(403).json({ error: 'HWID mismatch' });
    }

    const { data: user } = await supabase
      .from('users')
      .select('login,valid_until,is_banned,hwid,role')
      .eq('login', payload.login)
      .maybeSingle();

    if (!user || user.is_banned) return res.status(403).json({ error: 'Banned or deleted' });

    // Без подписки тоже пускаем в кабинет (активация ключа)
    const hasSub = !!(user.valid_until && new Date(user.valid_until) > new Date());
    const role = String(user.role || 'user').toLowerCase();

    return res.json({
      ok: true,
      login: user.login,
      valid_until: user.valid_until,
      hwid: user.hwid || null,
      role,
      is_admin: PANEL_ROLES.includes(role),
      has_sub: hasSub
    });
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
});

// ── Activate key ───────────────────────────────────────
app.post('/api/activate', async (req, res) => {
  try {
    const { token, key } = req.body || {};
    if (!token) return res.status(401).json({ error: 'Не авторизован' });
    if (!key || !String(key).trim()) return res.status(400).json({ error: 'Введи ключ' });

    let payload;
    try {
      payload = jwt.verify(token, JWT_SECRET);
    } catch {
      return res.status(401).json({ error: 'Неверный токен' });
    }

    const keyCode = String(key).trim().toUpperCase();

    const { data: license, error: keyErr } = await supabase
      .from('keys')
      .select('*')
      .eq('key', keyCode)
      .maybeSingle();

    if (keyErr) return res.status(500).json({ error: keyErr.message });
    if (!license) return res.status(400).json({ error: 'Ключ не найден' });
    if (license.used) return res.status(400).json({ error: 'Ключ уже использован' });

    const { data: user, error: userErr } = await supabase
      .from('users')
      .select('login,valid_until,role')
      .eq('login', payload.login)
      .maybeSingle();

    if (userErr) return res.status(500).json({ error: userErr.message });
    if (!user) return res.status(404).json({ error: 'Пользователь не найден' });

    const days = parseInt(license.days, 10) || 30;
    const base = user.valid_until && new Date(user.valid_until) > new Date()
      ? new Date(user.valid_until)
      : new Date();
    base.setDate(base.getDate() + days);
    const valid_until = base.toISOString();

    const upd = { valid_until };
    const keyRole = String(license.role || 'user').toLowerCase();
    const curRole = String(user.role || 'user').toLowerCase();
    if (keyRole === 'beta' && roleLevel(curRole) < roleLevel('beta')) {
      upd.role = 'beta';
    }

    const { error: updErr } = await supabase.from('users').update(upd).eq('login', user.login);
    if (updErr) return res.status(500).json({ error: updErr.message });

    // помечаем ключ использованным
    let useErr = (await supabase
      .from('keys')
      .update({ used: true, used_by: user.login, used_at: new Date().toISOString() })
      .eq('key', keyCode)).error;

    // fallback без used_at если колонки нет
    if (useErr) {
      useErr = (await supabase
        .from('keys')
        .update({ used: true, used_by: user.login })
        .eq('key', keyCode)).error;
    }

    if (useErr) return res.status(500).json({ error: useErr.message });

    return res.json({
      ok: true,
      message: `Подписка продлена на ${days} дн.`,
      valid_until,
      days
    });
  } catch (e) {
    console.error('activate error', e);
    return res.status(500).json({ error: 'Внутренняя ошибка сервера' });
  }
});

// ── Admin: list users ──────────────────────────────────
app.get('/api/admin/users', adminAuth, async (req, res) => {
  const { data, error } = await supabase
    .from('users')
    .select('login,hwid,valid_until,is_banned,role,created_at')
    .order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ── Admin: create / update user ────────────────────────
app.post('/api/admin/users', adminAuth, async (req, res) => {
  let { login, password, days, role } = req.body || {};
  login = (login || '').trim();
  password = (password || '').trim();
  days = parseInt(days, 10);
  role = String(role || 'user').toLowerCase();

  if (login.length < 3) return res.status(400).json({ error: 'Login 3-20' });
  if (!password || password.length < 4) return res.status(400).json({ error: 'Password 4-32' });
  if (!Number.isFinite(days)) days = 0;
  if (!ROLES[role]) role = 'user';

  // нельзя выдать роль выше своей
  if (roleLevel(role) > roleLevel(req.admin.role)) {
    return res.status(403).json({ error: 'Cannot assign role higher than yours' });
  }

  const { data: exists } = await supabase
    .from('users')
    .select('login,valid_until,role')
    .eq('login', login)
    .maybeSingle();

  const hash = await bcrypt.hash(password, 10);
  let valid_until = null;

  if (days === 0) {
    valid_until = new Date(Date.now() + 100 * 365 * 24 * 3600 * 1000).toISOString();
  } else if (days > 0) {
    const base = exists && exists.valid_until && new Date(exists.valid_until) > new Date()
      ? new Date(exists.valid_until)
      : new Date();
    base.setDate(base.getDate() + days);
    valid_until = base.toISOString();
  }

  if (exists) {
    const upd = { password_hash: hash, role };
    if (valid_until) upd.valid_until = valid_until;
    const { error } = await supabase.from('users').update(upd).eq('login', login);
    if (error) return res.status(500).json({ error: error.message });
  } else {
    const { error } = await supabase.from('users').insert({
      login,
      password_hash: hash,
      valid_until,
      role
    });
    if (error) return res.status(500).json({ error: error.message });
  }
  res.json({ ok: true });
});

// ── Admin: set role ────────────────────────────────────
app.post('/api/admin/users/:login/role', adminAuth, async (req, res) => {
  const login = req.params.login;
  let role = String((req.body || {}).role || '').toLowerCase().trim();

  if (!ROLES[role]) return res.status(400).json({ error: 'Unknown role' });
  if (roleLevel(role) > roleLevel(req.admin.role)) {
    return res.status(403).json({ error: 'Cannot assign role higher than yours' });
  }

  const { data: target } = await supabase
    .from('users')
    .select('login,role')
    .eq('login', login)
    .maybeSingle();

  if (!target) return res.status(404).json({ error: 'Not found' });

  // нельзя менять роль равного/выше себя (кроме себя? запретим чужих выше)
  if (roleLevel(target.role) > roleLevel(req.admin.role)) {
    return res.status(403).json({ error: 'Cannot modify user with higher role' });
  }

  const { error } = await supabase.from('users').update({ role }).eq('login', login);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true, role });
});

// ── Admin: extend ──────────────────────────────────────
app.post('/api/admin/users/:login/extend', adminAuth, async (req, res) => {
  const login = req.params.login;
  let days = parseInt(req.body.days, 10);
  if (!Number.isFinite(days) || days <= 0) return res.status(400).json({ error: 'days >0' });

  const { data: user } = await supabase.from('users').select('valid_until').eq('login', login).maybeSingle();
  if (!user) return res.status(404).json({ error: 'Not found' });

  const base = user.valid_until && new Date(user.valid_until) > new Date()
    ? new Date(user.valid_until)
    : new Date();
  base.setDate(base.getDate() + days);

  const { error } = await supabase
    .from('users')
    .update({ valid_until: base.toISOString() })
    .eq('login', login);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true, valid_until: base.toISOString() });
});

// ── Admin: reduce days ─────────────────────────────────
app.post('/api/admin/users/:login/reduce', adminAuth, async (req, res) => {
  const login = req.params.login;
  let days = parseInt(req.body.days, 10);
  if (!Number.isFinite(days) || days <= 0) return res.status(400).json({ error: 'days >0' });

  const { data: user } = await supabase.from('users').select('valid_until').eq('login', login).maybeSingle();
  if (!user) return res.status(404).json({ error: 'Not found' });

  let base = user.valid_until ? new Date(user.valid_until) : new Date();
  if (base <= new Date()) {
    // уже истекла — оставляем как есть (сейчас)
    base = new Date();
  }
  base.setDate(base.getDate() - days);
  // не уводим сильно в прошлое — можно обнулить до "сейчас - 1 мин"
  const now = new Date();
  if (base < now) base = new Date(now.getTime() - 60 * 1000);

  const { error } = await supabase
    .from('users')
    .update({ valid_until: base.toISOString() })
    .eq('login', login);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true, valid_until: base.toISOString(), message: '−' + days + ' дн. у ' + login });
});

// ── Admin: reset HWID ──────────────────────────────────
app.post('/api/admin/users/:login/reset_hwid', adminAuth, async (req, res) => {
  const login = req.params.login;
  const { error } = await supabase.from('users').update({ hwid: null }).eq('login', login);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

// ── Admin: ban ─────────────────────────────────────────
app.post('/api/admin/users/:login/ban', adminAuth, async (req, res) => {
  const login = req.params.login;
  const banned = !!req.body.banned;
  const { error } = await supabase.from('users').update({ is_banned: banned }).eq('login', login);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

// ── Admin: delete ──────────────────────────────────────
app.delete('/api/admin/users/:login', adminAuth, async (req, res) => {
  const login = req.params.login;
  const { error } = await supabase.from('users').delete().eq('login', login);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

// ── Admin: keys list ───────────────────────────────────
app.get('/api/admin/keys', adminAuth, async (req, res) => {
  const { data, error } = await supabase
    .from('keys')
    .select('key,days,role,used,used_by,created_at')
    .eq('used', false)
    .order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data || []);
});

// ── Admin: generate keys ───────────────────────────────
app.post('/api/admin/keys', adminAuth, async (req, res) => {
  let { days = 30, count = 1, role = 'user' } = req.body || {};
  days = parseInt(days, 10) || 30;
  count = Math.min(50, Math.max(1, parseInt(count, 10) || 1));
  role = String(role || 'user').toLowerCase();
  if (!['user', 'beta'].includes(role)) role = 'user';

  const keys = [];
  for (let i = 0; i < count; i++) {
    const key = genKey();
    const { error } = await supabase.from('keys').insert({
      key,
      days,
      role,
      used: false
    });
    if (error) return res.status(500).json({ error: error.message });
    keys.push({ key, days, role });
  }
  res.json({ keys });
});

// ── Admin: promo codes list ────────────────────────────
app.get('/api/admin/promos', adminAuth, async (req, res) => {
  const { data, error } = await supabase
    .from('promos')
    .select('*')
    .order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data || []);
});

// ── Admin: create promo ────────────────────────────────
app.post('/api/admin/promos', adminAuth, async (req, res) => {
  let { code, days = 7, max_uses = 1, role = 'user', expires_at } = req.body || {};
  code = String(code || '').trim().toUpperCase().replace(/\s+/g, '');
  days = parseInt(days, 10) || 7;
  max_uses = Math.max(1, parseInt(max_uses, 10) || 1);
  role = String(role || 'user').toLowerCase();
  if (!['user', 'beta'].includes(role)) role = 'user';

  if (!code || code.length < 3 || code.length > 32) {
    return res.status(400).json({ error: 'Код 3-32 символа' });
  }
  if (!/^[A-Z0-9_-]+$/.test(code)) {
    return res.status(400).json({ error: 'Только A-Z, 0-9, _, -' });
  }

  const row = {
    code,
    days,
    max_uses,
    used_count: 0,
    role,
    active: true
  };
  if (expires_at) row.expires_at = new Date(expires_at).toISOString();

  const { data, error } = await supabase.from('promos').insert(row).select().maybeSingle();
  if (error) {
    if (error.code === '23505') return res.status(409).json({ error: 'Такой промокод уже есть' });
    return res.status(500).json({ error: error.message });
  }
  res.json({ ok: true, promo: data });
});

// ── Admin: toggle promo ────────────────────────────────
app.post('/api/admin/promos/:code/toggle', adminAuth, async (req, res) => {
  const code = String(req.params.code || '').toUpperCase();
  const { data: promo } = await supabase.from('promos').select('active').eq('code', code).maybeSingle();
  if (!promo) return res.status(404).json({ error: 'Не найден' });

  const { error } = await supabase.from('promos').update({ active: !promo.active }).eq('code', code);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true, active: !promo.active });
});

// ── Admin: delete promo ────────────────────────────────
app.delete('/api/admin/promos/:code', adminAuth, async (req, res) => {
  const code = String(req.params.code || '').toUpperCase();
  const { error } = await supabase.from('promos').delete().eq('code', code);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

// ── User: redeem promo ─────────────────────────────────
app.post('/api/promo', async (req, res) => {
  try {
    const { token, code } = req.body || {};
    if (!token) return res.status(401).json({ error: 'Не авторизован' });
    if (!code || !String(code).trim()) return res.status(400).json({ error: 'Введи промокод' });

    let payload;
    try {
      payload = jwt.verify(token, JWT_SECRET);
    } catch {
      return res.status(401).json({ error: 'Неверный токен' });
    }

    const promoCode = String(code).trim().toUpperCase();

    const { data: promo, error: pErr } = await supabase
      .from('promos')
      .select('*')
      .eq('code', promoCode)
      .maybeSingle();

    if (pErr) return res.status(500).json({ error: pErr.message });
    if (!promo) return res.status(400).json({ error: 'Промокод не найден' });
    if (!promo.active) return res.status(400).json({ error: 'Промокод отключён' });
    if (promo.expires_at && new Date(promo.expires_at) < new Date()) {
      return res.status(400).json({ error: 'Промокод истёк' });
    }
    if (promo.used_count >= promo.max_uses) {
      return res.status(400).json({ error: 'Лимит активаций исчерпан' });
    }

    const { data: already } = await supabase
      .from('promo_uses')
      .select('id')
      .eq('code', promoCode)
      .eq('login', payload.login)
      .maybeSingle();

    if (already) return res.status(400).json({ error: 'Ты уже использовал этот промокод' });

    const { data: user, error: uErr } = await supabase
      .from('users')
      .select('login,valid_until,role')
      .eq('login', payload.login)
      .maybeSingle();

    if (uErr) return res.status(500).json({ error: uErr.message });
    if (!user) return res.status(404).json({ error: 'Пользователь не найден' });

    const days = parseInt(promo.days, 10) || 7;
    const base = user.valid_until && new Date(user.valid_until) > new Date()
      ? new Date(user.valid_until)
      : new Date();
    base.setDate(base.getDate() + days);
    const valid_until = base.toISOString();

    const upd = { valid_until };
    const promoRole = String(promo.role || 'user').toLowerCase();
    const curRole = String(user.role || 'user').toLowerCase();
    if (promoRole === 'beta' && roleLevel(curRole) < roleLevel('beta')) {
      upd.role = 'beta';
    }

    const { error: updErr } = await supabase.from('users').update(upd).eq('login', user.login);
    if (updErr) return res.status(500).json({ error: updErr.message });

    await supabase.from('promo_uses').insert({ code: promoCode, login: user.login });
    await supabase.from('promos').update({ used_count: (promo.used_count || 0) + 1 }).eq('code', promoCode);

    return res.json({
      ok: true,
      message: `Промокод активирован: +${days} дн.`,
      valid_until,
      days
    });
  } catch (e) {
    console.error('promo error', e);
    return res.status(500).json({ error: 'Внутренняя ошибка сервера' });
  }
});

// ── Download loader (только с активной подпиской) ──────
app.get('/api/download/loader', async (req, res) => {
  const token =
    req.query.token ||
    (req.headers.authorization || '').replace(/^Bearer\s+/i, '');

  if (!token) {
    return res.status(401).json({ error: 'Нужен вход' });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const { data: user, error } = await supabase
      .from('users')
      .select('login,valid_until,is_banned')
      .eq('login', payload.login)
      .maybeSingle();

    if (error) return res.status(500).json({ error: error.message });
    if (!user || user.is_banned) {
      return res.status(403).json({ error: 'Нет доступа' });
    }
    if (!user.valid_until || new Date(user.valid_until) <= new Date()) {
      return res.status(403).json({ error: 'Подписка истекла' });
    }

    const file = path.join(__dirname, 'downloads', 'Nebula-Launcher.exe');
    if (!fs.existsSync(file)) {
      return res.status(404).json({ error: 'Файл лоадера не найден на сервере' });
    }

    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', 'attachment; filename="Nebula-Launcher.exe"');
    return res.download(file, 'Nebula-Launcher.exe');
  } catch (e) {
    return res.status(401).json({ error: 'Неверный токен' });
  }
});

// ── Download client jar (Nebula.jar для лоадера с сайта) ──
app.get('/api/download/client', async (req, res) => {
  const token =
    req.query.token ||
    (req.headers.authorization || '').replace(/^Bearer\s+/i, '');

  if (!token) {
    return res.status(401).json({ error: 'Нужен вход в аккаунт' });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const { data: user, error } = await supabase
      .from('users')
      .select('login,valid_until,is_banned,role')
      .eq('login', payload.login)
      .maybeSingle();

    if (error) return res.status(500).json({ error: error.message });
    if (!user || user.is_banned) {
      return res.status(403).json({ error: 'Нет доступа к клиенту' });
    }

    const role = String(user.role || '').toLowerCase();
    const isPrivileged = PANEL_ROLES.includes(role) || ['katrek', '74iq'].includes(String(user.login).toLowerCase());
    const hasSub = user.valid_until && new Date(user.valid_until) > new Date();

    if (!isPrivileged && !hasSub) {
      return res.status(403).json({ error: 'Подписка истекла' });
    }

    const file = path.join(__dirname, 'downloads', 'Nebula.jar');
    if (!fs.existsSync(file)) {
      return res.status(404).json({ error: 'Файл клиента Nebula.jar не найден на сервере' });
    }

    res.setHeader('Content-Type', 'application/java-archive');
    res.setHeader('Content-Disposition', 'attachment; filename="Nebula.jar"');
    return res.download(file, 'Nebula.jar');
  } catch (e) {
    return res.status(401).json({ error: 'Неверный токен' });
  }
});

// ── Download project skeleton (для чистых ПК) ───────────
app.get('/api/download/skeleton', (req, res) => {
  const file = path.join(__dirname, 'downloads', 'skeleton.zip');
  if (!fs.existsSync(file)) {
    return res.status(404).json({ error: 'Файл skeleton.zip не найден на сервере' });
  }

  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('Content-Disposition', 'attachment; filename="skeleton.zip"');
  return res.download(file, 'skeleton.zip');
});

// ── Clean URLs (без .html) ─────────────────────────────
const SITE_DIR = path.join(__dirname, 'site');
const ADMIN_DIR = path.join(__dirname, 'admin');

// /profile.html → /profile
app.get(/\.html$/i, (req, res, next) => {
  if (req.path.startsWith('/api')) return next();
  const clean = req.path.replace(/\.html$/i, '') || '/';
  const qs = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
  return res.redirect(301, clean + qs);
});

// /admin → admin/index.html или admin.html
app.get('/admin', (req, res) => {
  const idx = path.join(ADMIN_DIR, 'index.html');
  if (fs.existsSync(idx)) return res.sendFile(idx);
  const alt = path.join(ADMIN_DIR, 'admin.html');
  if (fs.existsSync(alt)) return res.sendFile(alt);
  res.status(404).send('Admin not found');
});

app.use('/admin', express.static(ADMIN_DIR));

// css, js, картинки + авто .html через extensions
app.use(express.static(SITE_DIR, { extensions: ['html'] }));

app.get('/', (req, res) => {
  res.sendFile(path.join(SITE_DIR, 'index.html'));
});

// /profile → site/profile.html
app.get('/:page', (req, res, next) => {
  if (req.params.page.includes('.')) return next();
  const file = path.join(SITE_DIR, req.params.page + '.html');
  if (fs.existsSync(file)) return res.sendFile(file);
  next();
});

app.listen(PORT, () => console.log('Nebula auth listening on ' + PORT));
