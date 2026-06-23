import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { sign, verify } from 'hono/jwt';

const app = new Hono();

app.use('*', cors({ origin: '*' }));

// Параметры PBKDF2 — должны совпадать 1:1 с create-admin.mjs
const PBKDF2_ITERATIONS = 100000;
const PBKDF2_KEY_BITS   = 256;

async function deriveHash(password, saltHex) {
  const enc  = new TextEncoder();
  const salt = new Uint8Array(saltHex.match(/.{2}/g).map((b) => parseInt(b, 16)));

  const key = await crypto.subtle.importKey(
    'raw', enc.encode(password), 'PBKDF2', false, ['deriveBits'],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    key,
    PBKDF2_KEY_BITS,
  );

  return [...new Uint8Array(bits)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

// Возвращает целое число в диапазоне 1–38 или null
function parseRound(val) {
  const n = Number(val);
  return Number.isInteger(n) && n >= 1 && n <= 38 ? n : null;
}

// Возвращает целое неотрицательное число или null
function parseScore(val) {
  const n = Number(val);
  return Number.isInteger(n) && n >= 0 ? n : null;
}

// JWT-защита: все /api/* кроме health и login
app.use('/api/*', async (c, next) => {
  const path = c.req.path;
  if (path === '/api/health' || path === '/api/auth/login') {
    return next();
  }

  const authHeader = c.req.header('Authorization');
  if (!authHeader?.startsWith('Bearer ')) {
    return c.json(
      { success: false, error: { code: 'UNAUTHORIZED', message: 'Требуется авторизация.' } },
      401,
    );
  }

  try {
    const payload = await verify(authHeader.slice(7), c.env.JWT_SECRET, 'HS256');
    c.set('jwtPayload', payload);
    return next();
  } catch {
    return c.json(
      { success: false, error: { code: 'UNAUTHORIZED', message: 'Токен недействителен или истёк.' } },
      401,
    );
  }
});

// ── Публичные маршруты ────────────────────────────────────────────────────────

app.get('/api/health', (c) => {
  return c.json({
    success: true,
    data: {
      status: 'ok',
      service: 'epl-tracker-api',
      timestamp: new Date().toISOString(),
    },
  });
});

app.post('/api/auth/login', async (c) => {
  let body;
  try {
    body = await c.req.json();
  } catch {
    return c.json(
      { success: false, error: { code: 'VALIDATION_ERROR', message: 'Тело запроса должно быть JSON.' } },
      400,
    );
  }

  const { username, password } = body ?? {};
  if (!username || !password) {
    return c.json(
      { success: false, error: { code: 'VALIDATION_ERROR', message: 'Поля username и password обязательны.' } },
      400,
    );
  }

  const badCreds = {
    success: false,
    error: { code: 'INVALID_CREDENTIALS', message: 'Неверный логин или пароль.' },
  };

  const user = await c.env.DB.prepare(
    'SELECT id, username, password_hash, password_salt, is_active FROM users WHERE username = ?',
  ).bind(username).first();

  if (!user || !user.is_active) {
    return c.json(badCreds, 401);
  }

  const computedHash = await deriveHash(password, user.password_salt);
  if (computedHash !== user.password_hash) {
    return c.json(badCreds, 401);
  }

  const secret = c.env.JWT_SECRET;
  if (!secret) {
    return c.json(
      { success: false, error: { code: 'SERVER_ERROR', message: 'Ошибка конфигурации сервера.' } },
      500,
    );
  }

  const now = Math.floor(Date.now() / 1000);
  const token = await sign(
    { sub: String(user.id), username: user.username, iat: now, exp: now + 86400 },
    secret,
  );

  return c.json({ success: true, data: { token } });
});

// ── Защищённые маршруты ───────────────────────────────────────────────────────

app.get('/api/teams', async (c) => {
  const { results } = await c.env.DB.prepare(
    'SELECT id, name, short_name, sort_order FROM teams ORDER BY sort_order ASC',
  ).all();

  return c.json({ success: true, data: results });
});

// GET /api/matches/round/:round — должен быть раньше GET /api/matches
app.get('/api/matches/round/:round', async (c) => {
  const round = parseRound(c.req.param('round'));
  if (round === null) {
    return c.json(
      { success: false, error: { code: 'VALIDATION_ERROR', message: 'Номер тура должен быть целым числом от 1 до 38.' } },
      400,
    );
  }

  const { results } = await c.env.DB.prepare(
    'SELECT * FROM matches WHERE round = ? ORDER BY id ASC',
  ).bind(round).all();

  return c.json({ success: true, data: results });
});

app.get('/api/matches', async (c) => {
  const { results } = await c.env.DB.prepare(
    'SELECT * FROM matches ORDER BY round ASC, id ASC',
  ).all();

  return c.json({ success: true, data: results });
});

app.post('/api/matches', async (c) => {
  let body;
  try {
    body = await c.req.json();
  } catch {
    return c.json(
      { success: false, error: { code: 'VALIDATION_ERROR', message: 'Тело запроса должно быть JSON.' } },
      400,
    );
  }

  const { round, home_team_id, away_team_id, home_score, away_score, match_date } = body ?? {};

  const roundNum   = parseRound(round);
  const homeScore  = parseScore(home_score);
  const awayScore  = parseScore(away_score);

  if (roundNum === null) {
    return c.json(
      { success: false, error: { code: 'VALIDATION_ERROR', message: 'Номер тура должен быть целым числом от 1 до 38.' } },
      400,
    );
  }
  if (!home_team_id || !away_team_id) {
    return c.json(
      { success: false, error: { code: 'VALIDATION_ERROR', message: 'Укажите home_team_id и away_team_id.' } },
      400,
    );
  }
  if (home_team_id === away_team_id) {
    return c.json(
      { success: false, error: { code: 'VALIDATION_ERROR', message: 'Домашняя и гостевая команды должны быть разными.' } },
      400,
    );
  }
  if (homeScore === null || awayScore === null) {
    return c.json(
      { success: false, error: { code: 'VALIDATION_ERROR', message: 'Счёт должен быть целым неотрицательным числом.' } },
      400,
    );
  }
  if (!match_date || !/^\d{4}-\d{2}-\d{2}$/.test(match_date)) {
    return c.json(
      { success: false, error: { code: 'VALIDATION_ERROR', message: 'Дата матча обязательна и должна быть в формате YYYY-MM-DD.' } },
      400,
    );
  }

  // Проверяем существование обеих команд
  const homeTeam = await c.env.DB.prepare('SELECT id FROM teams WHERE id = ?').bind(home_team_id).first();
  if (!homeTeam) {
    return c.json(
      { success: false, error: { code: 'NOT_FOUND', message: `Команда "${home_team_id}" не найдена.` } },
      404,
    );
  }
  const awayTeam = await c.env.DB.prepare('SELECT id FROM teams WHERE id = ?').bind(away_team_id).first();
  if (!awayTeam) {
    return c.json(
      { success: false, error: { code: 'NOT_FOUND', message: `Команда "${away_team_id}" не найдена.` } },
      404,
    );
  }

  try {
    const result = await c.env.DB.prepare(
      'INSERT INTO matches (round, home_team_id, away_team_id, home_score, away_score, match_date) VALUES (?, ?, ?, ?, ?, ?)',
    ).bind(roundNum, home_team_id, away_team_id, homeScore, awayScore, match_date).run();

    const match = await c.env.DB.prepare('SELECT * FROM matches WHERE id = ?')
      .bind(result.meta.last_row_id).first();

    return c.json({ success: true, data: match }, 201);
  } catch (e) {
    if (e?.message?.includes('UNIQUE')) {
      return c.json(
        { success: false, error: { code: 'CONFLICT', message: 'Матч между этими командами в данном туре уже существует.' } },
        409,
      );
    }
    throw e;
  }
});

app.put('/api/matches/:id', async (c) => {
  const id = Number(c.req.param('id'));
  if (!Number.isInteger(id) || id < 1) {
    return c.json(
      { success: false, error: { code: 'VALIDATION_ERROR', message: 'Некорректный ID матча.' } },
      400,
    );
  }

  let body;
  try {
    body = await c.req.json();
  } catch {
    return c.json(
      { success: false, error: { code: 'VALIDATION_ERROR', message: 'Тело запроса должно быть JSON.' } },
      400,
    );
  }

  const { home_score, away_score, match_date } = body ?? {};

  const homeScore = parseScore(home_score);
  const awayScore = parseScore(away_score);

  if (homeScore === null || awayScore === null) {
    return c.json(
      { success: false, error: { code: 'VALIDATION_ERROR', message: 'Счёт должен быть целым неотрицательным числом.' } },
      400,
    );
  }
  if (!match_date || !/^\d{4}-\d{2}-\d{2}$/.test(match_date)) {
    return c.json(
      { success: false, error: { code: 'VALIDATION_ERROR', message: 'Дата матча обязательна и должна быть в формате YYYY-MM-DD.' } },
      400,
    );
  }

  const result = await c.env.DB.prepare(
    "UPDATE matches SET home_score = ?, away_score = ?, match_date = ?, updated_at = datetime('now') WHERE id = ?",
  ).bind(homeScore, awayScore, match_date, id).run();

  if (result.meta.changes === 0) {
    return c.json(
      { success: false, error: { code: 'NOT_FOUND', message: 'Матч не найден.' } },
      404,
    );
  }

  const match = await c.env.DB.prepare('SELECT * FROM matches WHERE id = ?').bind(id).first();
  return c.json({ success: true, data: match });
});

app.delete('/api/matches/:id', async (c) => {
  const id = Number(c.req.param('id'));
  if (!Number.isInteger(id) || id < 1) {
    return c.json(
      { success: false, error: { code: 'VALIDATION_ERROR', message: 'Некорректный ID матча.' } },
      400,
    );
  }

  const result = await c.env.DB.prepare('DELETE FROM matches WHERE id = ?').bind(id).run();

  if (result.meta.changes === 0) {
    return c.json(
      { success: false, error: { code: 'NOT_FOUND', message: 'Матч не найден.' } },
      404,
    );
  }

  return c.json({ success: true, data: null });
});

export default app;
