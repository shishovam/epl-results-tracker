import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { sign } from 'hono/jwt';

const app = new Hono();

app.use('*', cors({ origin: '*' }));

// Параметры PBKDF2 — должны совпадать 1:1 с create-admin.mjs
const PBKDF2_ITERATIONS = 100000;
const PBKDF2_KEY_BITS   = 256;

// Восстанавливает хеш из пароля и соли (hex → Uint8Array → deriveBits → hex)
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

// GET /api/health — без JWT
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

// POST /api/auth/login — без JWT
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

  // Один и тот же ответ для "нет такого пользователя" и "пароль не подошёл"
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

export default app;
