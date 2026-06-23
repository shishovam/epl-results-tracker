// Создание учётной записи администратора в УДАЛЁННОЙ базе D1.
//
// Пароль вводится скрытым вводом и нигде не сохраняется. В базу попадает
// только хеш (PBKDF2/SHA-256) с солью.
//
// Функция хеширования ниже — 1:1 как в Worker (см. development-gitbook.md §3.1).
// Это важно: если параметры отличаются, вход не сработает.
//
// Запуск из папки backend/:
//   node scripts/create-admin.mjs

import readline from 'node:readline';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { webcrypto } from 'node:crypto';

const crypto = webcrypto; // тот же Web Crypto API, что и в Workers

const USERNAME = 'admin';
const ITERATIONS = 100000;
const SALT_BYTES = 16;
const KEY_BITS = 256;

// --- Хеширование (идентично Worker) -----------------------------------
async function hashPassword(password) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));

  const key = await crypto.subtle.importKey(
    'raw', enc.encode(password), 'PBKDF2', false, ['deriveBits'],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' },
    key,
    KEY_BITS,
  );

  const toHex = (arr) => [...arr].map((b) => b.toString(16).padStart(2, '0')).join('');
  return { hash: toHex(new Uint8Array(bits)), salt: toHex(salt) };
}

// --- Скрытый ввод (эхо подавляется, перенос строки пропускается) -------
function askPassword(promptText) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
      terminal: process.stdin.isTTY,
    });
    rl._writeToOutput = (s) => {
      if (/\n|\r/.test(s)) process.stdout.write(s); // эхо символов не выводим
    };
    process.stdout.write(promptText); // приглашение показываем сами
    rl.question('', (answer) => {
      rl.close();
      process.stdout.write('\n');
      resolve(answer);
    });
  });
}

// --- main --------------------------------------------------------------
const pwd1 = await askPassword('Введите пароль администратора: ');
if (!pwd1) {
  console.error('❌ Пустой пароль недопустим.');
  process.exit(1);
}
const pwd2 = await askPassword('Повторите пароль: ');
if (pwd1 !== pwd2) {
  console.error('❌ Пароли не совпадают. Попробуйте снова.');
  process.exit(1);
}

const { hash, salt } = await hashPassword(pwd1);

// Одноразовый INSERT. Значения — hex без апострофов, инъекция невозможна.
const sql = `INSERT INTO users (username, password_hash, password_salt, is_active)
VALUES ('${USERNAME}', '${hash}', '${salt}', 1);`;

// Пишем SQL во временную папку ОС (вне репозитория), чтобы хеш не попал в git.
const tmpDir = mkdtempSync(join(tmpdir(), 'epl-admin-'));
const sqlFile = join(tmpDir, 'admin.sql');
writeFileSync(sqlFile, sql, 'utf8');

try {
  const result = spawnSync(
    'wrangler',
    ['d1', 'execute', 'epl-tracker', '--remote', '--file', sqlFile],
    { shell: true, stdio: 'inherit' },
  );
  if (result.status !== 0) {
    console.error('❌ Не удалось записать в D1 (код ' + result.status + ').');
    if (result.status === 1) {
      console.error('   Возможно, пользователь "admin" уже существует.');
    }
    process.exit(result.status ?? 1);
  }
} finally {
  rmSync(tmpDir, { recursive: true, force: true }); // удаляем в любом случае
}

console.log('✅ Администратор "' + USERNAME + '" создан в удалённой базе epl-tracker.');
console.log('   Пароль в базу не записывался — только PBKDF2-хеш с солью.');
