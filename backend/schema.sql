-- Включить проверку внешних ключей
PRAGMA foreign_keys = ON;

-- Пользователи (учётная запись администратора)
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    password_salt TEXT    NOT NULL,
    is_active     INTEGER NOT NULL DEFAULT 1,   -- 0/1 вместо BOOLEAN
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Команды АПЛ
CREATE TABLE IF NOT EXISTS teams (
    id         TEXT PRIMARY KEY,   -- 3-буквенный код, напр. 'ARS'
    name       TEXT NOT NULL UNIQUE,
    short_name TEXT,
    sort_order INTEGER
);

-- Матчи
CREATE TABLE IF NOT EXISTS matches (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    round        INTEGER NOT NULL CHECK (round BETWEEN 1 AND 38),
    home_team_id TEXT    NOT NULL REFERENCES teams(id),
    away_team_id TEXT    NOT NULL REFERENCES teams(id),
    home_score   INTEGER NOT NULL DEFAULT 0 CHECK (home_score >= 0),
    away_score   INTEGER NOT NULL DEFAULT 0 CHECK (away_score >= 0),
    match_date   TEXT    NOT NULL,             -- ISO-8601, напр. '2026-08-22'
    created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    CHECK (home_team_id <> away_team_id),
    UNIQUE (round, home_team_id, away_team_id)
);

-- Индексы для ускорения выборок
CREATE INDEX IF NOT EXISTS idx_matches_round ON matches(round);
CREATE INDEX IF NOT EXISTS idx_matches_home  ON matches(home_team_id);
CREATE INDEX IF NOT EXISTS idx_matches_away  ON matches(away_team_id);
