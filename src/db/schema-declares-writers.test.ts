/**
 * The SCHEMAFULL tables in sql/migrations must hold what identity's own writers write.
 *
 * api_key and key_session were created SCHEMALESS by their writers, and the migrations
 * turn them SCHEMAFULL over the rows already there. On SurrealDB 2.x that drops every
 * written field the schema does not declare, and a required field the writer never set
 * fails the file's index builds on the old rows (so the migration itself fails) and every
 * later UPDATE of them. A NULL the writer sends into a field that only allows NONE is
 * refused. So the writer's CREATE is captured here and checked against the declarations.
 */

import { test, expect, describe, mock } from 'bun:test';
import { readdirSync, readFileSync } from 'fs';
import { join } from 'path';

mock.module('./redis', () => ({
  redis: {},
  isKeyRevoked: async () => false,
  revokeKey: async () => {},
  unrevokeKey: async () => {},
  getRateLimitKey: (endpoint: string, ip: string) => `ratelimit:${endpoint}:${ip}`,
  checkRateLimit: async () => ({ allowed: true, retryAfterSeconds: 0 }),
}));

const surrealCalls: Array<{ sql: string; params?: Record<string, unknown> }> = [];
mock.module('./surrealdb', () => ({
  query: async (sql: string, params?: Record<string, unknown>) => {
    surrealCalls.push({ sql, params });
    return [];
  },
  getSurrealDB: async () => {
    throw new Error('SurrealDB stubbed in schema-declares-writers test');
  },
}));

import { mintApiKey, setQueryFn } from '../resolvers/issue-key';
import { recordKeySession } from '../services/keySession';

const MIGRATIONS = join(import.meta.dir, '../../sql/migrations');

/** table -> field -> declared TYPE, across every migration in apply order. */
function declaredFields(): Map<string, Map<string, string>> {
  const tables = new Map<string, Map<string, string>>();
  const re = /DEFINE\s+FIELD\s+(?:OVERWRITE\s+|IF\s+NOT\s+EXISTS\s+)?([\w.*]+)\s+ON\s+(?:TABLE\s+)?(\w+)\s+TYPE\s+(.+?)(?=\s+DEFAULT\b|\s+ASSERT\b|\s+VALUE\b|\s+PERMISSIONS\b|;)/gis;
  for (const file of readdirSync(MIGRATIONS).filter((f) => f.endsWith('.surql')).sort()) {
    const text = readFileSync(join(MIGRATIONS, file), 'utf8').replace(/--[^\n]*/g, '');
    for (const m of text.matchAll(re)) {
      const [, field, table, type] = m;
      if (!tables.has(table)) tables.set(table, new Map());
      tables.get(table)!.set(field, type.trim());
    }
  }
  return tables;
}

/** The fields a `CREATE <table> SET a = …, b = …;` assigns. */
function createdFields(sql: string, table: string): string[] {
  const m = new RegExp(`CREATE\\s+${table}\\s+SET\\s+([\\s\\S]*?);`, 'i').exec(sql);
  if (!m) throw new Error(`no CREATE ${table} in: ${sql}`);
  return [...m[1].matchAll(/(?:^|,)\s*(\w+)\s*=/g)].map((x) => x[1]);
}

const isOptional = (type: string) => /^option</i.test(type);
const allowsNull = (type: string) => /\bnull\b/i.test(type);

async function issueKeyCreate(): Promise<{ sql: string; params: Record<string, unknown> }> {
  const captured: Array<{ sql: string; params: Record<string, unknown> }> = [];
  setQueryFn(async (sql, params) => {
    captured.push({ sql, params: params ?? {} });
    return [];
  });
  try {
    const res = await mintApiKey({ user_id: 'users:u1', org_id: 'organizations:o1', name: 'n', expires_in_days: 30 });
    expect(res.ok).toBe(true);
  } finally {
    setQueryFn(null);
  }
  const create = captured.find((c) => /CREATE\s+api_key\b/i.test(c.sql));
  if (!create) throw new Error('issue-key sent no CREATE api_key');
  return create;
}

async function keySessionCreate(withUser: boolean): Promise<{ sql: string; params: Record<string, unknown> }> {
  surrealCalls.length = 0;
  await recordKeySession({
    key_id: 'key_abc',
    org_id: 'organizations:o1',
    ...(withUser ? { user_id: 'users:u1' } : {}),
    issued_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 900_000).toISOString(),
    source: 'resolve_flat',
  });
  const create = surrealCalls.find((c) => /CREATE\s+key_session\b/i.test(c.sql));
  if (!create) throw new Error('recordKeySession sent no CREATE key_session');
  return { sql: create.sql, params: create.params ?? {} };
}

describe('api_key: the schema holds what issue-key writes', () => {
  test('every field issue-key writes is declared, prefix included', async () => {
    const declared = declaredFields().get('api_key') ?? new Map();
    const written = createdFields((await issueKeyCreate()).sql, 'api_key');
    expect(written).toContain('prefix');
    expect(written.filter((f) => !declared.has(f))).toEqual([]);
  });

  test('every required field is one issue-key writes', async () => {
    const declared = declaredFields().get('api_key') ?? new Map();
    const written = new Set(createdFields((await issueKeyCreate()).sql, 'api_key'));
    const required = [...declared].filter(([f, t]) => !f.includes('.') && !isOptional(t)).map(([f]) => f);
    expect(required.length).toBeGreaterThan(0);
    expect(required.filter((f) => !written.has(f))).toEqual([]);
  });
});

describe('key_session: the schema holds what recordKeySession writes', () => {
  test('every field written is declared, and every required field is written', async () => {
    const declared = declaredFields().get('key_session') ?? new Map();
    const written = createdFields((await keySessionCreate(true)).sql, 'key_session');
    expect(written.filter((f) => !declared.has(f))).toEqual([]);
    const required = [...declared].filter(([, t]) => !isOptional(t)).map(([f]) => f);
    expect(required.filter((f) => !written.includes(f))).toEqual([]);
  });

  test('a field written as NULL is declared to allow NULL', async () => {
    const declared = declaredFields().get('key_session') ?? new Map();
    const { params } = await keySessionCreate(false);
    const nulls = Object.keys(params).filter((k) => params[k] === null);
    expect(nulls).toContain('user_id');
    expect(nulls.filter((f) => !allowsNull(declared.get(f) ?? ''))).toEqual([]);
  });
});
