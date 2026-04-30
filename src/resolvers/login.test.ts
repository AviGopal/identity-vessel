/**
 * Tests for the email+password login & signup resolver.
 *
 * SurrealDB and Redis are mocked at module load. Constant-time dummy hashing
 * is disabled via NODE_ENV=test (see resolvers/login.ts).
 */

import { test, expect, describe, beforeEach, afterEach, mock } from 'bun:test';

process.env.NODE_ENV = 'test';

mock.module('../db/redis', () => ({
  redis: {},
  isKeyRevoked: async () => false,
  revokeKey: async () => {},
  unrevokeKey: async () => {},
  getRateLimitKey: (endpoint: string, ip: string) => `ratelimit:${endpoint}:${ip}`,
  checkRateLimit: async () => ({ allowed: true, retryAfterSeconds: 0 }),
}));

mock.module('../db/surrealdb', () => ({
  query: async () => [],
  getSurrealDB: async () => { throw new Error('SurrealDB stubbed in login test'); },
}));

import {
  loginWithPassword, signupWithPassword, setQueryFn, type AuthResult,
} from './login';
import { hashPassword } from '../services/password';
import { verifyToken } from '../services/jwt';

// =============================================================================
// In-memory SurrealDB stub
// =============================================================================

interface DbState {
  users: Map<string, any>;        // keyed by email (lowercased)
  userById: Map<string, any>;
  organizationMembers: any[];
  accountMembers: any[];
  organizations: Map<string, any>;
  accounts: Map<string, any>;
}

function makeFreshDb(): DbState {
  return {
    users: new Map(), userById: new Map(),
    organizationMembers: [], accountMembers: [],
    organizations: new Map(), accounts: new Map(),
  };
}

let DB = makeFreshDb();
let userIdCounter = 0;

async function fakeQuery(sql: string, params?: Record<string, any>): Promise<any> {
  const norm = sql.replace(/\s+/g, ' ').trim();

  if (norm.startsWith('SELECT id, email, password_hash, default_org_id FROM users WHERE email')) {
    const row = DB.users.get((params?.email || '').toLowerCase());
    return row ? [[row]] : [[]];
  }
  if (norm.startsWith('SELECT id FROM users WHERE email')) {
    const row = DB.users.get((params?.email || '').toLowerCase());
    return row ? [[{ id: row.id }]] : [[]];
  }
  if (norm.startsWith('SELECT id FROM type::thing')) {
    const ref = String(params?.id || '');
    if (ref.startsWith('organizations:') && DB.organizations.has(ref)) return [[{ id: ref }]];
    if (ref.startsWith('accounts:') && DB.accounts.has(ref)) return [[{ id: ref }]];
    return [[]];
  }
  if (norm.startsWith('SELECT org_id, role FROM organization_members')) {
    return [DB.organizationMembers.filter((m) => m.user_id === params?.user_id)];
  }
  if (norm.startsWith('SELECT account_id, role FROM account_members')) {
    return [DB.accountMembers.filter((m) => m.user_id === params?.user_id)];
  }
  if (norm.startsWith('CREATE users SET')) {
    userIdCounter += 1;
    const id = `users:user_${userIdCounter}`;
    const row = {
      id, email: params?.email, name: params?.name,
      password_hash: params?.password_hash, default_org_id: params?.org_id,
    };
    DB.users.set(String(params?.email || '').toLowerCase(), row);
    DB.userById.set(id, row);
    return [[row]];
  }
  if (norm.startsWith('CREATE type::thing')) {
    const id = String(params?.id || '');
    const row = { id, name: params?.name, tier: 'free' };
    if (id.startsWith('organizations:')) DB.organizations.set(id, row);
    else if (id.startsWith('accounts:')) DB.accounts.set(id, row);
    return [[row]];
  }
  if (norm.startsWith('CREATE organization_members')) {
    const row = { org_id: params?.org_id, user_id: params?.user_id, role: 'owner' };
    DB.organizationMembers.push(row);
    return [[row]];
  }
  if (norm.startsWith('CREATE account_members')) {
    const row = { account_id: params?.account_id, user_id: params?.user_id, role: 'owner' };
    DB.accountMembers.push(row);
    return [[row]];
  }
  return [];
}

async function seedUser(email: string, password: string, role: 'owner' | 'admin' | 'member' = 'owner') {
  userIdCounter += 1;
  const userId = `users:seed_${userIdCounter}`;
  const orgRef = 'organizations:metabob';
  const acctRef = 'accounts:metabob';
  const row = {
    id: userId, email: email.toLowerCase(), name: email,
    password_hash: await hashPassword(password), default_org_id: orgRef,
  };
  DB.users.set(email.toLowerCase(), row);
  DB.userById.set(userId, row);
  DB.organizationMembers.push({ user_id: userId, org_id: orgRef, role });
  DB.accountMembers.push({ user_id: userId, account_id: acctRef, role });
  if (!DB.organizations.has(orgRef)) DB.organizations.set(orgRef, { id: orgRef, name: 'Metabob' });
  if (!DB.accounts.has(acctRef)) DB.accounts.set(acctRef, { id: acctRef, name: 'Metabob' });
  return userId;
}

function ensureFailure(r: AuthResult): asserts r is Extract<AuthResult, { ok: false }> {
  if (r.ok) throw new Error('expected failure result, got success');
}
function ensureSuccess(r: AuthResult): asserts r is Extract<AuthResult, { ok: true }> {
  if (!r.ok) throw new Error(`expected success, got ${r.status} ${JSON.stringify(r.body)}`);
}

// =============================================================================
// Login tests
// =============================================================================

describe('loginWithPassword', () => {
  beforeEach(() => { DB = makeFreshDb(); userIdCounter = 0; setQueryFn(fakeQuery); });
  afterEach(() => { setQueryFn(null); });

  test('happy path: known user → 200 + valid JWT carrying org_id, account_id, role', async () => {
    await seedUser('alice@metabob.com', 'CorrectHorse9!');
    const result = await loginWithPassword({ email: 'alice@metabob.com', password: 'CorrectHorse9!' });
    ensureSuccess(result);
    expect(result.status).toBe(200);
    expect(result.body.user_id).toMatch(/^users:/);
    expect(result.body.org_id).toBe('organizations:metabob');
    expect(result.body.role).toBe('owner');
    expect(result.body.account_id).toBe('accounts:metabob');
    expect(typeof result.body.token).toBe('string');
    expect(result.body.token.length).toBeGreaterThan(20);

    const verified = await verifyToken(result.body.token);
    expect(verified.valid).toBe(true);
    expect(verified.user_id).toBe(result.body.user_id);
    expect(verified.org_id).toBe('organizations:metabob');
    expect(verified.account_id).toBe('accounts:metabob');
    expect(verified.role).toBe('owner');
  });

  test('email lookup is case-insensitive', async () => {
    await seedUser('bob@metabob.com', 'Sup3rS3cret!');
    const r = await loginWithPassword({ email: 'BOB@METABOB.COM', password: 'Sup3rS3cret!' });
    ensureSuccess(r);
    expect(r.status).toBe(200);
  });

  test('wrong password → 401 invalid_credentials', async () => {
    await seedUser('alice@metabob.com', 'CorrectHorse9!');
    const r = await loginWithPassword({ email: 'alice@metabob.com', password: 'WrongHorse9!' });
    ensureFailure(r);
    expect(r.status).toBe(401);
    expect(r.body.error).toBe('INVALID_CREDENTIALS');
  });

  test('unknown email → 401, response shape identical to wrong-password', async () => {
    const r = await loginWithPassword({ email: 'nobody@nope.com', password: 'AnyPassword9!' });
    ensureFailure(r);
    expect(r.status).toBe(401);
    expect(r.body.error).toBe('INVALID_CREDENTIALS');
    expect(r.body).not.toHaveProperty('token');
  });

  test('missing email → 400', async () => {
    const r = await loginWithPassword({ password: 'whatever' });
    ensureFailure(r); expect(r.status).toBe(400); expect(r.body.error).toBe('INVALID_INPUT');
  });

  test('missing password → 400', async () => {
    const r = await loginWithPassword({ email: 'alice@metabob.com' });
    ensureFailure(r); expect(r.status).toBe(400); expect(r.body.error).toBe('INVALID_INPUT');
  });

  test('non-object body → 400', async () => {
    const r = await loginWithPassword(null);
    ensureFailure(r); expect(r.status).toBe(400); expect(r.body.error).toBe('INVALID_INPUT');
  });

  test('invalid email format → 400', async () => {
    const r = await loginWithPassword({ email: 'not-an-email', password: 'whatever' });
    ensureFailure(r); expect(r.status).toBe(400); expect(r.body.error).toBe('INVALID_INPUT');
  });

  test('user with null password_hash → 401 (no info leak)', async () => {
    DB.users.set('legacy@metabob.com', {
      id: 'users:legacy', email: 'legacy@metabob.com',
      password_hash: null, default_org_id: 'organizations:metabob',
    });
    const r = await loginWithPassword({ email: 'legacy@metabob.com', password: 'AnyPassword9!' });
    ensureFailure(r); expect(r.status).toBe(401); expect(r.body.error).toBe('INVALID_CREDENTIALS');
  });

  test('user with org membership but no account_members row omits account_id', async () => {
    userIdCounter += 1;
    const userId = `users:noacct_${userIdCounter}`;
    const row = {
      id: userId, email: 'noacct@metabob.com',
      password_hash: await hashPassword('Pwd12345!'),
      default_org_id: 'organizations:metabob',
    };
    DB.users.set('noacct@metabob.com', row);
    DB.userById.set(userId, row);
    DB.organizationMembers.push({ user_id: userId, org_id: 'organizations:metabob', role: 'member' });

    const r = await loginWithPassword({ email: 'noacct@metabob.com', password: 'Pwd12345!' });
    ensureSuccess(r);
    expect(r.body.account_id).toBeUndefined();
    expect(r.body.role).toBe('member');
  });
});

// =============================================================================
// Signup tests
// =============================================================================

describe('signupWithPassword', () => {
  beforeEach(() => { DB = makeFreshDb(); userIdCounter = 0; setQueryFn(fakeQuery); });
  afterEach(() => { setQueryFn(null); });

  test('new user + new org happy path → 200 + JWT + persisted rows', async () => {
    const r = await signupWithPassword({
      email: 'charlie@cool.io', password: 'BrandNewPwd1!',
      name: 'Charlie', org_name: 'Cool Co',
    });
    ensureSuccess(r);
    expect(r.status).toBe(200);
    expect(r.body.user_id).toMatch(/^users:/);
    expect(r.body.org_id).toBe('organizations:cool_co');
    expect(r.body.account_id).toBe('accounts:cool_co');
    expect(r.body.role).toBe('owner');
    expect(typeof r.body.token).toBe('string');

    expect(DB.users.has('charlie@cool.io')).toBe(true);
    expect(DB.organizations.has('organizations:cool_co')).toBe(true);
    expect(DB.accounts.has('accounts:cool_co')).toBe(true);
    expect(DB.organizationMembers.some((m) => m.role === 'owner')).toBe(true);
    expect(DB.accountMembers.some((m) => m.role === 'owner')).toBe(true);

    const verified = await verifyToken(r.body.token);
    expect(verified.valid).toBe(true);
    expect(verified.org_id).toBe('organizations:cool_co');
    expect(verified.account_id).toBe('accounts:cool_co');
  });

  test('signup with invitation token → 501 (deferred)', async () => {
    const r = await signupWithPassword({
      email: 'dave@invited.com', password: 'BrandNewPwd1!',
      accept_invitation_token: 'inv_abc123',
    });
    ensureFailure(r); expect(r.status).toBe(501); expect(r.body.error).toBe('INVITATION_INVALID');
  });

  test('duplicate email → 409', async () => {
    await seedUser('eve@dup.com', 'AlreadyPwd1!');
    const r = await signupWithPassword({
      email: 'eve@dup.com', password: 'NewPwd9!', org_name: 'Eve LLC',
    });
    ensureFailure(r); expect(r.status).toBe(409); expect(r.body.error).toBe('EMAIL_TAKEN');
  });

  test('weak password → 400', async () => {
    const r = await signupWithPassword({
      email: 'frank@new.com', password: 'short', org_name: 'Frank LLC',
    });
    ensureFailure(r); expect(r.status).toBe(400); expect(r.body.error).toBe('WEAK_PASSWORD');
    expect((r.body.details as any).errors.length).toBeGreaterThan(0);
  });

  test('missing both org_name and invitation → 400', async () => {
    const r = await signupWithPassword({ email: 'gina@new.com', password: 'StrongPwd9!' });
    ensureFailure(r); expect(r.status).toBe(400); expect(r.body.error).toBe('NEEDS_INVITATION_OR_ORG');
  });

  test('invalid email → 400', async () => {
    const r = await signupWithPassword({
      email: 'not-an-email', password: 'StrongPwd9!', org_name: 'X',
    });
    ensureFailure(r); expect(r.status).toBe(400); expect(r.body.error).toBe('INVALID_INPUT');
  });

  test('org name collision → 409', async () => {
    DB.organizations.set('organizations:taken', { id: 'organizations:taken', name: 'Taken' });
    const r = await signupWithPassword({
      email: 'henry@new.com', password: 'StrongPwd9!', org_name: 'Taken',
    });
    ensureFailure(r); expect(r.status).toBe(409); expect(r.body.error).toBe('EMAIL_TAKEN');
  });

  test('signup → login round-trip', async () => {
    const signup = await signupWithPassword({
      email: 'ivy@cycle.com', password: 'StrongPwd9!', org_name: 'Cycle Inc',
    });
    ensureSuccess(signup);
    const login = await loginWithPassword({ email: 'ivy@cycle.com', password: 'StrongPwd9!' });
    ensureSuccess(login);
    expect(login.body.user_id).toBe(signup.body.user_id);
    expect(login.body.org_id).toBe('organizations:cycle_inc');
  });
});
