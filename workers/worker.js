/**
 * team-tasks-api on Cloudflare Workers + D1 — the cloud twin of server.js.
 *
 * Same routes, same status codes, same response shapes as the Express app in
 * the repo root; every SQL statement is copied from the controllers verbatim
 * (D1 speaks the same SQLite dialect). Two deliberate substitutions, both
 * because Workers have no Node runtime:
 *
 *   jsonwebtoken  ->  HS256 via WebCrypto (same header/payload/claims)
 *   bcryptjs      ->  PBKDF2-SHA256 via WebCrypto (bcrypt busts the free
 *                     plan's CPU budget; the stored format is self-describing)
 *
 * Deploy:  npx wrangler deploy          (see wrangler.toml)
 * Seed:    npx wrangler d1 execute team-tasks --remote --file=schema.sql
 */

const ALLOWED_ORIGINS = new Set([
  'https://ruti-maman.github.io',
  'http://localhost:4200',
  'http://127.0.0.1:4200',
  'http://localhost:4801',
]);

const JSON_HEADERS = { 'Content-Type': 'application/json; charset=utf-8' };

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin') || '';
    const cors = corsHeaders(origin);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors });
    }

    try {
      const response = await route(request, url, env);
      for (const [k, v] of Object.entries(cors)) response.headers.set(k, v);
      return response;
    } catch (err) {
      const body = JSON.stringify({ error: 'Internal error', detail: String(err && err.message) });
      return new Response(body, { status: 500, headers: { ...JSON_HEADERS, ...cors } });
    }
  },
};

function corsHeaders(origin) {
  const headers = {
    'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
  };
  if (ALLOWED_ORIGINS.has(origin)) headers['Access-Control-Allow-Origin'] = origin;
  return headers;
}

/* --------------------------------------------------------------- routing */

async function route(request, url, env) {
  const method = request.method.toUpperCase();
  const path = url.pathname.replace(/\/+$/, '') || '/';

  if (path === '/health' && method === 'GET') {
    return json({ status: 'ok' });
  }

  if (!path.startsWith('/api/')) {
    return json({ error: 'Not found' }, 404);
  }
  const seg = path.slice('/api/'.length).split('/').filter(Boolean);
  const body = method === 'POST' || method === 'PATCH' ? await safeJson(request) : {};

  /* ------ auth (register/login are the only unauthenticated endpoints) */
  if (seg[0] === 'auth') {
    if (seg[1] === 'register' && method === 'POST') return register(env, body);
    if (seg[1] === 'login' && method === 'POST') return login(env, body);
    if (seg[1] === 'me' && method === 'GET') {
      const user = await authenticate(request, env);
      if (!user) return json({ error: 'Missing token' }, 401);
      const row = await env.DB.prepare('SELECT id, name, email, role FROM users WHERE id = ?')
        .bind(user.id).first();
      return row ? json(row) : json({ error: 'User not found' }, 404);
    }
    return json({ error: 'Not found' }, 404);
  }

  const user = await authenticate(request, env);
  if (!user) return json({ error: 'Missing token' }, 401);

  /* ------------------------------------------------------------- teams */
  if (seg[0] === 'teams') {
    if (seg.length === 1 && method === 'GET') {
      const { results } = await env.DB.prepare(
        `SELECT t.*, (
           SELECT COUNT(*) FROM team_members tm WHERE tm.team_id = t.id
         ) as members_count
         FROM teams t
         JOIN team_members tm ON tm.team_id = t.id
         WHERE tm.user_id = ?
         GROUP BY t.id`).bind(user.id).all();
      return json(results);
    }
    if (seg.length === 1 && method === 'POST') {
      const { name, description } = body;
      if (!name) return json({ error: 'name required' }, 400);
      const info = await env.DB.prepare('INSERT INTO teams (name, description) VALUES (?, ?)')
        .bind(name, description ?? null).run();
      const teamId = info.meta.last_row_id;
      await env.DB.prepare('INSERT INTO team_members (team_id, user_id, role) VALUES (?,?,?)')
        .bind(teamId, user.id, 'owner').run();
      const team = await env.DB.prepare('SELECT * FROM teams WHERE id = ?').bind(teamId).first();
      return json(team, 201);
    }
    if (seg.length === 2 && method === 'DELETE') {
      const teamId = seg[1];
      const membership = await member(env, teamId, user.id);
      if (!membership) return json({ error: 'Not a team member' }, 403);
      const team = await env.DB.prepare('SELECT id FROM teams WHERE id = ?').bind(teamId).first();
      if (!team) return json({ error: 'Team not found' }, 404);
      await env.DB.prepare('DELETE FROM teams WHERE id = ?').bind(teamId).run();
      return empty();
    }
    if (seg.length === 2 && seg[1] && method === 'GET') {
      return json({ error: 'Not found' }, 404);
    }
    if (seg[2] === 'members') {
      const teamId = seg[1];
      if (method === 'GET') {
        const { results } = await env.DB.prepare(
          `SELECT u.id, u.name FROM team_members tm
           JOIN users u ON u.id = tm.user_id
           WHERE tm.team_id = ? ORDER BY u.name ASC`).bind(teamId).all();
        return json(results);
      }
      if (method === 'POST') {
        const { userId, role = 'member' } = body;
        if (!userId) return json({ error: 'userId required' }, 400);
        const membership = await member(env, teamId, user.id);
        if (!membership) return json({ error: 'Not a team member' }, 403);
        await env.DB.prepare('INSERT OR IGNORE INTO team_members (team_id, user_id, role) VALUES (?,?,?)')
          .bind(teamId, userId, role).run();
        return empty();
      }
      if (method === 'DELETE' && seg[3]) {
        const membership = await member(env, teamId, user.id);
        if (!membership) return json({ error: 'Not a team member' }, 403);
        const team = await env.DB.prepare('SELECT id FROM teams WHERE id = ?').bind(teamId).first();
        if (!team) return json({ error: 'Team not found' }, 404);
        await env.DB.prepare('DELETE FROM team_members WHERE team_id = ? AND user_id = ?')
          .bind(teamId, seg[3]).run();
        return empty();
      }
    }
  }

  /* ---------------------------------------------------------- projects */
  if (seg[0] === 'projects') {
    if (seg.length === 1 && method === 'GET') {
      const { results } = await env.DB.prepare(
        `SELECT p.* FROM projects p
         JOIN team_members tm ON tm.team_id = p.team_id
         WHERE tm.user_id = ?
         ORDER BY p.created_at DESC`).bind(user.id).all();
      return json(results);
    }
    if (seg.length === 1 && method === 'POST') {
      const { teamId, name, description } = body;
      if (!teamId || !name) return json({ error: 'teamId and name required' }, 400);
      const membership = await member(env, teamId, user.id);
      if (!membership) return json({ error: 'Not a team member' }, 403);
      const info = await env.DB.prepare('INSERT INTO projects (team_id, name, description) VALUES (?,?,?)')
        .bind(teamId, name, description ?? null).run();
      const project = await env.DB.prepare('SELECT * FROM projects WHERE id = ?')
        .bind(info.meta.last_row_id).first();
      return json(project, 201);
    }
    if (seg.length === 2 && method === 'PATCH') {
      const projectId = seg[1];
      const existing = await env.DB.prepare('SELECT * FROM projects WHERE id = ?').bind(projectId).first();
      if (!existing) return json({ error: 'Project not found' }, 404);
      const membership = await env.DB.prepare(
        `SELECT 1 AS x FROM team_members tm JOIN projects p ON p.team_id = tm.team_id
         WHERE p.id = ? AND tm.user_id = ?`).bind(projectId, user.id).first();
      if (!membership) return json({ error: 'Not a team member' }, 403);
      const { name, description, status } = body;
      if (name === undefined && description === undefined && status === undefined) {
        return json({ error: 'Nothing to update' }, 400);
      }
      await env.DB.prepare('UPDATE projects SET name = ?, description = ?, status = ? WHERE id = ?')
        .bind(name ?? existing.name, description ?? existing.description, status ?? existing.status, projectId)
        .run();
      const updated = await env.DB.prepare('SELECT * FROM projects WHERE id = ?').bind(projectId).first();
      return json(updated);
    }
    if (seg.length === 2 && method === 'DELETE') {
      const projectId = seg[1];
      const existing = await env.DB.prepare('SELECT id, team_id FROM projects WHERE id = ?')
        .bind(projectId).first();
      if (!existing) return json({ error: 'Project not found' }, 404);
      const membership = await member(env, existing.team_id, user.id);
      if (!membership) return json({ error: 'Not a team member' }, 403);
      await env.DB.prepare('DELETE FROM projects WHERE id = ?').bind(projectId).run();
      return empty();
    }
  }

  /* ------------------------------------------------------------- tasks */
  if (seg[0] === 'tasks') {
    if (seg.length === 1 && method === 'GET') {
      const projectId = url.searchParams.get('projectId');
      if (projectId) {
        const membership = await projectMember(env, projectId, user.id);
        if (!membership) return json({ error: 'Not a member of the project team' }, 403);
        const { results } = await env.DB.prepare(
          'SELECT * FROM tasks WHERE project_id = ? ORDER BY order_index ASC, created_at DESC')
          .bind(projectId).all();
        return json(results);
      }
      const { results } = await env.DB.prepare(
        `SELECT t.* FROM tasks t
         JOIN projects p ON p.id = t.project_id
         JOIN team_members tm ON tm.team_id = p.team_id
         WHERE tm.user_id = ?
         ORDER BY t.created_at DESC`).bind(user.id).all();
      return json(results);
    }
    if (seg.length === 1 && method === 'POST') {
      const { projectId, title, description, status = 'todo', priority = 'normal',
              assigneeId = null, dueDate = null, orderIndex = 0 } = body;
      if (!projectId || !title) return json({ error: 'projectId and title required' }, 400);
      const membership = await projectMember(env, projectId, user.id);
      if (!membership) return json({ error: 'Not a member of the project team' }, 403);
      const info = await env.DB.prepare(
        `INSERT INTO tasks (project_id, title, description, status, priority, assignee_id, due_date, order_index)
         VALUES (?,?,?,?,?,?,?,?)`)
        .bind(projectId, title, description ?? null, status, priority, assigneeId, dueDate, orderIndex)
        .run();
      const task = await env.DB.prepare('SELECT * FROM tasks WHERE id = ?')
        .bind(info.meta.last_row_id).first();
      return json(task, 201);
    }
    if (seg.length === 2 && (method === 'PATCH' || method === 'DELETE')) {
      const id = seg[1];
      const taskRow = await env.DB.prepare(
        `SELECT t.*, p.team_id FROM tasks t
         JOIN projects p ON p.id = t.project_id
         WHERE t.id = ?`).bind(id).first();
      if (!taskRow) return json({ error: 'Task not found' }, 404);
      const membership = await member(env, taskRow.team_id, user.id);
      if (!membership) {
        const which = method === 'PATCH' ? 'modify' : 'delete';
        return json({ error: `Not authorized to ${which} this task` }, 403);
      }
      if (method === 'DELETE') {
        await env.DB.prepare('DELETE FROM tasks WHERE id = ?').bind(id).run();
        return empty();
      }
      const allowed = ['title', 'description', 'status', 'priority', 'assignee_id', 'due_date', 'order_index'];
      const fields = [];
      const values = [];
      for (const key of allowed) {
        if (key in body) {
          fields.push(`${key} = ?`);
          values.push(body[key]);
        }
      }
      if (fields.length === 0) return json({ error: 'No valid fields' }, 400);
      // the Express build relies on a trigger for this; here it is explicit
      fields.push(`updated_at = datetime('now')`);
      values.push(id);
      await env.DB.prepare(`UPDATE tasks SET ${fields.join(', ')} WHERE id = ?`).bind(...values).run();
      const task = await env.DB.prepare('SELECT * FROM tasks WHERE id = ?').bind(id).first();
      return json(task);
    }
  }

  /* ---------------------------------------------------------- comments */
  if (seg[0] === 'comments') {
    if (method === 'GET') {
      const taskId = url.searchParams.get('taskId');
      if (!taskId) return json({ error: 'taskId required' }, 400);
      const membership = await taskMember(env, taskId, user.id);
      if (!membership) return json({ error: 'Not authorized to view comments for this task' }, 403);
      const { results } = await env.DB.prepare(
        `SELECT c.*, u.name as author_name FROM comments c
         JOIN users u ON u.id = c.user_id
         WHERE task_id = ? ORDER BY c.created_at ASC`).bind(taskId).all();
      return json(results);
    }
    if (method === 'POST') {
      const { taskId, body: commentBody } = body;
      if (!taskId || !commentBody) return json({ error: 'taskId and body required' }, 400);
      const membership = await taskMember(env, taskId, user.id);
      if (!membership) return json({ error: 'Not authorized to comment on this task' }, 403);
      const info = await env.DB.prepare('INSERT INTO comments (task_id, user_id, body) VALUES (?,?,?)')
        .bind(taskId, user.id, commentBody).run();
      const row = await env.DB.prepare('SELECT * FROM comments WHERE id = ?')
        .bind(info.meta.last_row_id).first();
      return json(row, 201);
    }
  }

  /* ------------------------------------------------------------- users */
  if (seg[0] === 'users' && method === 'GET') {
    const { results } = await env.DB.prepare('SELECT id, name FROM users ORDER BY name ASC').all();
    return json(results);
  }

  return json({ error: 'Not found' }, 404);
}

/* ------------------------------------------------------------------ auth */

async function register(env, body) {
  const { name, email, password } = body;
  if (!name || !email || !password) return json({ error: 'name, email, password required' }, 400);
  const existing = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
  if (existing) return json({ error: 'Email already registered' }, 409);
  const hash = await hashPassword(password);
  const info = await env.DB.prepare('INSERT INTO users (name, email, password_hash) VALUES (?,?,?)')
    .bind(name, email, hash).run();
  const user = await env.DB.prepare('SELECT id, name, email, role FROM users WHERE id = ?')
    .bind(info.meta.last_row_id).first();
  const token = await signToken(user, env);
  return json({ user, token }, 201);
}

async function login(env, body) {
  const { email, password } = body;
  if (!email || !password) return json({ error: 'email, password required' }, 400);
  const user = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first();
  if (!user) return json({ error: 'Invalid credentials' }, 401);
  const ok = await verifyPassword(password, user.password_hash);
  if (!ok) return json({ error: 'Invalid credentials' }, 401);
  const token = await signToken({ id: user.id, email: user.email, role: user.role, name: user.name }, env);
  return json({ user: { id: user.id, name: user.name, email: user.email, role: user.role }, token });
}

async function authenticate(request, env) {
  const header = request.headers.get('Authorization') || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return null;
  return verifyToken(token, env);
}

/* JWT HS256 with the same claims signToken() issues in middleware/auth.js */

async function signToken(user, env) {
  const now = Math.floor(Date.now() / 1000);
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payload = b64url(JSON.stringify({
    id: user.id, email: user.email, role: user.role, name: user.name,
    iat: now, exp: now + 7 * 24 * 60 * 60,
  }));
  const signature = await hmac(`${header}.${payload}`, env.JWT_SECRET || 'dev_secret');
  return `${header}.${payload}.${signature}`;
}

async function verifyToken(token, env) {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const expected = await hmac(`${parts[0]}.${parts[1]}`, env.JWT_SECRET || 'dev_secret');
  if (!timingSafeEqual(expected, parts[2])) return null;
  try {
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
    if (typeof payload.exp === 'number' && payload.exp + 5 < Date.now() / 1000) return null;
    return payload;
  } catch {
    return null;
  }
}

async function hmac(data, secret) {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return b64urlBytes(new Uint8Array(sig));
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/* PBKDF2-SHA256, stored as pbkdf2$<iterations>$<salt>$<hash> (all base64url) */

const PBKDF2_ITERATIONS = 100000;

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const bits = await pbkdf2(password, salt, PBKDF2_ITERATIONS);
  return `pbkdf2$${PBKDF2_ITERATIONS}$${b64urlBytes(salt)}$${b64urlBytes(bits)}`;
}

async function verifyPassword(password, stored) {
  const parts = (stored || '').split('$');
  if (parts[0] !== 'pbkdf2' || parts.length !== 4) return false;
  const iterations = parseInt(parts[1], 10);
  const salt = bytesFromB64url(parts[2]);
  const bits = await pbkdf2(password, salt, iterations);
  return timingSafeEqual(b64urlBytes(bits), parts[3]);
}

async function pbkdf2(password, salt, iterations) {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, 256);
  return new Uint8Array(bits);
}

/* -------------------------------------------------------------- helpers */

async function member(env, teamId, userId) {
  return env.DB.prepare('SELECT 1 AS x FROM team_members WHERE team_id = ? AND user_id = ?')
    .bind(teamId, userId).first();
}

async function projectMember(env, projectId, userId) {
  return env.DB.prepare(
    `SELECT 1 AS x FROM team_members tm
     JOIN projects p ON p.team_id = tm.team_id
     WHERE p.id = ? AND tm.user_id = ?`).bind(projectId, userId).first();
}

async function taskMember(env, taskId, userId) {
  return env.DB.prepare(
    `SELECT 1 AS x FROM team_members tm
     JOIN projects p ON p.team_id = tm.team_id
     JOIN tasks t ON t.project_id = p.id
     WHERE t.id = ? AND tm.user_id = ?`).bind(taskId, userId).first();
}

async function safeJson(request) {
  try {
    return (await request.json()) ?? {};
  } catch {
    return {};
  }
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body ?? null), { status, headers: { ...JSON_HEADERS } });
}

function empty() {
  return new Response(null, { status: 204 });
}

function b64url(str) {
  return b64urlBytes(new TextEncoder().encode(str));
}

function b64urlBytes(bytes) {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function bytesFromB64url(str) {
  const bin = atob(str.replace(/-/g, '+').replace(/_/g, '/'));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
