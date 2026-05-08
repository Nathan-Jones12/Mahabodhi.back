import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt, { SignOptions } from 'jsonwebtoken';
import dotenv from 'dotenv';
import { RowDataPacket, ResultSetHeader } from 'mysql2';
import { pool, pingDb } from './db';
import { moderate, moderateMany } from './moderation';

dotenv.config();

const app = express();
const PORT = Number(process.env.PORT ?? 3000);
const JWT_SECRET = process.env.JWT_SECRET ?? 'dev-only-insecure-secret';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN ?? '7d';

const corsOriginEnv = process.env.CORS_ORIGIN ?? '*';
const allowList =
  corsOriginEnv === '*'
    ? null
    : corsOriginEnv.split(',').map((s) => s.trim()).filter(Boolean);

const corsOptions: cors.CorsOptions = {
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (allowList === null) return cb(null, true);
    if (allowList.includes(origin)) return cb(null, true);
    if (/^https:\/\/([a-z0-9-]+--)?mahabodhi\.netlify\.app$/.test(origin)) {
      return cb(null, true);
    }
    return cb(new Error(`origin_not_allowed:${origin}`));
  },
  credentials: false,
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

app.use((_req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});
app.use(express.json({ limit: '1mb' }));

// ---------- types ----------
type Stage = 'vitarka' | 'vicara' | 'ananda' | 'asmita';
type JhanaDepth = 'first' | 'second' | 'third' | 'fourth';

declare global {
  namespace Express {
    interface Request {
      userId?: number;
    }
  }
}

type AuthedRequest = Request & { userId: number };

interface UserRow extends RowDataPacket {
  id: number;
  username: string;
  email: string;
  password_hash: string;
  display_name: string | null;
  created_at: Date;
}

// ---------- auth middleware ----------
function authRequired(req: Request, res: Response, next: NextFunction) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'missing_token' });
  }
  const token = header.slice('Bearer '.length);
  try {
    const payload = jwt.verify(token, JWT_SECRET) as unknown as { sub: number };
    (req as AuthedRequest).userId = payload.sub;
    next();
  } catch {
    return res.status(401).json({ error: 'invalid_token' });
  }
}

function asyncHandler<T extends Request = Request>(
  fn: (req: T, res: Response, next: NextFunction) => Promise<unknown>
) {
  return (req: T, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

function signToken(userId: number): string {
  return jwt.sign({ sub: userId }, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN,
  } as SignOptions);
}

// ---------- health ----------
app.get('/api/health', asyncHandler(async (_req, res) => {
  await pingDb();
  res.json({ ok: true });
}));

// ---------- auth ----------
app.post('/api/auth/register', asyncHandler(async (req, res) => {
  const { username, email, password, display_name } = req.body ?? {};
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'username_email_password_required' });
  }
  if (typeof password !== 'string' || password.length < 6) {
    return res.status(400).json({ error: 'password_too_short' });
  }
  const modCheck = await moderateMany({ username, display_name });
  if (!modCheck.ok) {
    return res.status(400).json({ error: 'content_blocked', reason: modCheck.reason });
  }
  const hash = await bcrypt.hash(password, 10);
  try {
    const [result] = await pool.execute<ResultSetHeader>(
      'INSERT INTO users (username, email, password_hash, display_name) VALUES (?, ?, ?, ?)',
      [username, email, hash, display_name ?? username]
    );
    const userId = result.insertId;
    const token = signToken(userId);
    res.status(201).json({
      token,
      user: { id: userId, username, email, display_name: display_name ?? username },
    });
  } catch (err: unknown) {
    const code = (err as { code?: string }).code;
    if (code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'user_exists' });
    }
    throw err;
  }
}));

app.post('/api/auth/login', asyncHandler(async (req, res) => {
  const { email, password } = req.body ?? {};
  if (!email || !password) return res.status(400).json({ error: 'email_password_required' });

  const [rows] = await pool.execute<UserRow[]>(
    'SELECT * FROM users WHERE email = ? LIMIT 1',
    [email]
  );
  const user = rows[0];
  if (!user) return res.status(401).json({ error: 'invalid_credentials' });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'invalid_credentials' });

  const token = signToken(user.id);
  res.json({
    token,
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      display_name: user.display_name,
    },
  });
}));

app.get('/api/auth/me', authRequired, asyncHandler(async (req, res) => {
  const [rows] = await pool.execute<UserRow[]>(
    'SELECT id, username, email, display_name, created_at FROM users WHERE id = ? LIMIT 1',
    [req.userId!]
  );
  const user = rows[0];
  if (!user) return res.status(404).json({ error: 'not_found' });

  // current stage = most recently marked
  const [stageRows] = await pool.execute<RowDataPacket[]>(
    'SELECT stage, marked_at FROM meditation_stages WHERE user_id = ? ORDER BY marked_at DESC LIMIT 1',
    [req.userId!]
  );

  // total lifetime meditation seconds
  const [totalRows] = await pool.execute<RowDataPacket[]>(
    'SELECT COALESCE(SUM(duration_seconds), 0) AS total FROM meditation_sessions WHERE user_id = ?',
    [req.userId!]
  );

  res.json({
    user,
    current_stage: stageRows[0]?.stage ?? null,
    total_meditation_seconds: Number(totalRows[0]?.total ?? 0),
  });
}));

// ---------- stages ----------
const STAGES: Stage[] = ['vitarka', 'vicara', 'ananda', 'asmita'];

app.get('/api/stages', authRequired, asyncHandler(async (req, res) => {
  const [rows] = await pool.execute<RowDataPacket[]>(
    'SELECT id, stage, marked_at, notes FROM meditation_stages WHERE user_id = ? ORDER BY marked_at DESC',
    [req.userId!]
  );
  res.json({ history: rows, current: rows[0]?.stage ?? null });
}));

app.post('/api/stages', authRequired, asyncHandler(async (req, res) => {
  const { stage, notes } = req.body ?? {};
  if (!STAGES.includes(stage)) return res.status(400).json({ error: 'invalid_stage' });

  const [result] = await pool.execute<ResultSetHeader>(
    'INSERT INTO meditation_stages (user_id, stage, notes) VALUES (?, ?, ?)',
    [req.userId!,stage, notes ?? null]
  );
  res.status(201).json({ id: result.insertId, stage, notes: notes ?? null });
}));

// ---------- sessions ----------
const JHANA: JhanaDepth[] = ['first', 'second', 'third', 'fourth'];

app.get('/api/sessions', authRequired, asyncHandler(async (req, res) => {
  const [rows] = await pool.execute<RowDataPacket[]>(
    'SELECT id, concept, duration_seconds, jhana_depth, started_at FROM meditation_sessions WHERE user_id = ? ORDER BY started_at DESC LIMIT 200',
    [req.userId!]
  );
  res.json({ sessions: rows });
}));

app.post('/api/sessions', authRequired, asyncHandler(async (req, res) => {
  const { concept, duration_seconds, jhana_depth } = req.body ?? {};
  const dur = Number(duration_seconds);
  if (!Number.isFinite(dur) || dur < 0) {
    return res.status(400).json({ error: 'duration_required' });
  }
  if (jhana_depth && !JHANA.includes(jhana_depth)) {
    return res.status(400).json({ error: 'invalid_jhana_depth' });
  }
  const conceptText = typeof concept === 'string' ? concept.slice(0, 100) : null;

  const [result] = await pool.execute<ResultSetHeader>(
    'INSERT INTO meditation_sessions (user_id, concept, duration_seconds, jhana_depth) VALUES (?, ?, ?, ?)',
    [req.userId!,conceptText, Math.floor(dur), jhana_depth ?? null]
  );
  res.status(201).json({ id: result.insertId });
}));

// ---------- journal ----------
app.get('/api/journal', authRequired, asyncHandler(async (req, res) => {
  const [rows] = await pool.execute<RowDataPacket[]>(
    'SELECT id, title, body, concept_tag, created_at, updated_at FROM journal_entries WHERE user_id = ? ORDER BY created_at DESC',
    [req.userId!]
  );
  res.json({ entries: rows });
}));

app.post('/api/journal', authRequired, asyncHandler(async (req, res) => {
  const { title, body, concept_tag } = req.body ?? {};
  if (!body || typeof body !== 'string') {
    return res.status(400).json({ error: 'body_required' });
  }
  const [result] = await pool.execute<ResultSetHeader>(
    'INSERT INTO journal_entries (user_id, title, body, concept_tag) VALUES (?, ?, ?, ?)',
    [req.userId!,title ?? null, body, concept_tag ?? null]
  );
  res.status(201).json({ id: result.insertId });
}));

app.patch('/api/journal/:id', authRequired, asyncHandler(async (req, res) => {
  const id = Number(req.params.id);
  const { title, body, concept_tag } = req.body ?? {};
  const [result] = await pool.execute<ResultSetHeader>(
    'UPDATE journal_entries SET title = COALESCE(?, title), body = COALESCE(?, body), concept_tag = COALESCE(?, concept_tag) WHERE id = ? AND user_id = ?',
    [title ?? null, body ?? null, concept_tag ?? null, id, req.userId!]
  );
  if (result.affectedRows === 0) return res.status(404).json({ error: 'not_found' });
  res.json({ ok: true });
}));

app.delete('/api/journal/:id', authRequired, asyncHandler(async (req, res) => {
  const id = Number(req.params.id);
  const [result] = await pool.execute<ResultSetHeader>(
    'DELETE FROM journal_entries WHERE id = ? AND user_id = ?',
    [id, req.userId!]
  );
  if (result.affectedRows === 0) return res.status(404).json({ error: 'not_found' });
  res.json({ ok: true });
}));

// ---------- forum ----------
app.get('/api/forum/posts', asyncHandler(async (req, res) => {
  const tag = typeof req.query.tag === 'string' ? req.query.tag : null;
  const baseSql = `
    SELECT p.id, p.title, p.body, p.concept_tag, p.created_at, p.updated_at,
           u.id AS user_id, u.username, u.display_name,
           (SELECT stage FROM meditation_stages s WHERE s.user_id = u.id ORDER BY s.marked_at DESC LIMIT 1) AS user_stage,
           (SELECT COUNT(*) FROM forum_likes l WHERE l.post_id = p.id) AS like_count,
           (SELECT COUNT(*) FROM forum_replies r WHERE r.post_id = p.id) AS reply_count
    FROM forum_posts p
    JOIN users u ON u.id = p.user_id
  `;
  const [rows] = tag
    ? await pool.execute<RowDataPacket[]>(
        baseSql + ' WHERE p.concept_tag = ? ORDER BY p.created_at DESC LIMIT 200',
        [tag]
      )
    : await pool.execute<RowDataPacket[]>(
        baseSql + ' ORDER BY p.created_at DESC LIMIT 200'
      );
  res.json({ posts: rows });
}));

app.get('/api/forum/posts/:id', asyncHandler(async (req, res) => {
  const id = Number(req.params.id);
  const [postRows] = await pool.execute<RowDataPacket[]>(
    `SELECT p.id, p.title, p.body, p.concept_tag, p.created_at, p.updated_at,
            u.id AS user_id, u.username, u.display_name,
            (SELECT stage FROM meditation_stages s WHERE s.user_id = u.id ORDER BY s.marked_at DESC LIMIT 1) AS user_stage,
            (SELECT COUNT(*) FROM forum_likes l WHERE l.post_id = p.id) AS like_count
     FROM forum_posts p
     JOIN users u ON u.id = p.user_id
     WHERE p.id = ? LIMIT 1`,
    [id]
  );
  const post = postRows[0];
  if (!post) return res.status(404).json({ error: 'not_found' });

  const [replyRows] = await pool.execute<RowDataPacket[]>(
    `SELECT r.id, r.body, r.created_at,
            u.id AS user_id, u.username, u.display_name,
            (SELECT stage FROM meditation_stages s WHERE s.user_id = u.id ORDER BY s.marked_at DESC LIMIT 1) AS user_stage
     FROM forum_replies r
     JOIN users u ON u.id = r.user_id
     WHERE r.post_id = ?
     ORDER BY r.created_at ASC`,
    [id]
  );
  res.json({ post, replies: replyRows });
}));

app.post('/api/forum/posts', authRequired, asyncHandler(async (req, res) => {
  const { title, body, concept_tag } = req.body ?? {};
  if (!title || !body) return res.status(400).json({ error: 'title_and_body_required' });
  const modCheck = await moderateMany({ title, body, concept_tag });
  if (!modCheck.ok) {
    return res.status(400).json({ error: 'content_blocked', reason: modCheck.reason });
  }
  const [result] = await pool.execute<ResultSetHeader>(
    'INSERT INTO forum_posts (user_id, title, body, concept_tag) VALUES (?, ?, ?, ?)',
    [req.userId!,title, body, concept_tag ?? null]
  );
  res.status(201).json({ id: result.insertId });
}));

app.patch('/api/forum/posts/:id', authRequired, asyncHandler(async (req, res) => {
  const id = Number(req.params.id);
  const { title, body, concept_tag } = req.body ?? {};
  const modCheck = await moderateMany({ title, body, concept_tag });
  if (!modCheck.ok) {
    return res.status(400).json({ error: 'content_blocked', reason: modCheck.reason });
  }
  const [result] = await pool.execute<ResultSetHeader>(
    'UPDATE forum_posts SET title = COALESCE(?, title), body = COALESCE(?, body), concept_tag = COALESCE(?, concept_tag) WHERE id = ? AND user_id = ?',
    [title ?? null, body ?? null, concept_tag ?? null, id, req.userId!]
  );
  if (result.affectedRows === 0) return res.status(404).json({ error: 'not_found_or_forbidden' });
  res.json({ ok: true });
}));

app.delete('/api/forum/posts/:id', authRequired, asyncHandler(async (req, res) => {
  const id = Number(req.params.id);
  const [result] = await pool.execute<ResultSetHeader>(
    'DELETE FROM forum_posts WHERE id = ? AND user_id = ?',
    [id, req.userId!]
  );
  if (result.affectedRows === 0) return res.status(404).json({ error: 'not_found_or_forbidden' });
  res.json({ ok: true });
}));

app.post('/api/forum/posts/:id/replies', authRequired, asyncHandler(async (req, res) => {
  const id = Number(req.params.id);
  const { body } = req.body ?? {};
  if (!body) return res.status(400).json({ error: 'body_required' });
  const modCheck = await moderate(body);
  if (!modCheck.ok) {
    return res.status(400).json({ error: 'content_blocked', reason: modCheck.reason });
  }
  const [result] = await pool.execute<ResultSetHeader>(
    'INSERT INTO forum_replies (post_id, user_id, body) VALUES (?, ?, ?)',
    [id, req.userId!,body]
  );
  res.status(201).json({ id: result.insertId });
}));

app.post('/api/forum/posts/:id/like', authRequired, asyncHandler(async (req, res) => {
  const id = Number(req.params.id);
  // toggle: try insert, if duplicate then delete
  try {
    await pool.execute<ResultSetHeader>(
      'INSERT INTO forum_likes (post_id, user_id) VALUES (?, ?)',
      [id, req.userId!]
    );
    return res.json({ liked: true });
  } catch (err: unknown) {
    const code = (err as { code?: string }).code;
    if (code === 'ER_DUP_ENTRY') {
      await pool.execute<ResultSetHeader>(
        'DELETE FROM forum_likes WHERE post_id = ? AND user_id = ?',
        [id, req.userId!]
      );
      return res.json({ liked: false });
    }
    throw err;
  }
}));

// ---------- error handler ----------
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error('[error]', err);
  res.status(500).json({ error: 'internal_error', message: err.message });
});

// ---------- start ----------
app.listen(PORT, async () => {
  console.log(`[mahabodhi-backend] listening on :${PORT}`);
  try {
    await pingDb();
    console.log('[mahabodhi-backend] mysql ok');
  } catch (err) {
    console.error('[mahabodhi-backend] mysql connection failed', err);
  }
});
