const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'mkontakt-secret-change-me';

app.use(express.json({ limit: '5mb' }));
app.use(express.static(path.join(__dirname, 'public')));

/* ==================== DATABASE ==================== */
const db = new Database('database.db');
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    nick TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    mplus INTEGER DEFAULT 0,
    verified INTEGER DEFAULT 0,
    online INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (strftime('%s','now'))
  );

  CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    author_id INTEGER NOT NULL,
    text TEXT NOT NULL,
    banner INTEGER DEFAULT 0,
    likes INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (strftime('%s','now')),
    FOREIGN KEY(author_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS post_likes (
    user_id INTEGER NOT NULL,
    post_id INTEGER NOT NULL,
    PRIMARY KEY(user_id, post_id)
  );

  CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL,
    author_id INTEGER NOT NULL,
    text TEXT NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s','now'))
  );

  CREATE TABLE IF NOT EXISTS friends (
    user_id INTEGER NOT NULL,
    friend_id INTEGER NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s','now')),
    PRIMARY KEY(user_id, friend_id)
  );

  CREATE TABLE IF NOT EXISTS chats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user1_id INTEGER NOT NULL,
    user2_id INTEGER NOT NULL,
    UNIQUE(user1_id, user2_id)
  );

  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id INTEGER NOT NULL,
    from_id INTEGER NOT NULL,
    text TEXT NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s','now')),
    FOREIGN KEY(chat_id) REFERENCES chats(id)
  );

  CREATE TABLE IF NOT EXISTS clans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    tag TEXT NOT NULL,
    owner_id INTEGER NOT NULL,
    banner INTEGER DEFAULT 1,
    points INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (strftime('%s','now'))
  );

  CREATE TABLE IF NOT EXISTS clan_members (
    clan_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    role TEXT DEFAULT 'member',
    PRIMARY KEY(clan_id, user_id)
  );

  CREATE TABLE IF NOT EXISTS calls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_id INTEGER NOT NULL,
    to_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s','now'))
  );

  CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    by_id INTEGER NOT NULL,
    text TEXT NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s','now'))
  );
`);

/* Seed admin if empty */
const userCount = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
if (userCount === 0) {
  const hash = bcrypt.hashSync('admin123', 10);
  db.prepare(`INSERT INTO users (name, nick, password, role, mplus, verified) 
    VALUES (?, ?, ?, ?, 1, 1)`).run('Владелец', '@owner', hash, 'owner');
  console.log('✅ Создан админ: логин @owner пароль admin123');
}

/* ==================== HELPERS ==================== */
function logAction(userId, text) {
  db.prepare('INSERT INTO logs (by_id, text) VALUES (?, ?)').run(userId, text);
}

function auth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Не авторизован' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Токен недействителен' });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    const user = db.prepare('SELECT role FROM users WHERE id = ?').get(req.user.id);
    if (!user || !roles.includes(user.role)) {
      return res.status(403).json({ error: 'Нет прав' });
    }
    next();
  };
}

/* ==================== AUTH ==================== */
app.post('/api/register', (req, res) => {
  const { name, nick, password } = req.body;
  if (!name || !nick || !password) return res.status(400).json({ error: 'Заполни все поля' });
  if (password.length < 4) return res.status(400).json({ error: 'Пароль минимум 4 символа' });

  const finalNick = nick.startsWith('@') ? nick : '@' + nick;
  const exists = db.prepare('SELECT id FROM users WHERE nick = ?').get(finalNick);
  if (exists) return res.status(400).json({ error: 'Ник занят' });

  const hash = bcrypt.hashSync(password, 10);
  const info = db.prepare('INSERT INTO users (name, nick, password) VALUES (?, ?, ?)')
    .run(name, finalNick, hash);
  const token = jwt.sign({ id: info.lastInsertRowid }, JWT_SECRET);
  res.json({ token, userId: info.lastInsertRowid });
});

app.post('/api/login', (req, res) => {
  const { nick, password } = req.body;
  if (!nick || !password) return res.status(400).json({ error: 'Заполни поля' });
  const finalNick = nick.startsWith('@') ? nick : '@' + nick;
  const user = db.prepare('SELECT * FROM users WHERE nick = ?').get(finalNick);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(400).json({ error: 'Неверный логин или пароль' });
  }
  db.prepare('UPDATE users SET online = 1 WHERE id = ?').run(user.id);
  const token = jwt.sign({ id: user.id }, JWT_SECRET);
  res.json({ token, userId: user.id });
});

app.post('/api/logout', auth, (req, res) => {
  db.prepare('UPDATE users SET online = 0 WHERE id = ?').run(req.user.id);
  res.json({ ok: true });
});

app.get('/api/me', auth, (req, res) => {
  const user = db.prepare('SELECT id, name, nick, role, mplus, verified, online FROM users WHERE id = ?').get(req.user.id);
  res.json(user);
});

/* ==================== USERS ==================== */
app.get('/api/users', auth, (req, res) => {
  const users = db.prepare('SELECT id, name, nick, role, mplus, verified, online FROM users').all();
  res.json(users);
});

/* ==================== POSTS ==================== */
app.get('/api/posts', auth, (req, res) => {
  const posts = db.prepare(`
    SELECT p.*, u.name as author_name, u.nick as author_nick, u.mplus, u.verified, u.role
    FROM posts p JOIN users u ON p.author_id = u.id
    ORDER BY p.created_at DESC LIMIT 100
  `).all();
  const likes = db.prepare('SELECT post_id FROM post_likes WHERE user_id = ?').all(req.user.id);
  const likedSet = new Set(likes.map(l => l.post_id));
  posts.forEach(p => p.liked = likedSet.has(p.id));
  res.json(posts);
});

app.post('/api/posts', auth, (req, res) => {
  const { text, banner } = req.body;
  if (!text?.trim()) return res.status(400).json({ error: 'Пустой пост' });
  const user = db.prepare('SELECT mplus FROM users WHERE id = ?').get(req.user.id);
  if (banner && !user.mplus) return res.status(403).json({ error: 'Анимированные баннеры только для M+' });
  const info = db.prepare('INSERT INTO posts (author_id, text, banner) VALUES (?, ?, ?)')
    .run(req.user.id, text, banner ? 1 : 0);
  res.json({ id: info.lastInsertRowid });
});

app.delete('/api/posts/:id', auth, (req, res) => {
  const post = db.prepare('SELECT * FROM posts WHERE id = ?').get(req.params.id);
  if (!post) return res.status(404).json({ error: 'Пост не найден' });
  const user = db.prepare('SELECT role FROM users WHERE id = ?').get(req.user.id);
  if (post.author_id !== req.user.id && !['owner', 'admin', 'moderator'].includes(user.role)) {
    return res.status(403).json({ error: 'Нет прав' });
  }
  db.prepare('DELETE FROM posts WHERE id = ?').run(req.params.id);
  db.prepare('DELETE FROM post_likes WHERE post_id = ?').run(req.params.id);
  db.prepare('DELETE FROM comments WHERE post_id = ?').run(req.params.id);
  logAction(req.user.id, `Удалён пост #${req.params.id}`);
  res.json({ ok: true });
});

app.post('/api/posts/:id/like', auth, (req, res) => {
  const postId = req.params.id;
  const existing = db.prepare('SELECT 1 FROM post_likes WHERE user_id = ? AND post_id = ?')
    .get(req.user.id, postId);
  if (existing) {
    db.prepare('DELETE FROM post_likes WHERE user_id = ? AND post_id = ?').run(req.user.id, postId);
    db.prepare('UPDATE posts SET likes = likes - 1 WHERE id = ?').run(postId);
    res.json({ liked: false });
  } else {
    db.prepare('INSERT INTO post_likes (user_id, post_id) VALUES (?, ?)').run(req.user.id, postId);
    db.prepare('UPDATE posts SET likes = likes + 1 WHERE id = ?').run(postId);
    res.json({ liked: true });
  }
});

/* Comments */
app.get('/api/posts/:id/comments', auth, (req, res) => {
  const comments = db.prepare(`
    SELECT c.*, u.name as author_name FROM comments c
    JOIN users u ON c.author_id = u.id
    WHERE c.post_id = ? ORDER BY c.created_at ASC
  `).all(req.params.id);
  res.json(comments);
});

app.post('/api/posts/:id/comments', auth, (req, res) => {
  const { text } = req.body;
  if (!text?.trim()) return res.status(400).json({ error: 'Пусто' });
  db.prepare('INSERT INTO comments (post_id, author_id, text) VALUES (?, ?, ?)')
    .run(req.params.id, req.user.id, text);
  res.json({ ok: true });
});

/* ==================== FRIENDS ==================== */
app.get('/api/friends', auth, (req, res) => {
  const friends = db.prepare(`
    SELECT u.id, u.name, u.nick, u.mplus, u.verified, u.online FROM friends f
    JOIN users u ON f.friend_id = u.id WHERE f.user_id = ?
  `).all(req.user.id);
  res.json(friends);
});

app.post('/api/friends/:id', auth, (req, res) => {
  const friendId = +req.params.id;
  if (friendId === req.user.id) return res.status(400).json({ error: 'Нельзя себя' });
  try {
    db.prepare('INSERT OR IGNORE INTO friends (user_id, friend_id) VALUES (?, ?)').run(req.user.id, friendId);
    db.prepare('INSERT OR IGNORE INTO friends (user_id, friend_id) VALUES (?, ?)').run(friendId, req.user.id);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/friends/:id', auth, (req, res) => {
  const friendId = +req.params.id;
  db.prepare('DELETE FROM friends WHERE user_id = ? AND friend_id = ?').run(req.user.id, friendId);
  db.prepare('DELETE FROM friends WHERE user_id = ? AND friend_id = ?').run(friendId, req.user.id);
  res.json({ ok: true });
});

/* ==================== CHATS ==================== */
app.get('/api/chats', auth, (req, res) => {
  const chats = db.prepare(`
    SELECT c.id, c.user1_id, c.user2_id,
      u.id as other_id, u.name as other_name, u.nick as other_nick, u.mplus, u.verified, u.online,
      (SELECT text FROM messages WHERE chat_id = c.id ORDER BY id DESC LIMIT 1) as last_message,
      (SELECT created_at FROM messages WHERE chat_id = c.id ORDER BY id DESC LIMIT 1) as last_time
    FROM chats c
    JOIN users u ON u.id = CASE WHEN c.user1_id = ? THEN c.user2_id ELSE c.user1_id END
    WHERE c.user1_id = ? OR c.user2_id = ?
    ORDER BY last_time DESC
  `).all(req.user.id, req.user.id, req.user.id);
  res.json(chats);
});

function getOrCreateChat(userA, userB) {
  const [u1, u2] = userA < userB ? [userA, userB] : [userB, userA];
  let chat = db.prepare('SELECT * FROM chats WHERE user1_id = ? AND user2_id = ?').get(u1, u2);
  if (!chat) {
    const info = db.prepare('INSERT INTO chats (user1_id, user2_id) VALUES (?, ?)').run(u1, u2);
    chat = { id: info.lastInsertRowid, user1_id: u1, user2_id: u2 };
  }
  return chat;
}

app.get('/api/chats/:userId', auth, (req, res) => {
  const otherId = +req.params.userId;
  const chat = getOrCreateChat(req.user.id, otherId);
  const messages = db.prepare(`
    SELECT m.*, u.name as author_name FROM messages m
    JOIN users u ON m.from_id = u.id
    WHERE chat_id = ? ORDER BY m.id ASC LIMIT 200
  `).all(chat.id);
  res.json({ chatId: chat.id, messages });
});

app.post('/api/chats/:userId', auth, (req, res) => {
  const otherId = +req.params.userId;
  const { text } = req.body;
  if (!text?.trim()) return res.status(400).json({ error: 'Пусто' });
  const chat = getOrCreateChat(req.user.id, otherId);
  const info = db.prepare('INSERT INTO messages (chat_id, from_id, text) VALUES (?, ?, ?)')
    .run(chat.id, req.user.id, text);
  res.json({ id: info.lastInsertRowid });
});

/* ==================== CALLS ==================== */
app.get('/api/calls', auth, (req, res) => {
  const calls = db.prepare(`
    SELECT c.*, u.name as other_name, u.mplus, u.verified FROM calls c
    JOIN users u ON u.id = c.to_id
    WHERE c.from_id = ? ORDER BY c.created_at DESC LIMIT 50
  `).all(req.user.id);
  res.json(calls);
});

app.post('/api/calls', auth, (req, res) => {
  const { to_id, type } = req.body;
  db.prepare('INSERT INTO calls (from_id, to_id, type) VALUES (?, ?, ?)')
    .run(req.user.id, to_id, type || 'audio');
  res.json({ ok: true });
});

/* ==================== CLANS ==================== */
app.get('/api/clans', auth, (req, res) => {
  const clans = db.prepare(`
    SELECT c.*, u.name as owner_name,
      (SELECT COUNT(*) FROM clan_members WHERE clan_id = c.id) as members_count
    FROM clans c JOIN users u ON c.owner_id = u.id
    ORDER BY c.points DESC
  `).all();
  const members = db.prepare('SELECT clan_id, user_id FROM clan_members WHERE user_id = ?').all(req.user.id);
  const myClans = new Set(members.map(m => m.clan_id));
  clans.forEach(c => c.is_member = myClans.has(c.id));
  res.json(clans);
});

app.post('/api/clans', auth, (req, res) => {
  const user = db.prepare('SELECT mplus FROM users WHERE id = ?').get(req.user.id);
  if (!user.mplus) return res.status(403).json({ error: 'Только для M+' });
  const { name, tag } = req.body;
  if (!name || !tag) return res.status(400).json({ error: 'Заполни поля' });
  const info = db.prepare('INSERT INTO clans (name, tag, owner_id) VALUES (?, ?, ?)')
    .run(name, tag.substring(0, 4).toUpperCase(), req.user.id);
  db.prepare('INSERT INTO clan_members (clan_id, user_id, role) VALUES (?, ?, ?)')
    .run(info.lastInsertRowid, req.user.id, 'owner');
  res.json({ id: info.lastInsertRowid });
});

app.post('/api/clans/:id/join', auth, (req, res) => {
  db.prepare('INSERT OR IGNORE INTO clan_members (clan_id, user_id) VALUES (?, ?)')
    .run(req.params.id, req.user.id);
  res.json({ ok: true });
});

app.post('/api/clans/:id/leave', auth, (req, res) => {
  db.prepare('DELETE FROM clan_members WHERE clan_id = ? AND user_id = ?')
    .run(req.params.id, req.user.id);
  res.json({ ok: true });
});

app.delete('/api/clans/:id', auth, requireRole('owner', 'admin'), (req, res) => {
  db.prepare('DELETE FROM clans WHERE id = ?').run(req.params.id);
  db.prepare('DELETE FROM clan_members WHERE clan_id = ?').run(req.params.id);
  logAction(req.user.id, `Удалён клан #${req.params.id}`);
  res.json({ ok: true });
});

/* ==================== M+ ==================== */
app.post('/api/mplus/buy', auth, (req, res) => {
  db.prepare('UPDATE users SET mplus = 1 WHERE id = ?').run(req.user.id);
  res.json({ ok: true });
});

app.post('/api/mplus/cancel', auth, (req, res) => {
  db.prepare('UPDATE users SET mplus = 0 WHERE id = ?').run(req.user.id);
  res.json({ ok: true });
});

/* ==================== ADMIN ==================== */
app.get('/api/admin/logs', auth, requireRole('owner', 'admin'), (req, res) => {
  const logs = db.prepare(`
    SELECT l.*, u.name as by_name FROM logs l
    JOIN users u ON l.by_id = u.id
    ORDER BY l.id DESC LIMIT 100
  `).all();
  res.json(logs);
});

app.post('/api/admin/users/:id/role', auth, requireRole('owner', 'admin'), (req, res) => {
  const { role } = req.body;
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!target) return res.status(404).json({ error: 'Не найден' });
  if (role === 'owner' && req.user.id !== +req.params.id) {
    const me = db.prepare('SELECT role FROM users WHERE id = ?').get(req.user.id);
    if (me.role !== 'owner') return res.status(403).json({ error: 'Только владелец может назначать владельцев' });
  }
  db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, req.params.id);
  logAction(req.user.id, `Роль ${target.name} → ${role}`);
  res.json({ ok: true });
});

app.post('/api/admin/users/:id/verify', auth, requireRole('owner', 'admin'), (req, res) => {
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  const newVal = target.verified ? 0 : 1;
  db.prepare('UPDATE users SET verified = ? WHERE id = ?').run(newVal, req.params.id);
  logAction(req.user.id, `${newVal ? 'Выдана' : 'Снята'} галочка: ${target.name}`);
  res.json({ verified: !!newVal });
});

app.post('/api/admin/users/:id/mplus', auth, requireRole('owner', 'admin'), (req, res) => {
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  const newVal = target.mplus ? 0 : 1;
  db.prepare('UPDATE users SET mplus = ? WHERE id = ?').run(newVal, req.params.id);
  logAction(req.user.id, `${newVal ? 'Выдана' : 'Снята'} М+: ${target.name}`);
  res.json({ mplus: !!newVal });
});

app.delete('/api/admin/users/:id', auth, requireRole('owner', 'admin'), (req, res) => {
  if (+req.params.id === req.user.id) return res.status(400).json({ error: 'Себя нельзя' });
  const target = db.prepare('SELECT name FROM users WHERE id = ?').get(req.params.id);
  db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  logAction(req.user.id, `Забанен: ${target?.name}`);
  res.json({ ok: true });
});

/* ==================== SPA FALLBACK ==================== */
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`🚀 МКонтакт запущен на порту ${PORT}`);
});