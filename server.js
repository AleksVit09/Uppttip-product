require('dotenv').config();
const express       = require('express');
const basicAuth     = require('express-basic-auth');
const sqlite3       = require('sqlite3').verbose();
const bcrypt        = require('bcrypt');
const jwt           = require('jsonwebtoken');
const multer        = require('multer');
const upload        = multer(); // для аватаров, если решите хранить как base64

const {
  LT_USER, LT_PASSWORD, JWT_SECRET = 'change_me', PORT = 3000
} = process.env;

if(!LT_USER || !LT_PASSWORD) {
  console.error('❌ Задайте в .env LT_USER и LT_PASSWORD');
  process.exit(1);
}

const app = express();
app.use(express.json());

// — Basic-Auth перед всеми запросами:
app.use(basicAuth({
  users: { [LT_USER]: LT_PASSWORD },
  challenge: true
}));

// Инициализируем БД
const db = new sqlite3.Database('./data.db', err=>{
  if(err) throw err;
  console.log('✅ SQLite connected');
  initDb();
});

function initDb(){
  // Создаем таблицы
  db.exec(`
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY,
      username TEXT UNIQUE,
      password_hash TEXT,
      avatar TEXT
    );
    CREATE TABLE IF NOT EXISTS cards (
      id TEXT PRIMARY KEY,
      title TEXT,
      cat TEXT
    );
    CREATE TABLE IF NOT EXISTS steps (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      card_id TEXT,
      idx INTEGER,
      text TEXT,
      FOREIGN KEY(card_id) REFERENCES cards(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS user_steps (
      user_id INTEGER,
      step_id INTEGER,
      input TEXT,
      example TEXT,
      PRIMARY KEY(user_id,step_id),
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(step_id) REFERENCES steps(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS favorites (
      user_id INTEGER,
      card_id TEXT,
      PRIMARY KEY(user_id,card_id),
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(card_id) REFERENCES cards(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      date TEXT,
      text TEXT,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
  `, seedCards);
}

function seedCards(){
  // Если нет карточек — заполняем дефолтные
  db.get(`SELECT COUNT(*) AS cnt FROM cards`, (err,row)=>{
    if(err) throw err;
    if(row.cnt > 0) return;
    const defaultCards = [
      {id:'swot',title:'SWOT-анализ',cat:'analitica', steps:['Сильные стороны','Слабые стороны','Возможности','Угрозы']},
      {id:'pest',title:'PEST-анализ',cat:'analitica', steps:['Политические','Экономические','Социальные','Технологические']},
      /* … остальные … */
    ];
    const insertCard = db.prepare(`INSERT INTO cards(id,title,cat) VALUES(?,?,?)`);
    const insertStep = db.prepare(`INSERT INTO steps(card_id,idx,text) VALUES(?,?,?)`);
    for(const c of defaultCards){
      insertCard.run(c.id, c.title, c.cat);
      c.steps.forEach((s,i)=> insertStep.run(c.id,i,s));
    }
    insertCard.finalize();
    insertStep.finalize();
    console.log('✅ Seed cards');
  });
}

// — Регистрация
app.post('/api/register', async (req,res)=>{
  const {username, password} = req.body;
  if(!username||!password) return res.status(400).send('username/password required');
  const hash = await bcrypt.hash(password, 10);
  db.run(`INSERT INTO users(username,password_hash) VALUES(?,?)`, [username,hash], function(err){
    if(err) return res.status(400).send('username taken');
    const userId = this.lastID;
    const token = jwt.sign({id:userId}, JWT_SECRET, {expiresIn:'7d'});
    res.json({ user:{id:userId,username}, token });
  });
});

// — Логин
app.post('/api/login', (req,res)=>{
  const {username, password} = req.body;
  db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err,user)=>{
    if(err||!user) return res.status(401).send('invalid');
    const ok = await bcrypt.compare(password, user.password_hash);
    if(!ok) return res.status(401).send('invalid');
    const token = jwt.sign({id:user.id}, JWT_SECRET, {expiresIn:'7d'});
    res.json({ user:{id:user.id,username:user.username,avatar:user.avatar}, token });
  });
});

// — JWT-мидлвар
function auth(req,res,next){
  const h = req.headers.authorization;
  if(!h) return res.sendStatus(401);
  const token = h.replace(/^Bearer\s+/,'');
  jwt.verify(token, JWT_SECRET, (e,payload)=>{
    if(e) return res.sendStatus(401);
    req.userId = payload.id;
    next();
  });
}

// — Получить все карточки + шаги
app.get('/api/cards', auth, (req,res)=>{
  db.all(`SELECT * FROM cards`, (e,cards)=>{
    if(e) return res.sendStatus(500);
    db.all(`SELECT * FROM steps ORDER BY card_id, idx`, (e2,steps)=>{
      if(e2) return res.sendStatus(500);
      const map = {};
      cards.forEach(c=> map[c.id] = {...c, steps:[]});
      steps.forEach(s=> map[s.card_id].steps.push(s));
      res.json(Object.values(map));
    });
  });
});

// — User steps CRUD
app.get('/api/user_steps', auth, (req,res)=>{
  db.all(`SELECT * FROM user_steps WHERE user_id = ?`, [req.userId], (e,rows)=>{
    if(e) return res.sendStatus(500);
    res.json(rows);
  });
});
app.post('/api/user_steps', auth, (req,res)=>{
  const { step_id, input, example } = req.body;
  db.run(`
    INSERT INTO user_steps(user_id,step_id,input,example)
    VALUES(?,?,?,?)
    ON CONFLICT(user_id,step_id) DO UPDATE SET input=?,example=?
  `, [req.userId,step_id,input,example,input,example], err=>{
    if(err) return res.sendStatus(500);
    res.sendStatus(204);
  });
});

// — Favorites
app.get('/api/favorites', auth, (req,res)=>{
  db.all(`SELECT card_id FROM favorites WHERE user_id = ?`, [req.userId], (e,rows)=>{
    if(e) return res.sendStatus(500);
    res.json(rows.map(r=>r.card_id));
  });
});
app.post('/api/favorites', auth, (req,res)=>{
  const { card_id } = req.body;
  db.run(`
    INSERT OR IGNORE INTO favorites(user_id,card_id)
    VALUES(?,?)
  `, [req.userId,card_id], err=>{
    if(err) return res.sendStatus(500);
    res.sendStatus(204);
  });
});
app.delete('/api/favorites/:card_id', auth, (req,res)=>{
  db.run(`DELETE FROM favorites WHERE user_id=? AND card_id=?`,
    [req.userId, req.params.card_id], err=>{
      if(err) return res.sendStatus(500);
      res.sendStatus(204);
    });
});

// — Events
app.get('/api/events', auth, (req,res)=>{
  db.all(`SELECT * FROM events WHERE user_id = ? ORDER BY id DESC`, [req.userId], (e,rows)=>{
    if(e) return res.sendStatus(500);
    res.json(rows);
  });
});
app.post('/api/events', auth, (req,res)=>{
  const date = new Date().toLocaleString();
  db.run(`
    INSERT INTO events(user_id,date,text) VALUES(?,?,?)
  `, [req.userId,date,req.body.text], err=>{
    if(err) return res.sendStatus(500);
    res.sendStatus(204);
  });
});

// — Статистика (кол-во заполненных степов)
app.get('/api/stats', auth, (req,res)=>{
  db.all(`
    SELECT cards.id AS card_id, COUNT(steps.id) AS total,
           SUM(CASE WHEN user_steps.input IS NOT NULL THEN 1 ELSE 0 END) AS filled
    FROM cards
    JOIN steps ON steps.card_id=cards.id
    LEFT JOIN user_steps
      ON user_steps.step_id=steps.id AND user_steps.user_id=?
    GROUP BY cards.id
  `, [req.userId], (e,rows)=>{
    if(e) return res.sendStatus(500);
    res.json(rows);
  });
});

// — Профиль
app.get('/api/profile', auth, (req,res)=>{
  db.get(`SELECT id,username,avatar FROM users WHERE id = ?`, [req.userId], (e,u)=>{
    if(e||!u) return res.sendStatus(500);
    res.json(u);
  });
});
app.put('/api/profile', auth, upload.single('avatar'), async (req,res)=>{
  const { username, password } = req.body;
  let avatar = null;
  if(req.file) avatar = req.file.buffer.toString('base64');
  const updates = [], params = [];
  if(username){
    updates.push('username = ?'); params.push(username);
  }
  if(password){
    const hash = await bcrypt.hash(password,10);
    updates.push('password_hash = ?'); params.push(hash);
  }
  if(avatar){
    updates.push('avatar = ?'); params.push(avatar);
  }
  if(!updates.length) return res.sendStatus(204);
  params.push(req.userId);
  db.run(`UPDATE users SET ${updates.join(',')} WHERE id = ?`, params, err=>{
    if(err) return res.sendStatus(500);
    res.sendStatus(204);
  });
});

// — Запустить
app.listen(PORT, ()=> {
  console.log(`🚀 Backend running on http://localhost:${PORT}`);
});
