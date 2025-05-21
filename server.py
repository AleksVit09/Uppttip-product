import os
import sqlite3
import secrets
import jwt
import base64
import subprocess
import threading
from datetime import datetime, timedelta

from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Form
from fastapi.security import HTTPBasic, HTTPBasicCredentials, HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from passlib.context import CryptContext
from pydantic import BaseModel
from dotenv import load_dotenv

# ─── ЗАГРУЗКА КОНФИГА ────────────────────────────────────────────────────────
load_dotenv()
JWT_SECRET  = os.getenv("JWT_SECRET")
PORT        = int(os.getenv("PORT", 3000))
SUBDOMAIN   = os.getenv("LT_SUBDOMAIN")  # обязательно задайте в .env

if not (JWT_SECRET and SUBDOMAIN):
    raise RuntimeError("Укажите в .env LT_USER, LT_PASSWORD, JWT_SECRET и LT_SUBDOMAIN")

# просто инициализируем приложение без глобовой зависимости
app = FastAPI()

# ─── JWT & ПАРОЛЬНЫЙ КОНТЕКСТ ──────────────────────────────────────────────
pwd_ctx    = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_sec = HTTPBearer()

def create_token(data: dict):
    payload = data.copy()
    payload["exp"] = datetime.utcnow() + timedelta(days=7)
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def get_current_user(token: HTTPAuthorizationCredentials = Depends(bearer_sec)):
    try:
        payload = jwt.decode(token.credentials, JWT_SECRET, algorithms=["HS256"])
        uid = payload.get("id")
        if uid is None: raise
    except:
        raise HTTPException(status_code=401, detail="Invalid token")
    row = db.execute(
        "SELECT id,username,avatar,theme FROM users WHERE id=?", (uid,)
    ).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="User not found")
    return row

# ─── SQLITE ИНИЦИАЛИЗАЦИЯ ─────────────────────────────────────────────────
db = sqlite3.connect("data.db", check_same_thread=False)
db.row_factory = sqlite3.Row

def init_db():
    db.executescript("""
    PRAGMA foreign_keys=ON;
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY,
      username TEXT UNIQUE,
      password_hash TEXT,
      avatar TEXT,
      theme TEXT DEFAULT 'light'
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
    """)
    cnt = db.execute("SELECT COUNT(*) AS c FROM cards").fetchone()["c"]
    if cnt:
        return

    full = [  # 16 карточек + шаги
      {"id":"swot","title":"SWOT-анализ","cat":"analitica",
       "steps":["Сильные стороны","Слабые стороны","Возможности","Угрозы"]},
      {"id":"pest","title":"PEST-анализ","cat":"analitica",
       "steps":["Политические","Экономические","Социальные","Технологические"]},
      {"id":"porter","title":"5 сил Портера","cat":"analitica",
       "steps":["Сила поставщиков","Сила покупателей","Новые игроки","Заменители","Конкуренция"]},
      {"id":"lean","title":"Lean Canvas","cat":"plan",
       "steps":["Проблемы","Сегменты","УТП","Решение","Каналы","Доходы","Затраты"]},
      {"id":"bmc","title":"Business Model Canvas","cat":"plan",
       "steps":["ЦП","Клиенты","Каналы","Отношения","Доходы","Ресурсы","Деятельность","Партнёры","Затраты"]},
      {"id":"vpc","title":"Value Proposition Canvas","cat":"plan",
       "steps":["Профиль","Задачи","Боли","Выгоды","Продукт","Устранители болей","Создатели выгод"]},
      {"id":"smart","title":"SMART-цели","cat":"monitor",
       "steps":["Specific","Measurable","Achievable","Relevant","Time-bound"]},
      {"id":"okr","title":"OKR-план","cat":"monitor",
       "steps":["Objective","Key Result 1","Key Result 2","Key Result 3"]},
      {"id":"raci","title":"RACI-матрица","cat":"monitor",
       "steps":["Задача","R","A","C","I"]},
      {"id":"kpi","title":"KPI-дашборд","cat":"monitor",
       "steps":["Метрика","Текущий","Цель","Источник"]},
      {"id":"risk","title":"Матрица рисков","cat":"analitica",
       "steps":["Риск","Вероятность","Влияние","Стратегия"]},
      {"id":"stake","title":"Карта стейкхолдеров","cat":"analitica",
       "steps":["Стейкхолдер","Интерес","Влияние","Стратегия"]},
      {"id":"moscow","title":"MoSCoW-приоритизация","cat":"plan",
       "steps":["Must","Should","Could","Won’t"]},
      {"id":"usm","title":"User Story Map","cat":"plan",
       "steps":["Эпики","Действия","User Stories","Релизы"]},
      {"id":"gantt","title":"Гантт-диаграмма","cat":"plan",
       "steps":["Задача","Начало","Конец","Ответственный","%"]},
      {"id":"bsc","title":"Balanced Scorecard","cat":"monitor",
       "steps":["Финансы","Клиенты","Процессы","Обучение"]}
    ]
    cur = db.cursor()
    for c in full:
        cur.execute("INSERT INTO cards(id,title,cat) VALUES(?,?,?)",
                    (c["id"], c["title"], c["cat"]))
        for i, s in enumerate(c["steps"]):
            cur.execute("""INSERT INTO steps(card_id,idx,text)
                           VALUES(?,?,?)""", (c["id"], i, s))
    db.commit()
init_db()
# ─── СТАТИКА И SPA ────────────────────────────────────────────────────────
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
def serve_index():
    return FileResponse("static/index.html")

# ─── МОДЕЛИ ───────────────────────────────────────────────────────────────
class AuthData(BaseModel):
    username: str
    password: str

class StepData(BaseModel):
    step_id:  int
    input:    str
    example:  str

# ─── АПИ: АВТОРИЗАЦИЯ ─────────────────────────────────────────────────────
@app.post("/api/register")
def register(d: AuthData):
    hash_ = pwd_ctx.hash(d.password)
    try:
        r = db.execute("INSERT INTO users(username,password_hash) VALUES(?,?)",
                       (d.username, hash_))
        db.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(400, "Username taken")
    uid = r.lastrowid
    user = db.execute(
      "SELECT id,username,avatar,theme FROM users WHERE id=?", (uid,)
    ).fetchone()
    token = create_token({"id": uid})
    return {"user": dict(user), "token": token}

@app.post("/api/login")
def login(d: AuthData):
    row = db.execute("SELECT * FROM users WHERE username=?", (d.username,)).fetchone()
    if not row or not pwd_ctx.verify(d.password, row["password_hash"]):
        raise HTTPException(401, "Invalid credentials")
    user = db.execute(
      "SELECT id,username,avatar,theme FROM users WHERE id=?", (row["id"],)
    ).fetchone()
    token = create_token({"id": row["id"]})
    return {"user": dict(user), "token": token}

# ─── АПИ: КАРТОЧКИ ────────────────────────────────────────────────────────
@app.get("/api/cards")
def get_cards(user=Depends(get_current_user)):
    cards = db.execute("SELECT * FROM cards").fetchall()
    out = []
    for c in cards:
        steps = db.execute(
            "SELECT id,idx,text FROM steps WHERE card_id=? ORDER BY idx",
            (c["id"],)
        ).fetchall()
        out.append({
            "id": c["id"], "title": c["title"], "cat": c["cat"],
            "steps":[{"id":s["id"],"idx":s["idx"],"text":s["text"]} for s in steps]
        })
    return out

# ─── АПИ: USER_STEPS ─────────────────────────────────────────────────────
@app.get("/api/user_steps")
def list_steps(user=Depends(get_current_user)):
    rows = db.execute("SELECT * FROM user_steps WHERE user_id=?", (user["id"],)).fetchall()
    return [dict(r) for r in rows]

@app.post("/api/user_steps", status_code=204)
def upsert_step(d: StepData, user=Depends(get_current_user)):
    db.execute("""
      INSERT INTO user_steps(user_id,step_id,input,example)
      VALUES(?,?,?,?)
      ON CONFLICT(user_id,step_id) DO UPDATE
        SET input=excluded.input, example=excluded.example
    """, (user["id"], d.step_id, d.input, d.example))
    db.commit()

# ─── АПИ: FAVORITES ──────────────────────────────────────────────────────
@app.get("/api/favorites")
def get_fav(user=Depends(get_current_user)):
    rows = db.execute("SELECT card_id FROM favorites WHERE user_id=?", (user["id"],)).fetchall()
    return [r["card_id"] for r in rows]

@app.post("/api/favorites", status_code=204)
def add_fav(card_id: str = Form(...), user=Depends(get_current_user)):
    db.execute("INSERT OR IGNORE INTO favorites(user_id,card_id) VALUES(?,?)",
               (user["id"], card_id))
    db.commit()

@app.delete("/api/favorites/{card_id}", status_code=204)
def del_fav(card_id: str, user=Depends(get_current_user)):
    db.execute("DELETE FROM favorites WHERE user_id=? AND card_id=?", (user["id"], card_id))
    db.commit()

# ─── АПИ: EVENTS ─────────────────────────────────────────────────────────
@app.get("/api/events")
def get_events(user=Depends(get_current_user)):
    rows = db.execute("SELECT * FROM events WHERE user_id=? ORDER BY id DESC",
                      (user["id"],)).fetchall()
    return [dict(r) for r in rows]

@app.post("/api/events", status_code=204)
def add_event(text: str = Form(...), user=Depends(get_current_user)):
    dt = datetime.now().isoformat(sep=' ', timespec='seconds')
    db.execute("INSERT INTO events(user_id,date,text) VALUES(?,?,?)",
               (user["id"], dt, text))
    db.commit()

# ─── АПИ: STATS ──────────────────────────────────────────────────────────
@app.get("/api/stats")
def stats(user=Depends(get_current_user)):
    q = """
    SELECT cards.id AS card_id,
           COUNT(steps.id) AS total,
           SUM(CASE WHEN user_steps.input IS NOT NULL THEN 1 ELSE 0 END) AS filled
    FROM cards
    JOIN steps ON steps.card_id=cards.id
    LEFT JOIN user_steps
      ON user_steps.step_id=steps.id AND user_steps.user_id=?
    GROUP BY cards.id
    """
    rows = db.execute(q, (user["id"],)).fetchall()
    return [dict(r) for r in rows]

# ─── АПИ: PROFILE (включая theme) ────────────────────────────────────────
@app.get("/api/profile")
def profile(user=Depends(get_current_user)):
    return dict(user)

@app.put("/api/profile", status_code=204)
def update_profile(
    username: str     = Form(None),
    password: str     = Form(None),
    theme:    str     = Form(None),
    avatar:   UploadFile = File(None),
    user=Depends(get_current_user)
):
    upd, params = [], []
    if username:
        upd.append("username=?"); params.append(username)
    if password:
        ph = pwd_ctx.hash(password)
        upd.append("password_hash=?"); params.append(ph)
    if theme in ("light","dark"):
        upd.append("theme=?"); params.append(theme)
    if avatar:
        data = avatar.file.read()
        b64  = base64.b64encode(data).decode('ascii')
        upd.append("avatar=?"); params.append(b64)
    if not upd:
        return
    params.append(user["id"])
    sql = f"UPDATE users SET {','.join(upd)} WHERE id=?"
    db.execute(sql, tuple(params))
    db.commit()

# ─── AUTO LOCALTUNNEL ────────────────────────────────────────────────────
def start_tunnel():
    cmd = f"lt --port {PORT} --subdomain {SUBDOMAIN}"
    try:
        subprocess.run(cmd, shell=True, check=True)
    except Exception as e:
        print("❌ Не удалось запустить localtunnel:", e)
        print("   Убедитесь, что localtunnel установлен глобально: npm install -g localtunnel")

if __name__ == "__main__":
    threading.Thread(target=start_tunnel, daemon=True).start()
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=PORT, reload=False)
