import os
import uuid
import json
import base64
import hashlib
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, Tuple

from fastapi import FastAPI, Request, HTTPException, Depends, Form
from fastapi.responses import JSONResponse, HTMLResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from starlette.responses import RedirectResponse
from fastapi.responses import Response

# ----------------------------
# Config / ENV
# ----------------------------
API_KEY = os.getenv("API_KEY", "dev123")  # дев-ключ (оставлен для обратной совместимости)
BASIC_USER = os.getenv("BASIC_USER", "demo")
BASIC_PASS = os.getenv("BASIC_PASS", "demo")
PAIR_EXPIRES_SEC = int(os.getenv("PAIR_EXPIRES_SEC", "600"))  # 10 минут
PAIR_POLL_INTERVAL = int(os.getenv("PAIR_POLL_INTERVAL", "5"))
DB_PATH = os.getenv("DB_PATH", "jobs.db")
PORT = int(os.getenv("PORT", "7250"))

# ----------------------------
# App
# ----------------------------
app = FastAPI(title="Prompt Queue + Pairing")

# Включим CORS на localhost (на будущее, чтобы фронт мог ходить)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1", "http://localhost"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

basic_sec = HTTPBasic()

# ----------------------------
# DB helpers (sqlite3, синхронно)
# ----------------------------
def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def iso(ts: datetime) -> str:
    # ISO8601 с Z
    return ts.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

def b64url(nbytes: int = 32) -> str:
    return base64.urlsafe_b64encode(os.urandom(nbytes)).decode().rstrip("=")

def gen_user_code() -> str:
    # ABCD-1234 — человекочитаемый
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    part = "".join(secrets.choice(alphabet) for _ in range(4))
    part2 = "".join(secrets.choice(alphabet) for _ in range(4))
    return f"{part}-{part2}"

def hash_token_v1(token: str) -> str:
    salt = base64.urlsafe_b64encode(os.urandom(16)).decode().rstrip("=")
    h = hashlib.sha256((salt + token).encode()).hexdigest()
    return f"v1${salt}${h}"

def verify_token_v1(token: str, token_hash: str) -> bool:
    try:
        v, salt, h = token_hash.split("$", 2)
        if v != "v1": return False
        hh = hashlib.sha256((salt + token).encode()).hexdigest()
        return secrets.compare_digest(hh, h)
    except Exception:
        return False

def init_db():
    conn = get_conn()
    cur = conn.cursor()
    # Таблица задач (расширенная)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS jobs (
      id TEXT PRIMARY KEY,
      prompt TEXT NOT NULL,
      url TEXT,
      options TEXT,
      status TEXT CHECK(status IN ('PENDING','CLAIMED','RUNNING','SUCCEEDED','FAILED','CANCELLED')) NOT NULL,
      result TEXT,
      error TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      claimed_by TEXT,
      claimed_at TEXT,
      lock_until TEXT,
      attempts INTEGER DEFAULT 0,
      user_id TEXT,              -- владелец задачи (от сайта /verify)
      target_agent_id TEXT       -- если хотим адресовать конкретному агенту
    );
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_jobs_status_created ON jobs(status, created_at);")

    # Таблица заявок на привязку
    cur.execute("""
    CREATE TABLE IF NOT EXISTS pairing_requests (
      device_code TEXT PRIMARY KEY,
      user_code TEXT UNIQUE NOT NULL,
      status TEXT CHECK(status IN ('PENDING','APPROVED','EXPIRED','DELIVERED')) NOT NULL,
      user_id TEXT,
      agent_id TEXT,
      temp_token TEXT,      -- временно храним plain токен для единовременной выдачи
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      poll_interval INTEGER NOT NULL
    );
    """)

    # Таблица агентов
    cur.execute("""
    CREATE TABLE IF NOT EXISTS agents (
      agent_id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      token_hash TEXT NOT NULL,
      created_at TEXT NOT NULL,
      last_seen TEXT,
      meta TEXT
    );
    """)

    conn.commit()
    conn.close()

init_db()

# ----------------------------
# Utils: auth
# ----------------------------
def get_basic_user(credentials: HTTPBasicCredentials = Depends(basic_sec)) -> str:
    ok = (credentials.username == BASIC_USER) and (credentials.password == BASIC_PASS)
    if not ok:
        raise HTTPException(status_code=401, detail="Unauthorized (basic)")
    return credentials.username  # используем username как user_id демо-юзера

def get_bearer_token(req: Request) -> Optional[str]:
    auth = req.headers.get("authorization") or req.headers.get("Authorization")
    if auth and auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()
    # обратная совместимость: X-Agent-Token
    x = req.headers.get("X-Agent-Token")
    return x.strip() if x else None

def require_agent(req: Request) -> Dict[str, Any]:
    token = get_bearer_token(req)
    if not token:
        raise HTTPException(status_code=401, detail="Missing agent token")
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT agent_id, user_id, token_hash FROM agents")
        rows = cur.fetchall()
        for r in rows:
            if verify_token_v1(token, r["token_hash"]):
                # update last_seen
                cur.execute("UPDATE agents SET last_seen=? WHERE agent_id=?", (iso(now_utc()), r["agent_id"]))
                conn.commit()
                return {"agent_id": r["agent_id"], "user_id": r["user_id"]}
        raise HTTPException(status_code=401, detail="Invalid agent token")
    finally:
        conn.close()

# ----------------------------
# Health
# ----------------------------
@app.get("/health")
def health():
    return {"ok": True}

# ----------------------------
# Pairing flow
# ----------------------------
@app.post("/api/agents/pair/start")
def pair_start():
    device_code = b64url(32)
    user_code = gen_user_code()
    now = now_utc()
    expires = now + timedelta(seconds=PAIR_EXPIRES_SEC)
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO pairing_requests (device_code,user_code,status,user_id,agent_id,temp_token,created_at,expires_at,poll_interval) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (device_code, user_code, "PENDING", None, None, None, iso(now), iso(expires), PAIR_POLL_INTERVAL)
        )
        conn.commit()
    finally:
        conn.close()
    # В реальном интернете сюда ставим публичный домен
    verification_uri = os.getenv("VERIFICATION_URI", "http://127.0.0.1:7250/verify")
    return {
        "device_code": device_code,
        "user_code": user_code,
        "verification_uri": verification_uri,
        "expires_in": PAIR_EXPIRES_SEC,
        "interval": PAIR_POLL_INTERVAL
    }

@app.post("/api/agents/pair/poll")
def pair_poll(body: Dict[str, Any]):
    device_code = (body or {}).get("device_code")
    if not device_code:
        raise HTTPException(status_code=400, detail="device_code required")
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM pairing_requests WHERE device_code=?", (device_code,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="not found")
        # expiry
        if datetime.fromisoformat(row["expires_at"].replace("Z","+00:00")) < now_utc():
            # пометим как EXPIRED
            cur.execute("UPDATE pairing_requests SET status='EXPIRED' WHERE device_code=?", (device_code,))
            conn.commit()
            return {"status": "EXPIRED"}
        status = row["status"]
        if status == "PENDING":
            return {"status": "PENDING"}
        if status == "APPROVED" and row["temp_token"]:
            # отдаем один раз и помечаем доставленным
            agent_id = row["agent_id"]
            token = row["temp_token"]
            cur.execute("UPDATE pairing_requests SET status='DELIVERED', temp_token=NULL WHERE device_code=?", (device_code,))
            conn.commit()
            return {"status": "APPROVED", "agent_id": agent_id, "agent_token": token}
        if status in ("APPROVED","DELIVERED"):
            return {"status": status}
        if status == "EXPIRED":
            return {"status":"EXPIRED"}
        return {"status": status}
    finally:
        conn.close()

# ----------------------------
# Verify UI (Basic auth)
# ----------------------------
VERIFY_FORM = """
<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<title>Pair Browser</title>
<style>
  body{font-family:ui-sans-serif,system-ui,Segoe UI,Roboto,Arial;margin:40px;max-width:640px}
  form{display:flex;gap:12px}
  input[type=text]{flex:1;padding:10px;font-size:16px}
  button{padding:10px 16px;font-size:16px}
  .ok{color:#0a0}
  .err{color:#a00}
  .box{padding:12px;border:1px solid #ddd;border-radius:8px;background:#fafafa}
</style>
</head>
<body>
  <h1>Pair this browser</h1>
  <p>Введите <b>Pairing code</b>, который показывает расширение NanoBrowser.</p>
  <div class="box">
    <form method="POST" action="/verify">
      <input type="text" name="user_code" placeholder="ABCD-1234" required autofocus />
      <button type="submit">Link</button>
    </form>
  </div>
  {MSG}
</body>
</html>
"""

@app.get("/verify")
def verify_get(user: str = Depends(get_basic_user)):
    return HTMLResponse(VERIFY_FORM.replace("{MSG}", ""))

@app.post("/verify")
def verify_post(user_code: str = Form(...), user: str = Depends(get_basic_user)):
    user_code = user_code.strip().upper()
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM pairing_requests WHERE user_code=?", (user_code,))
        row = cur.fetchone()
        if not row:
            return HTMLResponse(VERIFY_FORM.replace("{MSG}", '<p class="err">Неверный код</p>'), status_code=400)
        if row["status"] in ("APPROVED","DELIVERED"):
            return HTMLResponse(VERIFY_FORM.replace("{MSG}", '<p class="ok">Этот код уже был подтверждён.</p>'))
        if datetime.fromisoformat(row["expires_at"].replace("Z","+00:00")) < now_utc():
            cur.execute("UPDATE pairing_requests SET status='EXPIRED' WHERE user_code=?", (user_code,))
            conn.commit()
            return HTMLResponse(VERIFY_FORM.replace("{MSG}", '<p class="err">Код просрочен</p>'), status_code=400)
        # создаём агента
        agent_id = str(uuid.uuid4())
        agent_token = b64url(32)
        token_hash = hash_token_v1(agent_token)
        now_iso = iso(now_utc())
        cur.execute(
            "INSERT INTO agents(agent_id,user_id,token_hash,created_at,last_seen,meta) VALUES (?,?,?,?,?,?)",
            (agent_id, user, token_hash, now_iso, now_iso, json.dumps({"origin":"pairing"}))
        )
        # помечаем заявку как APPROVED и кладём temp_token для единовременной выдачи при poll
        cur.execute(
            "UPDATE pairing_requests SET status='APPROVED', user_id=?, agent_id=?, temp_token=? WHERE user_code=?",
            (user, agent_id, agent_token, user_code)
        )
        conn.commit()
        msg = f'<p class="ok">Браузер привязан к пользователю <b>{user}</b>.<br/>Agent ID: <code>{agent_id}</code></p>'
        return HTMLResponse(VERIFY_FORM.replace("{MSG}", msg))
    finally:
        conn.close()

RUN_FORM = """
<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<title>Run a job</title>
<style>
  body{font-family:system-ui,Segoe UI,Roboto,Arial;margin:40px;max-width:720px}
  input,textarea{width:100%;padding:10px;font-size:16px}
  label{display:block;margin:12px 0 6px}
  button{padding:10px 16px;font-size:16px;margin-top:12px}
  .msg{margin-top:16px;padding:12px;border:1px solid #ddd;border-radius:8px;background:#f8fafc}
  code{background:#eee;padding:2px 4px;border-radius:4px}
</style>
</head>
<body>
  <h1>Run a job</h1>
  <form method="POST" action="/run">
    <label>URL</label>
    <input name="url" placeholder="https://news.ycombinator.com/" />
    <label>Prompt</label>
    <textarea name="prompt" rows="4" placeholder="найди кроссовки на озоне и выведи 5 вариантов"></textarea>
    <button type="submit">Запустить</button>
  </form>
  {MSG}
  <p style="opacity:.7;margin-top:24px">Под капотом это вызывает <code>POST /api/jobs</code> от имени текущего пользователя (Basic).</p>
</body>
</html>
"""

@app.get("/run")
def run_get(user: str = Depends(get_basic_user)):
    return HTMLResponse(RUN_FORM.replace("{MSG}", ""))

@app.post("/run")
def run_post(
    user: str = Depends(get_basic_user),
    url: str = Form(""),
    prompt: str = Form(...)
):
    if not prompt.strip():
        return HTMLResponse(RUN_FORM.replace("{MSG}", '<div class="msg">Нужен prompt</div>'), status_code=400)
    # создаём задачу как в /api/jobs, привязываем к user
    conn = get_conn()
    try:
        nowi = iso(now_utc())
        job_id = str(uuid.uuid4())
        row = {
            "id": job_id,
            "prompt": prompt,
            "url": url or None,
            "options": None,
            "status": "PENDING",
            "result": None,
            "error": None,
            "created_at": nowi,
            "updated_at": nowi,
            "claimed_by": None,
            "claimed_at": None,
            "lock_until": None,
            "attempts": 0,
            "user_id": user,
            "target_agent_id": None
        }
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO jobs (id,prompt,url,options,status,result,error,created_at,updated_at,claimed_by,claimed_at,lock_until,attempts,user_id,target_agent_id)
            VALUES (:id,:prompt,:url,:options,:status,:result,:error,:created_at,:updated_at,:claimed_by,:claimed_at,:lock_until,:attempts,:user_id,:target_agent_id)
        """, row)
        conn.commit()
    finally:
        conn.close()
    msg = f'<div class="msg">Задача создана: <code>{job_id}</code>. Проверь статус: <a href="/api/jobs/{job_id}">/api/jobs/{job_id}</a></div>'
    return HTMLResponse(RUN_FORM.replace("{MSG}", msg))

# ----------------------------
# Debug: whoami (по агентному токену)
# ----------------------------
@app.get("/api/whoami")
def whoami(req: Request):
    agent = require_agent(req)
    return agent

# ----------------------------
# Jobs API (создание — сайт по Basic; claim/update — агент)
# ----------------------------
@app.post("/api/jobs")
def create_job(req: Request, body: Dict[str, Any] = None, basic: Optional[str] = Depends(lambda: None)):
    """
    Создать задачу.
    - Если запрос с Basic (сайт) — привяжем user_id = BASIC_USER.
    - Если с X-API-Key (legacy) — создадим без user_id (видно всем dev-агентам по старой схеме).
    """
    data = body or {}
    prompt = data.get("prompt")
    if not prompt:
        raise HTTPException(status_code=400, detail="prompt required")
    url = data.get("url")
    options = data.get("options")

    # Basic?
    user_id: Optional[str] = None
    # Попробуем basic вручную (чтоб не мешать UI): Authorization: Basic
    auth = req.headers.get("authorization") or req.headers.get("Authorization") or ""
    if auth.lower().startswith("basic "):
        # очень простой чек, полная проверка уже сделана в /verify, но тут хватит
        try:
            raw = base64.b64decode(auth.split(" ",1)[1]).decode()
            u, p = raw.split(":", 1)
            if u == BASIC_USER and p == BASIC_PASS:
                user_id = u
            else:
                raise ValueError
        except Exception:
            raise HTTPException(status_code=401, detail="Unauthorized (basic)")
    else:
        # dev-режим через X-API-Key
        x = req.headers.get("X-API-Key")
        if x != API_KEY:
            # Разрешим и без хедера (для локальной отладки фронта) — убери, если не надо
            pass

    nowi = iso(now_utc())
    job_id = str(uuid.uuid4())
    row = {
        "id": job_id,
        "prompt": prompt,
        "url": url,
        "options": json.dumps(options) if options is not None else None,
        "status": "PENDING",
        "result": None,
        "error": None,
        "created_at": nowi,
        "updated_at": nowi,
        "claimed_by": None,
        "claimed_at": None,
        "lock_until": None,
        "attempts": 0,
        "user_id": user_id,
        "target_agent_id": None
    }
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO jobs (id,prompt,url,options,status,result,error,created_at,updated_at,claimed_by,claimed_at,lock_until,attempts,user_id,target_agent_id)
            VALUES (:id,:prompt,:url,:options,:status,:result,:error,:created_at,:updated_at,:claimed_by,:claimed_at,:lock_until,:attempts,:user_id,:target_agent_id)
        """, row)
        conn.commit()
    finally:
        conn.close()
    return JSONResponse(status_code=201, content={"id": job_id, "status": "PENDING"})

def _select_claimable_for_agent(cur, agent_id: str, user_id: str) -> Optional[sqlite3.Row]:
    # берём самую старую PENDING или просроченную, ограничиваем user_id и target_agent_id
    nowi = iso(now_utc())
    cur.execute("""
      SELECT * FROM jobs
      WHERE
        status IN ('PENDING','CLAIMED','RUNNING')
        AND (status='PENDING' OR (lock_until IS NOT NULL AND lock_until < ?))
        AND (user_id IS NULL OR user_id = ?)              -- чужие dev-задачи не достанутся
        AND (target_agent_id IS NULL OR target_agent_id = ?)
      ORDER BY created_at ASC
      LIMIT 1
    """, (nowi, user_id, agent_id))
    return cur.fetchone()

def _select_claimable_legacy(cur) -> Optional[sqlite3.Row]:
    # старая логика для dev (но теперь только задачи без user_id)
    nowi = iso(now_utc())
    cur.execute("""
      SELECT * FROM jobs
      WHERE
        status IN ('PENDING','CLAIMED','RUNNING')
        AND (status='PENDING' OR (lock_until IS NOT NULL AND lock_until < ?))
        AND user_id IS NULL
      ORDER BY created_at ASC
      LIMIT 1
    """, (nowi,))
    return cur.fetchone()

@app.post("/api/jobs/claim")
def claim_job(req: Request):
    """
    Агент пытается забрать задачу:
    - Если есть Bearer токен → проверяем агента, достаём только его задачи (по user_id / target_agent_id).
    - Если Bearer нет, но есть X-API-Key → legacy dev-режим (как раньше).
    """
    token = get_bearer_token(req)
    conn = get_conn()
    try:
        cur = conn.cursor()
        row = None
        agent_id = None
        user_id = None
        if token:
            # агентная авторизация
            cur.execute("SELECT agent_id,user_id,token_hash FROM agents")
            rows = cur.fetchall()
            found = None
            for r in rows:
                if verify_token_v1(token, r["token_hash"]):
                    found = r
                    break
            if not found:
                raise HTTPException(status_code=401, detail="Invalid agent token")
            agent_id = found["agent_id"]; user_id = found["user_id"]
            row = _select_claimable_for_agent(cur, agent_id, user_id)
        else:
            # legacy dev
            if req.headers.get("X-API-Key") != API_KEY:
                # нет токена и не dev — запрет
                return Response(status_code=204)
            row = _select_claimable_legacy(cur)

        if not row:
            return Response(status_code=204)

        # claim
        lock_until = iso(now_utc() + timedelta(seconds=120))
        attempts = (row["attempts"] or 0) + 1
        claimed_by = agent_id if agent_id else req.headers.get("X-Agent-Id")  # legacy
        nowi = iso(now_utc())
        cur.execute("""
          UPDATE jobs
          SET status='CLAIMED', claimed_by=?, claimed_at=?, lock_until=?, attempts=?, updated_at=?
          WHERE id=?
        """, (claimed_by, nowi, lock_until, attempts, nowi, row["id"]))
        conn.commit()

        # вернём полную запись
        cur.execute("SELECT * FROM jobs WHERE id=?", (row["id"],))
        out = dict(cur.fetchone())
        # JSON-поля распарсим
        if out.get("options"):
            try: out["options"] = json.loads(out["options"])
            except: pass
        return out
    finally:
        conn.close()

@app.post("/api/jobs/{job_id}/update")
def update_job(job_id: str, req: Request, body: Dict[str, Any]):
    """
    Агент обновляет статус задачи.
    - Если Bearer токен → проверяем, что claimed_by = этот agent_id.
    - Иначе legacy X-API-Key + X-Agent-Id.
    """
    if not body or "status" not in body:
        raise HTTPException(status_code=400, detail="status required")
    status = body["status"]
    if status not in ("RUNNING","SUCCEEDED","FAILED","CANCELLED"):
        raise HTTPException(status_code=400, detail="bad status")

    token = get_bearer_token(req)
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM jobs WHERE id=?", (job_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Job not found")

        # check ownership
        if token:
            # verify token -> agent_id
            cur.execute("SELECT agent_id, token_hash FROM agents")
            rows = cur.fetchall()
            agent_id = None
            for r in rows:
                if verify_token_v1(token, r["token_hash"]):
                    agent_id = r["agent_id"]; break
            if not agent_id:
                raise HTTPException(status_code=401, detail="Invalid agent token")
            if row["claimed_by"] != agent_id:
                raise HTTPException(status_code=409, detail="Job is claimed by another agent")
        else:
            if req.headers.get("X-API-Key") != API_KEY:
                raise HTTPException(status_code=401, detail="Unauthorized")
            # legacy check
            agent_id_hdr = req.headers.get("X-Agent-Id")
            if row["claimed_by"] and agent_id_hdr and row["claimed_by"] != agent_id_hdr:
                raise HTTPException(status_code=409, detail="Job is claimed by another agent")

        # update fields
        upd = {
            "status": status,
            "result": None,
            "error": None,
            "lock_until": None,
        }
        if status in ("RUNNING",):
            upd["lock_until"] = iso(now_utc() + timedelta(seconds=120))
        elif status in ("SUCCEEDED",):
            res = body.get("result")
            upd["result"] = json.dumps(res) if res is not None else None
        elif status in ("FAILED",):
            upd["error"] = str(body.get("error") or "unknown")
        elif status in ("CANCELLED",):
            pass

        nowi = iso(now_utc())
        cur.execute("""
          UPDATE jobs
          SET status=?, result=?, error=?, lock_until=?, updated_at=?
          WHERE id=?
        """, (upd["status"], upd["result"], upd["error"], upd["lock_until"], nowi, job_id))
        conn.commit()

        # return record
        cur.execute("SELECT * FROM jobs WHERE id=?", (job_id,))
        out = dict(cur.fetchone())
        if out.get("options"):
            try: out["options"] = json.loads(out["options"])
            except: pass
        if out.get("result"):
            try: out["result"] = json.loads(out["result"])
            except: pass
        return out
    finally:
        conn.close()

@app.get("/api/jobs/{job_id}")
def get_job(job_id: str):
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM jobs WHERE id=?", (job_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Job not found")
        out = dict(row)
        if out.get("options"):
            try: out["options"] = json.loads(out["options"])
            except: pass
        if out.get("result"):
            try: out["result"] = json.loads(out["result"])
            except: pass
        # приведи ISO к Z (у нас уже Z)
        return out
    finally:
        conn.close()

@app.get("/api/jobs")
def list_jobs(status: Optional[str] = None):
    conn = get_conn()
    try:
        cur = conn.cursor()
        if status:
            cur.execute("SELECT * FROM jobs WHERE status=? ORDER BY created_at ASC", (status,))
        else:
            cur.execute("SELECT * FROM jobs ORDER BY created_at ASC")
        rows = [dict(r) for r in cur.fetchall()]
        for r in rows:
            if r.get("options"):
                try: r["options"] = json.loads(r["options"])
                except: pass
            if r.get("result"):
                try: r["result"] = json.loads(r["result"])
                except: pass
        return rows
    finally:
        conn.close()

# ----------------------------
# Entrypoint
# ----------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=PORT, reload=True)
