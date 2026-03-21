import os
import shutil
import sqlite3
import uuid
import json
from datetime import datetime, timedelta
from typing import Optional, List
from urllib.parse import unquote
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Request, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import FileResponse
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt

# ==========================================
# --- 1. الإعدادات الأمنية (Security) ---
# ==========================================
SECRET_KEY = "ROYAL_MATH_968_OMAN" 
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480 

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
def hash_password(password: str): return pwd_context.hash(password)
def verify_password(plain, hashed): return pwd_context.verify(plain, hashed)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# ==========================================
# --- 2. إدارة قاعدة البيانات (Database) ---
# ==========================================
class Database:
    # تم تحديث الاسم ليتطابق مع الملف الحقيقي royal_platform.db (40KB)
    def __init__(self, db_path='royal_platform.db'):
        self.db_path = db_path

    def __enter__(self):
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        return self.conn

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None: self.conn.commit()
        self.conn.close()

# دالة حماية المسارات (Admin Only)
async def get_current_admin(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="غير مسموح بالدخول - يرجى تسجيل دخول المعلم")
    
    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("sub") != "admin": raise Exception()
        return payload.get("sub")
    except:
        raise HTTPException(status_code=401, detail="جلسة العمل غير صالحة")

# ==========================================
# --- 3. تهيئة البيئة والجداول ---
# ==========================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
STATIC_FOLDER = os.path.join(BASE_DIR, "static")
TEMPLATES_FOLDER = os.path.join(BASE_DIR, "templates")

for folder in [UPLOAD_FOLDER, STATIC_FOLDER, TEMPLATES_FOLDER]:
    if not os.path.exists(folder): os.makedirs(folder)

templates = Jinja2Templates(directory="templates")

def init_db():
    with Database() as db:
        db.executescript('''
            CREATE TABLE IF NOT EXISTS students (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL, username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL, grade TEXT NOT NULL,
                school_name TEXT, avatar_url TEXT
            );
            CREATE TABLE IF NOT EXISTS questions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                grade TEXT, lesson TEXT, subject TEXT, q_type TEXT,
                question TEXT, options TEXT, answer TEXT, image_url TEXT
            );
            CREATE TABLE IF NOT EXISTS results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id INTEGER, student_name TEXT, lesson TEXT,
                score INTEGER, total INTEGER, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (student_id) REFERENCES students (id)
            );
            CREATE TABLE IF NOT EXISTS summaries (
                id INTEGER PRIMARY KEY AUTOINCREMENT, lesson TEXT UNIQUE, pdf_url TEXT
            );
            CREATE TABLE IF NOT EXISTS exams (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL, exam_type TEXT NOT NULL, 
                exam_date TEXT NOT NULL, exam_time TEXT NOT NULL,
                target_lesson TEXT NOT NULL, duration INTEGER NOT NULL DEFAULT 15,
                num_questions INTEGER NOT NULL DEFAULT 10, points_per_q INTEGER NOT NULL DEFAULT 10,
                target_q_type TEXT NOT NULL DEFAULT 'all'
            );
        ''')

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# تأمين الوصول للمجلدات الثابتة
app.mount("/uploads", StaticFiles(directory=UPLOAD_FOLDER), name="uploads")
app.mount("/static", StaticFiles(directory=STATIC_FOLDER), name="static")

# ==========================================
# --- 4. مسارات العرض (HTML & PWA) ---
# ==========================================
@app.get("/")
async def read_root(request: Request): return templates.TemplateResponse("index.html", {"request": request})

@app.get("/admin")
async def read_admin(request: Request): return templates.TemplateResponse("admin.html", {"request": request})

@app.get("/student")
async def read_student(request: Request): return templates.TemplateResponse("student.html", {"request": request})

@app.get("/parent")
async def read_parent(request: Request): return templates.TemplateResponse("parent.html", {"request": request})

# --- روابط الـ PWA والأيقونات لإصلاح أخطاء الـ 404 ---
@app.get("/manifest.json")
async def get_manifest():
    return FileResponse("manifest.json")

@app.get("/favicon.ico")
async def get_favicon():
    return FileResponse("static/teacher.jpg")

# ==========================================
# --- 5. نظام الدخول والحماية ---
# ==========================================
@app.post("/api/admin/login")
async def admin_login(username: str = Form(...), password: str = Form(...)):
    if username == "admin" and password == "Roshdy@2026":
        token = create_access_token(data={"sub": username})
        return {"access_token": token, "token_type": "bearer"}
    raise HTTPException(status_code=401, detail="خطأ في بيانات دخول المعلم")

@app.post("/api/student/register")
async def register_student(
    full_name: str = Form(...), username: str = Form(...), 
    password: str = Form(...), grade: str = Form(...),
    school_name: str = Form(None), avatar_url: str = Form(None)
):
    with Database() as db:
        try:
            db.execute('INSERT INTO students (full_name, username, password, grade, school_name, avatar_url) VALUES (?, ?, ?, ?, ?, ?)', 
                       (full_name, username, hash_password(password), grade, school_name, avatar_url))
            return {"status": "success", "message": "تم انضمام البطل لجيش الرياضيات"}
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=400, detail="اسم المستخدم موجود مسبقاً")

@app.post("/api/student/login")
async def login_student(username: str = Form(...), password: str = Form(...)):
    with Database() as db:
        user = db.execute('SELECT * FROM students WHERE username = ?', (username,)).fetchone()
    if user and verify_password(password, user['password']):
        return {"status": "success", "user": dict(user)}
    raise HTTPException(status_code=401, detail="بيانات الدخول غير صحيحة")

# ==========================================
# --- 6. مسارات المعلم (Admin - المحمية) ---
# ==========================================
@app.post("/api/admin/exams")
async def create_exam(
    title: str = Form(...), exam_type: str = Form(...), exam_date: str = Form(...), 
    exam_time: str = Form(...), target_lesson: str = Form(...), duration: int = Form(...),
    num_questions: int = Form(...), points_per_q: int = Form(...), target_q_type: str = Form(...),
    admin=Depends(get_current_admin)
):
    with Database() as db:
        db.execute('''INSERT INTO exams (title, exam_type, exam_date, exam_time, target_lesson, duration, num_questions, points_per_q, target_q_type) 
                      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''', 
                   (title, exam_type, exam_date, exam_time, target_lesson, duration, num_questions, points_per_q, target_q_type))
    return {"status": "success"}

@app.get("/api/admin/stats")
async def get_student_stats(admin=Depends(get_current_admin)):
    with Database() as db:
        query = '''SELECT s.full_name, s.grade, COUNT(r.id) as tests_count, AVG(r.score) as avg_score, MAX(r.timestamp) as last_activity
                   FROM students s LEFT JOIN results r ON s.id = r.student_id GROUP BY s.id'''
        rows = db.execute(query).fetchall()
    return [dict(row) for row in rows]

@app.post("/api/admin/questions")
async def add_question(
    grade: str = Form(...), lesson: str = Form(...), subject: str = Form(...), 
    q_type: str = Form(...), question: str = Form(...), options: str = Form(""), 
    answer: str = Form(...), image: UploadFile = File(None),
    admin=Depends(get_current_admin)
):
    img_path = ""
    if image:
        img_path = f"uploads/img_{uuid.uuid4().hex}{os.path.splitext(image.filename)[1]}"
        with open(os.path.join(BASE_DIR, img_path), "wb") as buffer: shutil.copyfileobj(image.file, buffer)
    with Database() as db:
        db.execute('INSERT INTO questions (grade, lesson, subject, q_type, question, options, answer, image_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', 
                  (grade, lesson, subject, q_type, question, options, answer, img_path))
    return {"status": "success"}

@app.put("/api/admin/questions/{q_id}")
async def edit_question(
    q_id: int, grade: str = Form(...), lesson: str = Form(...), subject: str = Form(...), 
    q_type: str = Form(...), question: str = Form(...), options: str = Form(""), 
    answer: str = Form(...), image: UploadFile = File(None),
    admin=Depends(get_current_admin)
):
    with Database() as db:
        if image:
            img_path = f"uploads/img_{uuid.uuid4().hex}{os.path.splitext(image.filename)[1]}"
            with open(os.path.join(BASE_DIR, img_path), "wb") as buffer: shutil.copyfileobj(image.file, buffer)
            db.execute('UPDATE questions SET grade=?, lesson=?, subject=?, q_type=?, question=?, options=?, answer=?, image_url=? WHERE id=?', 
                       (grade, lesson, subject, q_type, question, options, answer, img_path, q_id))
        else:
            db.execute('UPDATE questions SET grade=?, lesson=?, subject=?, q_type=?, question=?, options=?, answer=? WHERE id=?', 
                       (grade, lesson, subject, q_type, question, options, answer, q_id))
    return {"status": "success"}

@app.delete("/api/admin/questions/{q_id}")
async def delete_question(q_id: int, admin=Depends(get_current_admin)):
    with Database() as db: db.execute("DELETE FROM questions WHERE id=?", (q_id,))
    return {"status": "success"}

@app.post("/api/admin/summaries")
async def upload_summary(lesson: str = Form(...), pdf: UploadFile = File(...), admin=Depends(get_current_admin)):
    pdf_path = f"uploads/summary_{uuid.uuid4().hex}{os.path.splitext(pdf.filename)[1]}"
    with open(os.path.join(BASE_DIR, pdf_path), "wb") as buffer: shutil.copyfileobj(pdf.file, buffer)
    with Database() as db: db.execute('INSERT OR REPLACE INTO summaries (lesson, pdf_url) VALUES (?, ?)', (lesson, pdf_path))
    return {"status": "success"}

@app.get("/api/admin/summaries_list")
async def get_all_summaries():
    with Database() as db: rows = db.execute("SELECT lesson, pdf_url FROM summaries").fetchall()
    return [dict(row) for row in rows]

@app.delete("/api/admin/summaries/{lesson_name:path}")
async def delete_summary(lesson_name: str, admin=Depends(get_current_admin)):
    lesson_dec = unquote(lesson_name)
    with Database() as db:
        row = db.execute("SELECT pdf_url FROM summaries WHERE lesson=?", (lesson_dec,)).fetchone()
        if row:
            try: os.remove(os.path.join(BASE_DIR, row["pdf_url"]))
            except: pass
        db.execute("DELETE FROM summaries WHERE lesson=?", (lesson_dec,))
    return {"message": "Deleted"}

@app.get("/api/admin/results")
async def get_admin_results(admin=Depends(get_current_admin)):
    with Database() as db: rows = db.execute("SELECT * FROM results ORDER BY timestamp DESC").fetchall()
    return [dict(row) for row in rows]

# السماح للطلاب بجلب الأسئلة لتشغيل اللعبة التعليمية
@app.get("/api/admin/questions")
async def get_questions_admin():
    with Database() as db: rows = db.execute("SELECT * FROM questions ORDER BY id DESC").fetchall()
    return [dict(row) for row in rows]

# ==========================================
# --- 7. مسارات الطلاب وأولياء الأمور ---
# ==========================================
@app.post("/api/student/update")
async def update_student(student_id: int = Form(...), full_name: str = Form(...), school_name: str = Form(None), avatar_url: str = Form(None)):
    with Database() as db: db.execute('UPDATE students SET full_name=?, school_name=?, avatar_url=? WHERE id=?', (full_name, school_name, avatar_url, student_id))
    return {"status": "success"}

@app.post("/api/student/results")
async def save_result(student_id: int = Form(...), student_name: str = Form(...), lesson: str = Form(...), score: int = Form(...), total: int = Form(...)):
    with Database() as db: db.execute('INSERT INTO results (student_id, student_name, lesson, score, total) VALUES (?, ?, ?, ?, ?)', (student_id, student_name, lesson, score, total))
    return {"status": "success"}

@app.get("/api/leaderboard")
async def get_leaderboard():
    with Database() as db:
        rows = db.execute('SELECT student_name, (SUM(score) * 100) as total_points FROM results GROUP BY student_name ORDER BY total_points DESC LIMIT 10').fetchall()
    return [dict(row) for row in rows]

@app.get("/api/student/summaries/{lesson:path}")
async def get_student_summary(lesson: str):
    lesson_dec = unquote(lesson)
    with Database() as db: row = db.execute("SELECT pdf_url FROM summaries WHERE lesson = ?", (lesson_dec,)).fetchone()
    return {"pdf_url": row["pdf_url"] if row else None}

@app.get("/api/parent/search/{name:path}")
async def parent_search(name: str):
    name_dec = unquote(name)
    with Database() as db:
        student = db.execute("SELECT id, full_name, grade, school_name FROM students WHERE full_name LIKE ?", (f"%{name_dec}%",)).fetchone()
        if not student: return {"found": False}
        results = db.execute("SELECT lesson, score, total, timestamp FROM results WHERE student_id = ? ORDER BY timestamp DESC", (student["id"],)).fetchall()
        total_points = db.execute("SELECT SUM(score) * 100 FROM results WHERE student_id = ?", (student["id"],)).fetchone()[0] or 0
    return {"found": True, "student": dict(student), "total_xp": total_points, "history": [dict(r) for r in results]}

@app.get("/api/exams/upcoming")
async def get_upcoming_exams():
    with Database() as db: rows = db.execute("SELECT * FROM exams ORDER BY exam_date ASC, exam_time ASC").fetchall()
    return [dict(row) for row in rows]

@app.delete("/api/admin/exams/{exam_id}")
async def delete_exam(exam_id: int, admin=Depends(get_current_admin)):
    with Database() as db: db.execute("DELETE FROM exams WHERE id=?", (exam_id,))
    return {"status": "success"}

if __name__ == "__main__":
    import uvicorn
    # تحسين التوافق مع بورت Render الديناميكي
    port = int(os.environ.get("PORT", 8000))
    print(f"🚀 إمبراطورية الرياضيات الملكية تفتح أبوابها على بورت {port}...")
    uvicorn.run(app, host="0.0.0.0", port=port)