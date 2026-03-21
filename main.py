import os
import shutil
import uuid
from datetime import datetime, timedelta
from typing import Optional, List
from urllib.parse import unquote

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Request, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import FileResponse
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt

# استيراد مكتبة السحاب
from supabase import create_client, Client

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
# --- 2. إدارة قاعدة البيانات (Supabase Cloud) ---
# ==========================================
# الرابط والمفتاح الصحيحان 100%
SUPABASE_URL = "https://xlgttngreiuihutjrlev.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InhsZ3R0bmdyZWl1aWh1dGpybGV2Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzQxMTY0OTgsImV4cCI6MjA4OTY5MjQ5OH0.4Il0UbMK0a2e-2B-OyB1uoyZ6mIv2cP1NeRCM-0fTKw"

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

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

app = FastAPI()
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
async def get_manifest(): return FileResponse("manifest.json")

@app.get("/favicon.ico")
async def get_favicon(): return FileResponse("static/teacher.jpg")

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
    # فحص التكرار
    existing = supabase.table("students").select("username").eq("username", username).execute()
    if existing.data and len(existing.data) > 0:
        raise HTTPException(status_code=400, detail="اسم المستخدم موجود مسبقاً")
    
    student_data = {
        "full_name": full_name, "username": username, "password": hash_password(password),
        "grade": grade, "school_name": school_name, "avatar_url": avatar_url
    }
    supabase.table("students").insert(student_data).execute()
    return {"status": "success", "message": "تم انضمام البطل لجيش الرياضيات"}

@app.post("/api/student/login")
async def login_student(username: str = Form(...), password: str = Form(...)):
    result = supabase.table("students").select("*").eq("username", username).execute()
    if result.data and len(result.data) > 0:
        user = result.data[0]
        if verify_password(password, user['password']):
            return {"status": "success", "user": user}
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
    exam_data = {
        "title": title, "exam_type": exam_type, "exam_date": exam_date, "exam_time": exam_time, 
        "target_lesson": target_lesson, "duration": duration, "num_questions": num_questions, 
        "points_per_q": points_per_q, "target_q_type": target_q_type
    }
    supabase.table("exams").insert(exam_data).execute()
    return {"status": "success"}

@app.get("/api/admin/stats")
async def get_student_stats(admin=Depends(get_current_admin)):
    students = supabase.table("students").select("id, full_name, grade").execute().data
    results = supabase.table("results").select("*").execute().data
    
    stats = []
    if students and results is not None:
        for s in students:
            s_results = [r for r in results if r.get('student_id') == s.get('id')]
            stats.append({
                "full_name": s.get('full_name', ''),
                "grade": s.get('grade', ''),
                "tests_count": len(s_results),
                "avg_score": (sum(r.get('score', 0) for r in s_results) / len(s_results)) if s_results else 0,
                "last_activity": max(r.get('timestamp') for r in s_results) if s_results else None
            })
    return stats

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
    
    q_data = {
        "grade": grade, "lesson": lesson, "subject": subject, "q_type": q_type, 
        "question": question, "options": options, "answer": answer, "image_url": img_path
    }
    supabase.table("questions").insert(q_data).execute()
    return {"status": "success"}

@app.put("/api/admin/questions/{q_id}")
async def edit_question(
    q_id: int, grade: str = Form(...), lesson: str = Form(...), subject: str = Form(...), 
    q_type: str = Form(...), question: str = Form(...), options: str = Form(""), 
    answer: str = Form(...), image: UploadFile = File(None),
    admin=Depends(get_current_admin)
):
    update_data = {
        "grade": grade, "lesson": lesson, "subject": subject, 
        "q_type": q_type, "question": question, "options": options, "answer": answer
    }
    if image:
        img_path = f"uploads/img_{uuid.uuid4().hex}{os.path.splitext(image.filename)[1]}"
        with open(os.path.join(BASE_DIR, img_path), "wb") as buffer: shutil.copyfileobj(image.file, buffer)
        update_data["image_url"] = img_path
        
    supabase.table("questions").update(update_data).eq("id", q_id).execute()
    return {"status": "success"}

@app.delete("/api/admin/questions/{q_id}")
async def delete_question(q_id: int, admin=Depends(get_current_admin)):
    supabase.table("questions").delete().eq("id", q_id).execute()
    return {"status": "success"}

@app.post("/api/admin/summaries")
async def upload_summary(lesson: str = Form(...), pdf: UploadFile = File(...), admin=Depends(get_current_admin)):
    pdf_path = f"uploads/summary_{uuid.uuid4().hex}{os.path.splitext(pdf.filename)[1]}"
    with open(os.path.join(BASE_DIR, pdf_path), "wb") as buffer: shutil.copyfileobj(pdf.file, buffer)
    
    # بديل لـ INSERT OR REPLACE في SQLite
    existing = supabase.table("summaries").select("id").eq("lesson", lesson).execute()
    if existing.data:
        supabase.table("summaries").update({"pdf_url": pdf_path}).eq("lesson", lesson).execute()
    else:
        supabase.table("summaries").insert({"lesson": lesson, "pdf_url": pdf_path}).execute()
        
    return {"status": "success"}

@app.get("/api/admin/summaries_list")
async def get_all_summaries():
    res = supabase.table("summaries").select("lesson, pdf_url").execute()
    return res.data if res.data else []

@app.delete("/api/admin/summaries/{lesson_name:path}")
async def delete_summary(lesson_name: str, admin=Depends(get_current_admin)):
    lesson_dec = unquote(lesson_name)
    row = supabase.table("summaries").select("pdf_url").eq("lesson", lesson_dec).execute()
    if row.data and len(row.data) > 0:
        try: os.remove(os.path.join(BASE_DIR, row.data[0]["pdf_url"]))
        except: pass
    supabase.table("summaries").delete().eq("lesson", lesson_dec).execute()
    return {"message": "Deleted"}

@app.get("/api/admin/results")
async def get_admin_results(admin=Depends(get_current_admin)):
    res = supabase.table("results").select("*").order("timestamp", desc=True).execute()
    return res.data if res.data else []

# السماح للطلاب بجلب الأسئلة لتشغيل اللعبة التعليمية
@app.get("/api/admin/questions")
async def get_questions_admin():
    res = supabase.table("questions").select("*").order("id", desc=True).execute()
    return res.data if res.data else []

# ==========================================
# --- 7. مسارات الطلاب وأولياء الأمور ---
# ==========================================
@app.post("/api/student/update")
async def update_student(student_id: int = Form(...), full_name: str = Form(...), school_name: str = Form(None), avatar_url: str = Form(None)):
    supabase.table("students").update({"full_name": full_name, "school_name": school_name, "avatar_url": avatar_url}).eq("id", student_id).execute()
    return {"status": "success"}

@app.post("/api/student/results")
async def save_result(student_id: int = Form(...), student_name: str = Form(...), lesson: str = Form(...), score: int = Form(...), total: int = Form(...)):
    res_data = {"student_id": student_id, "student_name": student_name, "lesson": lesson, "score": score, "total": total}
    supabase.table("results").insert(res_data).execute()
    return {"status": "success"}

@app.get("/api/leaderboard")
async def get_leaderboard():
    results = supabase.table("results").select("student_name, score").execute().data
    lb = {}
    if results:
        for r in results:
            lb[r['student_name']] = lb.get(r['student_name'], 0) + (r['score'] * 100)
    
    sorted_lb = sorted(lb.items(), key=lambda x: x[1], reverse=True)[:10]
    return [{"student_name": name, "total_points": points} for name, points in sorted_lb]

@app.get("/api/student/summaries/{lesson:path}")
async def get_student_summary(lesson: str):
    lesson_dec = unquote(lesson)
    res = supabase.table("summaries").select("pdf_url").eq("lesson", lesson_dec).execute()
    return {"pdf_url": res.data[0]["pdf_url"] if res.data and len(res.data) > 0 else None}

@app.get("/api/parent/search/{name:path}")
async def parent_search(name: str):
    name_dec = unquote(name)
    student_res = supabase.table("students").select("id, full_name, grade, school_name").ilike("full_name", f"%{name_dec}%").execute()
    
    if not student_res.data or len(student_res.data) == 0: return {"found": False}
    
    student = student_res.data[0]
    history = supabase.table("results").select("lesson, score, total, timestamp").eq("student_id", student["id"]).order("timestamp", desc=True).execute().data
    
    total_xp = 0
    if history: total_xp = sum(r.get("score", 0) for r in history) * 100
    else: history = []
    
    return {"found": True, "student": student, "total_xp": total_xp, "history": history}

@app.get("/api/exams/upcoming")
async def get_upcoming_exams():
    res = supabase.table("exams").select("*").order("exam_date", desc=False).order("exam_time", desc=False).execute()
    return res.data if res.data else []

@app.delete("/api/admin/exams/{exam_id}")
async def delete_exam(exam_id: int, admin=Depends(get_current_admin)):
    supabase.table("exams").delete().eq("id", exam_id).execute()
    return {"status": "success"}

if __name__ == "__main__":
    import uvicorn
    # تحسين التوافق مع بورت Render الديناميكي
    port = int(os.environ.get("PORT", 8000))
    print(f"🚀 إمبراطورية الرياضيات الملكية تفتح أبوابها السحابية على بورت {port}...")
    uvicorn.run(app, host="0.0.0.0", port=port)