import os
import uuid
import random
from datetime import datetime, timedelta, timezone
from typing import Optional, List
from urllib.parse import unquote

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Request, Depends, status, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import FileResponse, JSONResponse
from passlib.context import CryptContext
from jose import JWTError, jwt

# استيراد مكتبة السحاب (Supabase)
from supabase import create_client, Client

# Rate Limiting — منطق يدوي في الذاكرة (لا يحتاج مكتبة خارجية)
import time as _time
from collections import defaultdict as _defaultdict

_rate_store: dict = _defaultdict(list)  # {ip: [timestamps]}

def _is_rate_limited(ip: str, max_calls: int, window_seconds: int) -> bool:
    """يتحقق إذا تجاوز الـ IP الحد المسموح — يُرجع True إذا محظور"""
    now = _time.time()
    calls = _rate_store[ip]
    # احتفظ فقط بالطلبات داخل النافذة الزمنية
    _rate_store[ip] = [t for t in calls if now - t < window_seconds]
    if len(_rate_store[ip]) >= max_calls:
        return True
    _rate_store[ip].append(now)
    return False

# ==========================================
# --- 1. الإعدادات الأمنية والاتصال ---
# ==========================================
# ══════════════════════════════════════════════════
# الأسرار تُقرأ من متغيرات البيئة (.env) — لا تكتب
# أي قيمة حرفية هنا أبداً
# ══════════════════════════════════════════════════
# python-dotenv اختياري — يمكن ضبط المتغيرات مباشرة في البيئة
try:
    import importlib.util as _ilu
    if _ilu.find_spec("dotenv") is not None:
        from dotenv import load_dotenv  # type: ignore[import]
        load_dotenv()
except Exception:
    pass

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "ROYAL_MATH_968_OMAN")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480

# بيانات الاتصال بـ Supabase — من متغيرات البيئة
SUPABASE_URL = os.getenv("SUPABASE_URL", "https://xlgttngreiuihutjrlev.supabase.co")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InhsZ3R0bmdyZWl1aWh1dGpybGV2Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzQxMTY0OTgsImV4cCI6MjA4OTY5MjQ5OH0.4Il0UbMK0a2e-2B-OyB1uoyZ6mIv2cP1NeRCM-0fTKw")

# كلمة مرور الأدمن — من متغيرات البيئة
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "Roshdy@2026")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

def hash_password(password: str): return pwd_context.hash(password)
def verify_password(plain, hashed): return pwd_context.verify(plain, hashed)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# ==========================================
# --- 2. تهيئة التطبيق ومعالجة الأخطاء ---
# ==========================================
app = FastAPI(title="Math Empire API")

# Rate Limiter — يدوي في الذاكرة، لا يحتاج تسجيل

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    print(f"Error occurred: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={"status": "error", "message": "عطل في الديوان الملكي"},
    )

# النطاقات المسموح بها — أضف نطاق إنتاجك هنا
_ALLOWED_ORIGINS = [o.strip() for o in os.getenv(
    "ALLOWED_ORIGINS",
    "http://localhost:8001,http://127.0.0.1:8001"
).split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
for folder in ["static", "templates"]:
    path = os.path.join(BASE_DIR, folder)
    if not os.path.exists(path): os.makedirs(path)

templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")

async def get_current_admin(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="يرجى تسجيل دخول المعلم")
    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("sub") != "admin": raise Exception()
        return payload.get("sub")
    except:
        raise HTTPException(status_code=401, detail="جلسة العمل غير صالحة")

# ==========================================
# --- 3. مسارات العرض (HTML) والملفات التقنية ---
# ==========================================
@app.get("/")
async def read_root(request: Request): return templates.TemplateResponse(request=request, name="index.html")

@app.get("/admin")
async def read_admin(request: Request): return templates.TemplateResponse(request=request, name="admin.html")

@app.get("/student")
async def read_student(request: Request): return templates.TemplateResponse(request=request, name="student.html")

@app.get("/parent")
async def read_parent(request: Request): return templates.TemplateResponse(request=request, name="parent.html")

@app.get("/teachers")
async def read_teachers(request: Request): return templates.TemplateResponse(request=request, name="teachers.html")

@app.get("/manifest.json")
async def get_manifest(): return FileResponse(os.path.join(BASE_DIR, "manifest.json"))

@app.get("/sw.js")
async def get_sw(): return FileResponse(os.path.join(BASE_DIR, "static", "sw.js"))

# ==========================================
# --- 4. نظام الدخول (إمبراطور / طالب / معلم) ---
# ==========================================
@app.post("/api/admin/login")
async def admin_login(request: Request, username: str = Form(...), password: str = Form(...)):
    # Rate limit: 5 محاولات/دقيقة لكل IP
    client_ip = request.client.host if request.client else "unknown"
    if _is_rate_limited(client_ip, max_calls=5, window_seconds=60):
        raise HTTPException(status_code=429, detail="⏳ تجاوزت عدد المحاولات المسموحة — انتظر دقيقة")
    if username == os.getenv("ADMIN_USERNAME", "admin") and password == ADMIN_PASSWORD:
        token = create_access_token(data={"sub": username})
        return {"access_token": token, "token_type": "bearer"}
    raise HTTPException(status_code=401, detail="بيانات دخول المعلم خاطئة")

@app.post("/api/teacher/register")
async def register_teacher(full_name: str=Form(...), username: str=Form(...), password: str=Form(...)):
    existing = supabase.table("teachers").select("username").eq("username", username).execute()
    if existing.data: raise HTTPException(status_code=400, detail="المستخدم موجود مسبقاً")
    supabase.table("teachers").insert({
        "full_name": full_name, 
        "username": username, 
        "password": hash_password(password)
    }).execute()
    return {"status": "success"}

@app.post("/api/teacher/login")
async def teacher_login(username: str = Form(...), password: str = Form(...)):
    res = supabase.table("teachers").select("*").eq("username", username).execute()
    if res.data and verify_password(password, res.data[0]['password']):
        return {"status": "success", "user": res.data[0]}

    raise HTTPException(status_code=401, detail="بيانات الدخول خاطئة")

@app.post("/api/student/register")
async def register_student(
    full_name: str=Form(...), username: str=Form(...),
    password: str=Form(...), grade: str=Form(...),
    parent_code: str=Form(default="")
):
    existing = supabase.table("students").select("username").eq("username", username).execute()
    if existing.data: raise HTTPException(status_code=400, detail="المستخدم موجود مسبقاً")
    supabase.table("students").insert({
        "full_name":   full_name,
        "username":    username,
        "password":    hash_password(password),
        "grade":       grade,
        "parent_code": parent_code or None,
    }).execute()
    return {"status": "success"}

@app.post("/api/student/login")
async def login_student(request: Request, username: str = Form(...), password: str = Form(...)):
    # Rate limit: 10 محاولات/دقيقة لكل IP
    client_ip = request.client.host if request.client else "unknown"
    if _is_rate_limited(client_ip, max_calls=10, window_seconds=60):
        raise HTTPException(status_code=429, detail="⏳ تجاوزت عدد المحاولات المسموحة — انتظر دقيقة")
    res = supabase.table("students").select("*").eq("username", username).execute()
    if res.data and verify_password(password, res.data[0]['password']):
        user = res.data[0]
        user.pop('password', None)
        return {"status": "success", "user": user}
    raise HTTPException(status_code=401, detail="بيانات الدخول خاطئة")

# ==========================================
# --- 5. مسار المنحة الملكية (XP اليدوي) ---
# ==========================================
@app.post("/api/admin/grant_xp")
async def grant_xp(student_name: str = Form(...), points: int = Form(...), admin=Depends(get_current_admin)):
    supabase.table("results").insert({
        "student_name": student_name,
        "lesson": "💎 منحة ملكية تقديرية من الأستاذ رشدي",
        "score": points,
        "total": points
    }).execute()
    return {"status": "success"}

# ==========================================
# --- 6. إدارة المنهج الدراسي ---
# ==========================================
@app.post("/api/admin/curriculum/grades")
async def add_grade(name: str = Form(...), admin=Depends(get_current_admin)):
    return supabase.table("grades").insert({"name": name}).execute()

@app.post("/api/admin/curriculum/semesters")
async def add_semester(grade_id: int = Form(...), name: str = Form(...), admin=Depends(get_current_admin)):
    return supabase.table("semesters").insert({"grade_id": grade_id, "name": name}).execute()

@app.post("/api/admin/curriculum/units")
async def add_unit(semester_id: int = Form(...), name: str = Form(...), admin=Depends(get_current_admin)):
    return supabase.table("units").insert({"semester_id": semester_id, "name": name}).execute()

@app.post("/api/admin/curriculum/lessons")
async def add_lesson(unit_id: int = Form(...), name: str = Form(...), admin=Depends(get_current_admin)):
    return supabase.table("lessons").insert({"unit_id": unit_id, "name": name}).execute()

@app.put("/api/admin/curriculum/grades/{item_id}")
async def update_grade(item_id: int, name: str = Form(...), admin=Depends(get_current_admin)):
    supabase.table("grades").update({"name": name}).eq("id", item_id).execute()
    return {"status": "success"}

@app.put("/api/admin/curriculum/semesters/{item_id}")
async def update_semester(item_id: int, name: str = Form(...), admin=Depends(get_current_admin)):
    supabase.table("semesters").update({"name": name}).eq("id", item_id).execute()
    return {"status": "success"}

@app.put("/api/admin/curriculum/units/{item_id}")
async def update_unit(item_id: int, name: str = Form(...), admin=Depends(get_current_admin)):
    supabase.table("units").update({"name": name}).eq("id", item_id).execute()
    return {"status": "success"}

@app.put("/api/admin/curriculum/lessons/{item_id}")
async def update_lesson(item_id: int, name: str = Form(...), admin=Depends(get_current_admin)):
    supabase.table("lessons").update({"name": name}).eq("id", item_id).execute()
    return {"status": "success"}

@app.delete("/api/admin/curriculum/grades/{item_id}")
async def delete_grade(item_id: int, admin=Depends(get_current_admin)):
    supabase.table("grades").delete().eq("id", item_id).execute()
    return {"status": "success"}

@app.delete("/api/admin/curriculum/semesters/{item_id}")
async def delete_semester(item_id: int, admin=Depends(get_current_admin)):
    supabase.table("semesters").delete().eq("id", item_id).execute()
    return {"status": "success"}

@app.delete("/api/admin/curriculum/units/{item_id}")
async def delete_unit(item_id: int, admin=Depends(get_current_admin)):
    supabase.table("units").delete().eq("id", item_id).execute()
    return {"status": "success"}

@app.delete("/api/admin/curriculum/lessons/{item_id}")
async def delete_lesson(item_id: int, admin=Depends(get_current_admin)):
    supabase.table("lessons").delete().eq("id", item_id).execute()
    return {"status": "success"}

@app.get("/api/curriculum/structure")
async def get_full_structure():
    try:
        res = supabase.table("grades").select("*, semesters(*, units(*, lessons(*)))").execute()
        data = res.data or []
    except Exception as e:
        print(f"curriculum/structure error: {e}")
        # fallback: جلب الصفوف فقط بدون nested
        try:
            res = supabase.table("grades").select("id, name").execute()
            data = [{"id": g["id"], "name": g["name"], "semesters": []} for g in (res.data or [])]
        except:
            return []

    # ترتيب احتياطي إذا لم يكن sort_order موجوداً
    grade_order = [
        'الصف الخامس','الصف السادس','الصف السابع','الصف الثامن',
        'الصف التاسع','الصف العاشر',
        'الصف الحادي عشر (متقدم)','الصف الحادي عشر(اساسي)',
        'الصف الثاني عشر (متقدم)','الصف الثاني عشر (أساسي)',
    ]

    def grade_sort_key(g):
        name = (g.get("name") or "").strip()
        try:
            return grade_order.index(name)
        except ValueError:
            return 999

    data.sort(key=grade_sort_key)

    # trim الفراغات الزائدة من جميع الأسماء
    for g in data:
        g["name"] = (g.get("name") or "").strip()
        for s in (g.get("semesters") or []):
            s["name"] = (s.get("name") or "").strip()
            for u in (s.get("units") or []):
                u["name"] = (u.get("name") or "").strip()
                for l in (u.get("lessons") or []):
                    l["name"] = (l.get("name") or "").strip()
    return data

# ==========================================
# --- 7. بنك الأسئلة والامتحانات ---
# ==========================================
@app.post("/api/admin/questions")
async def add_question(
    grade: str=Form(...), lesson: str=Form(...), subject: str=Form(...), 
    q_type: str=Form(...), question: str=Form(...), options: str=Form(""), 
    answer: str=Form(...), image: UploadFile=File(None), admin=Depends(get_current_admin)
):
    img_url = ""
    if image and image.filename:
        img_name = f"q_img_{uuid.uuid4().hex}{os.path.splitext(image.filename)[1]}"
        content = await image.read()
        supabase.storage.from_("resources").upload(path=img_name, file=content, file_options={"content-type": image.content_type})
        img_url = supabase.storage.from_("resources").get_public_url(img_name)
    
    supabase.table("questions").insert({
        "grade": grade, "lesson": lesson, "subject": subject, "q_type": q_type, 
        "question": question, "options": options, "answer": answer, "image_url": img_url
    }).execute()
    return {"status": "success"}

@app.put("/api/admin/questions/{q_id}")
async def update_question(
    q_id: int, grade: str=Form(...), lesson: str=Form(...), subject: str=Form(...), 
    q_type: str=Form(...), question: str=Form(...), options: str=Form(""), 
    answer: str=Form(...), image: UploadFile=File(None), admin=Depends(get_current_admin)
):
    update_data = {
        "grade": grade, "lesson": lesson, "subject": subject, "q_type": q_type, 
        "question": question, "options": options, "answer": answer
    }
    
    if image and image.filename:
        img_name = f"q_img_{uuid.uuid4().hex}{os.path.splitext(image.filename)[1]}"
        content = await image.read()
        supabase.storage.from_("resources").upload(path=img_name, file=content, file_options={"content-type": image.content_type})
        update_data["image_url"] = supabase.storage.from_("resources").get_public_url(img_name)

    supabase.table("questions").update(update_data).eq("id", q_id).execute()
    return {"status": "success"}

@app.delete("/api/admin/questions/{q_id}")
async def delete_question(q_id: int, admin=Depends(get_current_admin)):
    supabase.table("questions").delete().eq("id", q_id).execute()
    return {"status": "success"}

@app.get("/api/admin/questions")
async def get_all_questions(admin=Depends(get_current_admin)):
    """جلب الأسئلة كاملةً للأدمن فقط (مع الإجابات)"""
    res = supabase.table("questions").select("*").order("id", desc=True).execute()
    return res.data if res.data else []

def _grade_variants(grade: str) -> list:
    """يولّد جميع الصيغ الممكنة لاسم الصف لضمان تطابق الأسئلة المخزونة بأي صيغة"""
    if not grade:
        return []
    s = grade.strip()
    # نضيف الصيغة الأصلية + مع مسافات (لأن Supabase قد يخزنها بمسافات زائدة)
    variants = {s, f" {s} ", f" {s}", f"{s} "}

    # خريطة الأرقام العربية ↔ الأرقام
    ar_to_num = {
        "الأول":"1","الثاني":"2","الثالث":"3","الرابع":"4","الخامس":"5","السادس":"6",
        "السابع":"7","الثامن":"8","التاسع":"9","العاشر":"10","الحادي عشر":"11","الثاني عشر":"12",
    }
    num_to_ar = {v: k for k, v in ar_to_num.items()}

    import re
    # حالة 1: "الصف السادس" → نستخرج "السادس" ثم "6"
    m = re.match(r"الصف\s+(.+)", s)
    if m:
        word = m.group(1).strip()
        num  = ar_to_num.get(word, word)
        variants.update([num, f"الصف {word}", f"الصف {num}", word])

    # حالة 2: "السادس" فقط (بدون "الصف") → نضيف "6" و"الصف السادس"
    elif s in ar_to_num:
        num  = ar_to_num[s]
        variants.update([num, f"الصف {s}", f"الصف {num}"])

    # حالة 3: رقم مجرد "6" → نضيف "السادس" و"الصف السادس"
    elif re.match(r"^\d+$", s):
        word = num_to_ar.get(s, s)
        variants.update([f"الصف {word}", f"الصف {s}", word])

    return list(variants)


@app.get("/api/student/questions")
async def get_questions_for_student(grade: str, lesson: str = ""):
    """
    جلب الأسئلة للطالب — بدون حقل answer
    - يدعم جميع صيغ اسم الصف (الصف السادس / 6 / السادس)
    - إذا أُرسل lesson يُفلتر به، وإلا يُرجع كل أسئلة الصف
    - يُرجع الأسئلة حتى لو لم يكن هناك منهج مبني (للأسئلة القديمة)
    """
    variants = _grade_variants(grade)

    all_questions = []
    seen_ids: set = set()

    # إذا لم تتوفر أي صيغة — أرجع كل الأسئلة (fallback للأسئلة القديمة)
    search_variants = variants if variants else [grade] if grade else []

    for v in search_variants:
        v_stripped = v.strip()
        query = supabase.table("questions").select(
            "id, grade, lesson, subject, q_type, question, options, image_url"
        ).eq("grade", v_stripped)
        if lesson:
            query = query.ilike("lesson", lesson.strip())
        res = query.execute()
        for q in (res.data or []):
            if q["id"] not in seen_ids:
                seen_ids.add(q["id"])
                all_questions.append(q)

    # إذا لم نجد شيئاً وكان lesson محدداً — جرّب بحث جزئي في lesson
    if not all_questions and lesson:
        for v in search_variants:
            res = supabase.table("questions").select(
                "id, grade, lesson, subject, q_type, question, options, image_url"
            ).eq("grade", v).ilike("lesson", f"%{lesson.strip()}%").execute()
            for q in (res.data or []):
                if q["id"] not in seen_ids:
                    seen_ids.add(q["id"])
                    all_questions.append(q)

    return all_questions


@app.get("/api/admin/debug/questions")
async def debug_questions(admin=Depends(get_current_admin)):
    """
    نقطة تشخيصية — تُظهر قيم grade و lesson المخزونة فعلياً في Supabase
    مفيدة لمعرفة لماذا لا تظهر الأسئلة عند الطلاب
    """
    res = supabase.table("questions").select("id, grade, lesson, q_type").order("id", desc=True).limit(200).execute()
    if not res.data:
        return {"count": 0, "grades": [], "lessons": [], "samples": []}
    
    grades  = sorted(set(q["grade"]  or "" for q in res.data))
    lessons = sorted(set(q["lesson"] or "" for q in res.data))
    return {
        "count":   len(res.data),
        "grades":  grades,
        "lessons": lessons,
        "samples": res.data[:10],
    }

@app.post("/api/admin/exams")
async def create_exam(
    title: str=Form(...), exam_date: str=Form(...), 
    exam_time: str=Form(...), target_lesson: str=Form(...), duration: int=Form(...),
    exam_type: str=Form(default="ملحمة أسبوعية"), num_questions: int=Form(default=10), 
    points_per_q: int=Form(default=10), target_q_type: str=Form(default="all"),
    admin=Depends(get_current_admin)
):
    supabase.table("exams").insert({
        "title": title, "exam_type": exam_type, "exam_date": exam_date, "exam_time": exam_time, 
        "target_lesson": target_lesson, "duration": duration, "num_questions": num_questions, 
        "points_per_q": points_per_q, "target_q_type": target_q_type
    }).execute()
    return {"status": "success"}

@app.get("/api/exams/upcoming")
async def get_upcoming_exams():
    res = supabase.table("exams").select("*").order("id", desc=True).execute()
    return res.data if res.data else []

@app.delete("/api/admin/exams/{exam_id}")
async def delete_exam(exam_id: int, admin=Depends(get_current_admin)):
    supabase.table("exams").delete().eq("id", exam_id).execute()
    return {"status": "success"}

# ==========================================
# --- 8. ديوان الموارد ولفائف المعرفة ---
# ==========================================
@app.get("/api/resources")
async def get_resources(grade: str, semester: str, category: str = "all"):
    query = supabase.table("teacher_resources").select("*").eq("grade", grade).eq("semester", semester)
    if category != "all":
        query = query.eq("category", category)
    res = query.execute()
    return res.data

@app.get("/api/admin/all_resources")
async def get_all_resources(admin=Depends(get_current_admin)):
    res = supabase.table("teacher_resources").select("*").order("id", desc=True).execute()
    return res.data if res.data else []

@app.post("/api/admin/resources")
async def add_resource(
    title: str=Form(...), grade: str=Form(...), semester: str=Form(...), 
    category: str=Form(...), description: str=Form(""), 
    file: UploadFile=File(...), admin=Depends(get_current_admin)
):
    file_extension = os.path.splitext(file.filename)[1]
    file_name = f"res_{uuid.uuid4().hex}{file_extension}"
    
    content = await file.read()
    
    supabase.storage.from_("resources").upload(
        path=file_name, 
        file=content,
        file_options={"content-type": file.content_type}
    )
    file_url = supabase.storage.from_("resources").get_public_url(file_name)
    
    supabase.table("teacher_resources").insert({
        "title": title, "grade": grade, "semester": semester, 
        "category": category, "description": description, "file_url": file_url
    }).execute()
    return {"status": "success"}

@app.delete("/api/admin/resources/{res_id}")
async def delete_resource(res_id: int, admin=Depends(get_current_admin)):
    supabase.table("teacher_resources").delete().eq("id", res_id).execute()
    return {"status": "success"}

@app.post("/api/admin/summaries")
async def upload_summary(
    lesson:         str         = Form(...),
    resource_type:  str         = Form(default="pdf"),
    resource_label: str         = Form(default=""),
    external_url:   str         = Form(default=""),
    pdf:            UploadFile  = File(default=None),
    admin=Depends(get_current_admin)
):
    """رفع مصدر تعليمي — PDF أو فيديو أو رابط خارجي"""
    try:
        is_file_type = resource_type in ("pdf", "worksheet")

        if is_file_type:
            if not pdf or not pdf.filename:
                raise HTTPException(status_code=400, detail="يرجى إرفاق ملف")
            file_extension = os.path.splitext(pdf.filename)[1] or ".pdf"
            file_name      = f"res_{uuid.uuid4().hex}{file_extension}"
            content        = await pdf.read()
            content_type   = pdf.content_type or "application/pdf"
            supabase.storage.from_("resources").upload(
                path=file_name, file=content,
                file_options={"content-type": content_type}
            )
            resource_url = supabase.storage.from_("resources").get_public_url(file_name)
        else:
            if not external_url:
                raise HTTPException(status_code=400, detail="يرجى إدخال الرابط الخارجي")
            resource_url = external_url

        row = {
            "lesson":         lesson,
            "pdf_url":        resource_url,
            "resource_type":  resource_type,
            "resource_label": resource_label,
        }
        supabase.table("summaries").insert(row).execute()
        return {"status": "success", "url": resource_url}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/admin/summaries_list")
async def get_summaries():
    res = supabase.table("summaries").select("*").order("id", desc=True).execute()
    return res.data if res.data else []


@app.delete("/api/admin/summaries/{resource_id}")
async def delete_summary(resource_id: str, admin=Depends(get_current_admin)):
    """حذف مصدر بالمعرّف أو باسم الدرس (للتوافق مع الكود القديم)"""
    if resource_id.isdigit():
        supabase.table("summaries").delete().eq("id", int(resource_id)).execute()
    else:
        clean = unquote(resource_id)
        supabase.table("summaries").delete().eq("lesson", clean).execute()
    return {"status": "success"}

# ==========================================
# --- 9. النتائج ولوحة الشرف والبحث ---
# ==========================================
@app.post("/api/student/results")
async def save_result(student_id: int=Form(...), student_name: str=Form(...), lesson: str=Form(...), score: int=Form(...), total: int=Form(...)):
    supabase.table("results").insert({"student_id": student_id, "student_name": student_name, "lesson": lesson, "score": score, "total": total}).execute()
    return {"status": "success"}

@app.get("/api/leaderboard")
async def get_lb():
    res = supabase.table("results").select("student_name, score").execute().data
    lb = {}
    if res:
        for r in res: 
            lb[r['student_name']] = lb.get(r['student_name'], 0) + r['score']
    sorted_lb = sorted(lb.items(), key=lambda x: x[1], reverse=True)[:10]
    return [{"student_name": k, "total_points": v} for k, v in sorted_lb]

@app.get("/api/parent/search/{query:path}")
async def parent_search(query: str):
    """بحث ولي الأمر — يدعم: رقم معرف، كود RS-، اسم المستخدم، اسم الطالب"""
    clean = unquote(query).strip()
    if not clean:
        return {"found": False, "message": "يرجى إدخال الاسم أو الرمز"}

    st = None

    # بحث برقم المعرف
    if clean.isdigit():
        st = supabase.table("students").select("id, full_name, grade, username, created_at").eq("id", int(clean)).execute()

    # بحث بـ parent_code (RS-XXXXX)
    if not (st and st.data):
        pc = clean if clean.upper().startswith("RS-") else f"RS-{clean}"
        st = supabase.table("students").select("id, full_name, grade, username, created_at").eq("parent_code", pc.upper()).execute()

    # بحث بـ username
    if not (st and st.data):
        st = supabase.table("students").select("id, full_name, grade, username, created_at").ilike("username", clean).execute()

    # بحث بالاسم جزئي
    if not (st and st.data):
        st = supabase.table("students").select("id, full_name, grade, username, created_at").ilike("full_name", f"%{clean}%").execute()

    if not st.data:
        return {"found": False, "message": "لم يعثر على طالب بهذا الاسم او الرمز"}

    student = st.data[0]
    student.pop("password", None)

    history = supabase.table("results").select(
        "id, lesson, score, total, timestamp"
    ).eq("student_id", student["id"]).order("timestamp", desc=True).limit(100).execute().data

    return {
        "found":   True,
        "student": student,
        "history": history or [],
    }


# ==========================================
# --- 10. نظام ساحة المبارزة المباشرة (WebSockets) ---
# ==========================================
class ArenaConnectionManager:
    def __init__(self):
        # طابور الانتظار مخصص حسب الصف الدراسي: {"الصف السادس": [{"ws": socket, "name": "أحمد"}], ...}
        self.waiting_players = {}
        # حفظ الغرف النشطة لتبادل النقاط: {"room_id": {"p1": p1, "p2": p2}}
        self.active_rooms = {}

    async def connect(self, websocket: WebSocket, student_name: str, grade: str):
        await websocket.accept()
        
        # إنشاء الطابور الخاص بالصف إذا لم يكن موجوداً
        if grade not in self.waiting_players:
            self.waiting_players[grade] = []
            
        self.waiting_players[grade].append({"ws": websocket, "name": student_name})
        await self.matchmake(grade)

    async def matchmake(self, grade: str):
        queue = self.waiting_players[grade]
        # إذا توفر طالبان من نفس الصف، يتم إنشاء الغرفة وبدء المعركة
        if len(queue) >= 2:
            p1 = queue.pop(0)
            p2 = queue.pop(0)
            
            room_id = f"room_{uuid.uuid4().hex[:8]}"
            
            # جلب أسئلة مخصصة لصف الطالبين من السحاب
            res = supabase.table("questions").select("*").eq("grade", grade).execute()
            all_qs = res.data if res.data else []
            
            # اختيار 5 أسئلة عشوائياً (أو أقل إذا لم يتوفر)
            if len(all_qs) >= 5:
                match_qs = random.sample(all_qs, 5)
            else:
                match_qs = all_qs 
                
            self.active_rooms[room_id] = {"p1": p1, "p2": p2}
            
            # إرسال إشارة بدء المعركة مع نفس الأسئلة لكلا الطالبين في نفس اللحظة
            try:
                await p1["ws"].send_json({
                    "type": "match_found", 
                    "opponent": p2["name"], 
                    "room_id": room_id,
                    "questions": match_qs
                })
                await p2["ws"].send_json({
                    "type": "match_found", 
                    "opponent": p1["name"], 
                    "room_id": room_id,
                    "questions": match_qs
                })
            except Exception as e:
                print(f"Error starting match: {e}")

    async def broadcast_score(self, room_id: str, sender_name: str, new_score: int):
        room = self.active_rooms.get(room_id)
        if room:
            target = room["p2"] if room["p1"]["name"] == sender_name else room["p1"]
            try:
                await target["ws"].send_json({
                    "type": "score_update", 
                    "opponent_score": new_score
                })
            except Exception as e:
                print(f"Error broadcasting score: {e}")

    async def disconnect(self, websocket: WebSocket, grade: str):
        # إزالة الطالب من طابور الانتظار إذا انسحب
        if grade in self.waiting_players:
            self.waiting_players[grade] = [p for p in self.waiting_players[grade] if p["ws"] != websocket]
        
        # إذا انسحب الطالب أثناء المعركة النشطة
        for room_id, room in list(self.active_rooms.items()):
            if room["p1"]["ws"] == websocket or room["p2"]["ws"] == websocket:
                target = room["p2"] if room["p1"]["ws"] == websocket else room["p1"]
                try:
                    await target["ws"].send_json({"type": "opponent_disconnected"})
                except:
                    pass
                del self.active_rooms[room_id]
                break

arena_manager = ArenaConnectionManager()

@app.websocket("/api/arena/ws/{student_name}/{grade}")
async def arena_websocket(websocket: WebSocket, student_name: str, grade: str):
    # نقوم بفك تشفير الأسماء والصفوف التي قد تحتوي على مسافات
    clean_name = unquote(student_name)
    clean_grade = unquote(grade)
    
    await arena_manager.connect(websocket, clean_name, clean_grade)
    try:
        while True:
            data = await websocket.receive_json()
            if data.get("type") == "score_update":
                room_id = data.get("room_id")
                new_score = data.get("score")
                await arena_manager.broadcast_score(room_id, clean_name, new_score)
    except WebSocketDisconnect:
        await arena_manager.disconnect(websocket, clean_grade)


# ==========================================
# --- 12. نظام أكواد الاشتراك الملكي ---
# ==========================================
# ⚠️ يجب إنشاء جدول subscription_codes في Supabase بهذا SQL:
# CREATE TABLE subscription_codes (
#   id              BIGSERIAL PRIMARY KEY,
#   code            TEXT UNIQUE NOT NULL,
#   months          INTEGER NOT NULL DEFAULT 1,  -- -1 = دائم
#   note            TEXT DEFAULT '',
#   is_used         BOOLEAN DEFAULT FALSE,
#   used_at         TIMESTAMPTZ,
#   student_id      BIGINT REFERENCES students(id) ON DELETE SET NULL,
#   activated_by_student BIGINT REFERENCES students(id) ON DELETE SET NULL,
#   created_at      TIMESTAMPTZ DEFAULT NOW()
# );
# CREATE INDEX idx_sub_codes_code ON subscription_codes(code);
# ──────────────────────────────────────────────────────────────────

@app.post("/api/admin/subscription/generate")
async def generate_subscription_codes(
    months: int = Form(...),
    count: int = Form(default=10),
    student_id: Optional[int] = Form(default=None),
    note: str = Form(default=""),
    admin=Depends(get_current_admin)
):
    """توليد أكواد اشتراك آمنة وحفظها في قاعدة البيانات"""
    import hmac, hashlib
    codes = []
    for _ in range(min(count, 50)):  # حد أقصى 50 كوداً في المرة الواحدة
        raw_uuid = uuid.uuid4().hex.upper()
        prefix = "LIFE" if months == -1 else ("YEAR" if months == 12 else ("HALF" if months == 6 else ("QRTR" if months == 3 else "MNTH")))
        # HMAC-SHA256 للتحقق من صحة الكود لاحقاً
        sig = hmac.new(SECRET_KEY.encode(), raw_uuid.encode(), hashlib.sha256).hexdigest()[:8].upper()
        code = f"ME-{prefix}-{raw_uuid[:8]}-{raw_uuid[8:16]}-{sig}"
        
        data = {
            "code": code,
            "months": months,
            "note": note,
            "is_used": False,
            "student_id": student_id
        }
        result = supabase.table("subscription_codes").insert(data).execute()
        codes.append({"code": code, "id": result.data[0]["id"] if result.data else None})
    
    return {"status": "success", "codes": codes}


@app.post("/api/subscription/activate")
async def activate_subscription_code(
    code: str = Form(...),
    student_id: Optional[int] = Form(default=None)
):
    """تفعيل كود اشتراك من قِبَل الطالب"""
    code_upper = code.strip().upper()
    
    # البحث عن الكود في قاعدة البيانات
    res = supabase.table("subscription_codes").select("*").eq("code", code_upper).execute()
    
    if not res.data:
        raise HTTPException(status_code=404, detail="الكود غير موجود")
    
    entry = res.data[0]
    
    if entry.get("is_used"):
        raise HTTPException(status_code=400, detail="هذا الكود مستخدَم مسبقاً")
    
    # التحقق من أن الكود مربوط بطالب معين (إن وُجد)
    if entry.get("student_id") and student_id and entry["student_id"] != student_id:
        raise HTTPException(status_code=403, detail="هذا الكود مخصص لطالب آخر")
    
    # حساب تاريخ الانتهاء
    months = entry.get("months", 1)
    if months == -1:
        expiry = None
    else:
        now = datetime.now(timezone.utc)
        expiry = (now.replace(month=((now.month - 1 + months) % 12) + 1,
                              year=now.year + ((now.month - 1 + months) // 12))).isoformat()
    
    # تحديث الكود كمستخدَم
    update_data = {
        "is_used": True,
        "used_at": datetime.now(timezone.utc).isoformat(),
        "activated_by_student": student_id
    }
    supabase.table("subscription_codes").update(update_data).eq("id", entry["id"]).execute()
    
    return {
        "status": "success",
        "months": months,
        "expiry": expiry,
        "note": entry.get("note", "")
    }


@app.get("/api/admin/subscription/codes")
async def get_all_subscription_codes(admin=Depends(get_current_admin)):
    """جلب جميع أكواد الاشتراك للأدمن"""
    res = supabase.table("subscription_codes").select("*, students(full_name, grade)").order("id", desc=True).execute()
    return res.data if res.data else []


@app.delete("/api/admin/subscription/codes/{code_id}")
async def delete_subscription_code(code_id: int, admin=Depends(get_current_admin)):
    """حذف كود اشتراك"""
    supabase.table("subscription_codes").delete().eq("id", code_id).execute()
    return {"status": "success"}


@app.post("/api/admin/sub_codes/batch")
async def batch_save_sub_codes(request: Request, admin=Depends(get_current_admin)):
    """حفظ دفعة من الأكواد المولَّدة من واجهة الأدمن دفعة واحدة في Supabase"""
    body = await request.json()
    codes_list = body.get("codes", [])
    if not codes_list:
        raise HTTPException(status_code=400, detail="لا توجد أكواد للحفظ")

    rows = []
    for c in codes_list:
        rows.append({
            "code":       c.get("code", ""),
            "months":     int(c.get("months", 1)),
            "note":       c.get("note", ""),
            "student_id": int(c["studentId"]) if c.get("studentId") else None,
            "is_used":    False,
        })

    try:
        supabase.table("subscription_codes").insert(rows).execute()
    except Exception:
        saved = 0
        for row in rows:
            try:
                supabase.table("subscription_codes").insert(row).execute()
                saved += 1
            except Exception:
                pass
        return {"status": "partial", "saved": saved, "total": len(rows)}

    return {"status": "success", "saved": len(rows)}


@app.get("/api/admin/students")
async def get_all_students_admin(admin=Depends(get_current_admin)):
    """جلب قائمة جميع الطلاب للأدمن (للربط بأكواد الاشتراك)"""
    res = supabase.table("students").select("id, full_name, grade, username").order("full_name").execute()
    return res.data if res.data else []


@app.get("/api/admin/reports/full")
async def get_full_report(admin=Depends(get_current_admin)):
    """تقرير شامل للإمبراطورية — الطلاب + النتائج + الإحصائيات"""
    # جلب الطلاب
    students_res = supabase.table("students").select(
        "id, full_name, grade, username, created_at"
    ).order("full_name").execute()
    students = students_res.data or []

    # جلب كل النتائج
    results_res = supabase.table("results").select(
        "student_id, student_name, lesson, score, total, timestamp"
    ).order("timestamp", desc=True).execute()
    results = results_res.data or []

    # جلب عدد الأسئلة
    q_res = supabase.table("questions").select("id, grade", count="exact").execute()
    total_questions = len(q_res.data) if q_res.data else 0

    # بناء إحصائيات لكل طالب
    from collections import defaultdict
    student_stats = defaultdict(lambda: {"tests": 0, "total_score": 0, "total_max": 0, "lessons": set()})
    for r in results:
        sid = r.get("student_id")
        if sid:
            student_stats[sid]["tests"]       += 1
            student_stats[sid]["total_score"] += (r.get("score") or 0)
            student_stats[sid]["total_max"]   += (r.get("total") or 1)
            student_stats[sid]["lessons"].add(r.get("lesson", ""))

    # دمج البيانات
    students_report = []
    for s in students:
        sid   = s["id"]
        stats = student_stats.get(sid, {})
        xp    = stats.get("total_score", 0)
        tests = stats.get("tests", 0)
        total_max = stats.get("total_max", 0)
        accuracy = round((xp / total_max * 100)) if total_max > 0 else 0
        students_report.append({
            "id":         sid,
            "full_name":  s.get("full_name", ""),
            "grade":      s.get("grade", ""),
            "username":   s.get("username", ""),
            "joined":     s.get("created_at", ""),
            "xp":         xp,
            "tests":      tests,
            "accuracy":   accuracy,
            "lessons_count": len(stats.get("lessons", set())),
        })

    # ترتيب حسب XP
    students_report.sort(key=lambda x: x["xp"], reverse=True)

    # إحصائيات الصفوف
    grade_stats = defaultdict(int)
    for s in students:
        grade_stats[(s.get("grade") or "غير محدد")] += 1

    return {
        "summary": {
            "total_students":  len(students),
            "total_questions": total_questions,
            "total_results":   len(results),
            "active_students": sum(1 for s in students_report if s["tests"] > 0),
        },
        "grade_distribution": dict(grade_stats),
        "students":           students_report,
        "top10":              students_report[:10],
    }


# ==========================================
# --- 13. تشغيل المحرك المركزي ---
# ==========================================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)