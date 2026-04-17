import os
import uuid
import random
from datetime import datetime, timedelta, timezone
from dateutil.relativedelta import relativedelta
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

SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not SECRET_KEY:
    import secrets
    SECRET_KEY = secrets.token_hex(32)
    print("⚠️ JWT_SECRET_KEY not set — using random key (tokens reset on restart)")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480

# بيانات الاتصال بـ Supabase — من متغيرات البيئة (إلزامي)
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError(
        "❌ SUPABASE_URL و SUPABASE_KEY يجب تعيينهما في متغيرات البيئة. "
        "اذهب إلى Render Dashboard → Environment → أضفهما."
    )

# كلمة مرور الأدمن — من متغيرات البيئة (إلزامي)
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
if not ADMIN_PASSWORD:
    raise RuntimeError(
        "❌ ADMIN_PASSWORD يجب تعيينه في متغيرات البيئة. "
        "اذهب إلى Render Dashboard → Environment → أضفها."
    )
if len(ADMIN_PASSWORD) < 8:
    raise RuntimeError("❌ ADMIN_PASSWORD يجب أن تكون 8 أحرف على الأقل.")

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

@app.middleware("http")
async def security_headers(request: Request, call_next):
    """إضافة security headers لكل response"""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"]    = "nosniff"
    response.headers["X-Frame-Options"]           = "SAMEORIGIN"
    response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"]        = "geolocation=(), camera=(), microphone=()"

    # ═══ Content Security Policy ═══
    # نسمح بالـ CDNs المستخدمة فعلاً + Supabase + fonts.googleapis.com + unsafe-inline/eval
    # (unsafe-inline ضروري بسبب كثرة inline scripts/styles في الملفات الحالية)
    csp_directives = [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' "
            "https://cdnjs.cloudflare.com "
            "https://cdn.jsdelivr.net "
            "https://unpkg.com "
            "https://generativelanguage.googleapis.com "
            "https://api.x.ai",
        "style-src 'self' 'unsafe-inline' "
            "https://fonts.googleapis.com "
            "https://cdnjs.cloudflare.com",
        "font-src 'self' data: "
            "https://fonts.gstatic.com "
            "https://cdnjs.cloudflare.com",
        "img-src 'self' data: blob: https:",
        "media-src 'self' data: blob: https:",
        "connect-src 'self' "
            "https://*.supabase.co "
            "https://generativelanguage.googleapis.com "
            "https://api.x.ai "
            "wss: ws:",
        "frame-ancestors 'self'",
        "base-uri 'self'",
        "form-action 'self'",
    ]
    response.headers["Content-Security-Policy"] = "; ".join(csp_directives)

    # HSTS — فقط للـ HTTPS (Render يستخدم HTTPS)
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    return response

# Rate Limiter — يدوي في الذاكرة، لا يحتاج تسجيل

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    print(f"Error occurred: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={"status": "error", "message": "عطل في الديوان الملكي"},
    )

# ضمان ترميز UTF-8 لجميع الاستجابات
from fastapi.responses import Response
import json as _json

class UTF8JSONResponse(JSONResponse):
    def render(self, content) -> bytes:
        return _json.dumps(content, ensure_ascii=False, allow_nan=False, indent=None, separators=(",", ":")).encode("utf-8")

app.router.default_response_class = UTF8JSONResponse

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
async def teacher_login(request: Request, username: str = Form(...), password: str = Form(...)):
    # Rate limiting (كما في admin/student login)
    ip = request.client.host if request.client else "unknown"
    if _is_rate_limited(f"teacher_login:{ip}", max_calls=10, window_seconds=60):
        raise HTTPException(status_code=429, detail="محاولات كثيرة — انتظر دقيقة")

    res = supabase.table("teachers").select("*").eq("username", username).execute()
    if res.data and verify_password(password, res.data[0]['password']):
        # ═══ نسخة نظيفة من بيانات المعلم بدون كلمة المرور ═══
        user_clean = {k: v for k, v in res.data[0].items() if k != 'password'}
        return {"status": "success", "user": user_clean}

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

def get_current_student(request: Request):
    """التحقق من JWT الطالب"""
    auth = request.headers.get("Authorization", "")
    token = auth.replace("Bearer ", "").strip()
    if not token:
        # fallback: قبول student_id في الـ form (للتوافق مع الكود القديم)
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("role") != "student":
            return None
        return payload
    except JWTError:
        return None


@app.post("/api/student/login")
async def login_student(request: Request, username: str = Form(...), password: str = Form(...)):
    # Rate limit: 10 محاولات/دقيقة لكل IP
    client_ip = request.client.host if request.client else "unknown"
    if _is_rate_limited(client_ip, max_calls=10, window_seconds=60):
        raise HTTPException(status_code=429, detail="⏳ تجاوزت عدد المحاولات المسموحة — انتظر دقيقة")
    res = supabase.table("students").select("*").eq("username", username).execute()
    if res.data and verify_password(password, res.data[0]['password']):
        user = res.data[0]

        # ═══ فحص is_active: الحسابات المعطلة تُمنع من الدخول ═══
        # نعتبر الحساب نشطاً افتراضياً إذا ما كان الحقل موجوداً (للتوافق مع القديم)
        if user.get('is_active') is False:
            raise HTTPException(
                status_code=403,
                detail="🚫 حسابك معطّل حالياً. تواصل مع الأستاذ رشدي لإعادة التفعيل."
            )

        user.pop('password', None)

        # ═══ تحديث last_active للطالب ═══
        try:
            supabase.table("students").update({
                "last_active": datetime.now(timezone.utc).isoformat()
            }).eq("id", user["id"]).execute()
        except Exception:
            pass  # الحقل قد لا يكون موجوداً في جداول قديمة

        # إنشاء JWT للطالب
        token = create_access_token({
            "sub":   str(user["id"]),
            "role":  "student",
            "grade": user.get("grade", "")
        })
        return {"status": "success", "access_token": token, "user": user}
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
    grade:      str         = Form(...),
    semester:   str         = Form(default=""),
    unit:       str         = Form(default=""),
    lesson:     str         = Form(...),
    subject:    str         = Form(...),
    q_type:     str         = Form(...),
    question:   str         = Form(...),
    options:    str         = Form(""),
    answer:     str         = Form(...),
    image:      UploadFile  = File(None),
    is_elite:   str         = Form(default="false"),
    difficulty: str         = Form(default="hard"),
    admin=Depends(get_current_admin)
):
    img_url = ""
    if image and image.filename:
        img_name = f"q_img_{uuid.uuid4().hex}{os.path.splitext(image.filename)[1]}"
        content = await image.read()
        supabase.storage.from_("resources").upload(path=img_name, file=content, file_options={"content-type": image.content_type})
        img_url = supabase.storage.from_("resources").get_public_url(img_name)

    row = {
        "grade":    grade,
        "semester": semester,
        "unit":     unit,
        "lesson":   lesson,
        "subject":  subject,
        "q_type":   q_type,
        "question": question,
        "options":  options,
        "answer":   answer,
        "image_url": img_url,
    }
    # حقول النخبة — اختيارية
    elite_val = is_elite.lower().strip() not in ('false', '0', 'no', '')
    if elite_val:
        row["is_elite"]   = True
        row["difficulty"] = difficulty.strip() or "hard"

    try:
        supabase.table("questions").insert(row).execute()
    except Exception as e:
        # fallback: لو الأعمدة الجديدة ما موجودة بعد، نحذفها ونعيد المحاولة
        if "semester" in str(e) or "unit" in str(e) or "column" in str(e).lower():
            row.pop("semester", None)
            row.pop("unit", None)
            supabase.table("questions").insert(row).execute()
        else:
            raise
    return {"status": "success"}

@app.put("/api/admin/questions/{q_id}")
async def update_question(
    q_id: int,
    grade: str=Form(...),
    semester: str=Form(default=""),
    unit: str=Form(default=""),
    lesson: str=Form(...),
    subject: str=Form(...),
    q_type: str=Form(...), question: str=Form(...), options: str=Form(""), 
    answer: str=Form(...), image: UploadFile=File(None), admin=Depends(get_current_admin)
):
    update_data = {
        "grade": grade, "semester": semester, "unit": unit,
        "lesson": lesson, "subject": subject, "q_type": q_type, 
        "question": question, "options": options, "answer": answer
    }
    
    if image and image.filename:
        img_name = f"q_img_{uuid.uuid4().hex}{os.path.splitext(image.filename)[1]}"
        content = await image.read()
        supabase.storage.from_("resources").upload(path=img_name, file=content, file_options={"content-type": image.content_type})
        update_data["image_url"] = supabase.storage.from_("resources").get_public_url(img_name)

    try:
        supabase.table("questions").update(update_data).eq("id", q_id).execute()
    except Exception as e:
        # fallback: لو الأعمدة الجديدة ما موجودة
        if "semester" in str(e) or "unit" in str(e) or "column" in str(e).lower():
            update_data.pop("semester", None)
            update_data.pop("unit", None)
            supabase.table("questions").update(update_data).eq("id", q_id).execute()
        else:
            raise
    return {"status": "success"}

@app.delete("/api/admin/questions/{q_id}")
async def delete_question(q_id: int, admin=Depends(get_current_admin)):
    supabase.table("questions").delete().eq("id", q_id).execute()
    return {"status": "success"}


@app.post("/api/admin/questions/bulk_delete")
async def bulk_delete_questions(
    request: Request,
    admin=Depends(get_current_admin)
):
    """
    حذف أسئلة بالجملة حسب الفلتر الملكي.
    يتطلب كلمة مرور الأدمن كحماية إضافية لأن العملية مدمّرة.

    Body (form-urlencoded):
      - admin_password (إلزامي): كلمة مرور الأدمن للتأكيد
      - grade          (إلزامي): اسم الصف — نرفض الحذف بدونه لمنع مسح كامل
      - semester       (اختياري): اسم الفصل
      - unit           (اختياري): اسم الوحدة
      - lesson         (اختياري): اسم الدرس
      - dry_run        (اختياري): "true" لعدّ الأسئلة فقط دون حذف (معاينة)
    """
    body = await request.form()
    admin_pass = body.get("admin_password", "")
    grade      = (body.get("grade") or "").strip()
    semester   = (body.get("semester") or "").strip()
    unit       = (body.get("unit") or "").strip()
    lesson     = (body.get("lesson") or "").strip()
    dry_run    = str(body.get("dry_run", "")).lower() in ("true", "1", "yes")

    # حماية 1: كلمة مرور الأدمن مطلوبة
    if not admin_pass or admin_pass != ADMIN_PASSWORD:
        raise HTTPException(status_code=403, detail="كلمة مرور الأدمن خاطئة")

    # حماية 2: الصف إلزامي — لا يُسمح بحذف كل الأسئلة دفعة واحدة عن طريق الخطأ
    if not grade:
        raise HTTPException(status_code=400, detail="يجب تحديد الصف على الأقل")

    # بناء الاستعلام مع كل صيغ الصف (السادس / 6 / الصف السادس …)
    variants = _grade_variants(grade)
    if not variants:
        variants = [grade]

    # عدّ الأسئلة المطابقة لكل صيغة ثم دمجها
    matched_ids = set()
    matched_preview = []
    for v in variants:
        q = supabase.table("questions").select("id, grade, semester, unit, lesson, question")\
            .eq("grade", v.strip())
        if semester:
            q = q.eq("semester", semester)
        if unit:
            q = q.eq("unit", unit)
        if lesson:
            q = q.eq("lesson", lesson)
        try:
            res = q.execute()
        except Exception:
            # لو الأعمدة semester/unit لسه ما انضافت لقاعدة البيانات، نرجع للدرس فقط
            q2 = supabase.table("questions").select("id, grade, lesson, question")\
                .eq("grade", v.strip())
            if lesson:
                q2 = q2.eq("lesson", lesson)
            res = q2.execute()
        for row in (res.data or []):
            if row["id"] not in matched_ids:
                matched_ids.add(row["id"])
                if len(matched_preview) < 5:
                    matched_preview.append({
                        "id": row["id"],
                        "lesson": row.get("lesson", ""),
                        "question": (row.get("question") or "")[:80]
                    })

    count = len(matched_ids)

    if dry_run:
        return {
            "status": "preview",
            "count": count,
            "preview": matched_preview,
            "filter": {"grade": grade, "semester": semester, "unit": unit, "lesson": lesson}
        }

    if count == 0:
        return {"status": "empty", "deleted": 0, "message": "لا توجد أسئلة مطابقة"}

    # الحذف الفعلي — على دفعات من 50 لتجنّب تجاوز حدود Supabase
    ids_list = list(matched_ids)
    deleted = 0
    for i in range(0, len(ids_list), 50):
        batch = ids_list[i:i+50]
        try:
            supabase.table("questions").delete().in_("id", batch).execute()
            deleted += len(batch)
        except Exception as e:
            # نكمل حتى لو فشلت دفعة
            print(f"[bulk_delete] فشلت دفعة: {e}")

    return {
        "status": "success",
        "deleted": deleted,
        "requested": count,
        "filter": {"grade": grade, "semester": semester, "unit": unit, "lesson": lesson}
    }


@app.post("/api/admin/questions/bulk")
async def bulk_add_questions(request: Request, admin=Depends(get_current_admin)):
    """ضخ دفعة أسئلة مولّدة بالذكاء الاصطناعي دفعة واحدة — أسرع من الإرسال الفردي"""
    body = await request.json()
    questions = body.get("questions", [])
    if not questions:
        raise HTTPException(status_code=400, detail="لا توجد أسئلة في الطلب")
    inserted = 0
    errors   = 0
    for q in questions:
        try:
            row = {
                "grade":    str(q.get("grade",    "") or "").strip(),
                "semester": str(q.get("semester", "") or "").strip(),
                "unit":     str(q.get("unit",    "") or "").strip(),
                "lesson":   str(q.get("lesson",   "") or "").strip(),
                "subject":  str(q.get("subject",  "رياضيات") or "رياضيات").strip(),
                "q_type":   str(q.get("q_type",   "choice") or "choice").strip(),
                "question": str(q.get("question", "") or "").strip(),
                "options":  str(q.get("options",  "") or "").strip(),
                "answer":   str(q.get("answer",   "") or "").strip(),
                "image_url": "",
            }
            if not row["question"] or not row["answer"]:
                errors += 1
                continue
            is_elite_val = str(q.get("is_elite", "false")).lower().strip()
            if is_elite_val not in ("false", "0", "no", ""):
                row["is_elite"]   = True
                row["difficulty"] = str(q.get("difficulty", "hard") or "hard").strip()
            else:
                diff = str(q.get("difficulty", "") or "").strip()
                if diff in ("easy", "medium", "hard"):
                    row["difficulty"] = diff
            try:
                supabase.table("questions").insert(row).execute()
                inserted += 1
            except Exception as e:
                # fallback: الأعمدة الجديدة ما موجودة
                if "semester" in str(e) or "unit" in str(e) or "column" in str(e).lower():
                    row.pop("semester", None)
                    row.pop("unit", None)
                    supabase.table("questions").insert(row).execute()
                    inserted += 1
                else:
                    errors += 1
        except Exception:
            errors += 1
    return {"inserted": inserted, "errors": errors, "total": len(questions)}

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
    - الإجابات تُفحص عبر /api/student/check_answer فقط (لا تُرسل للعميل)
    """
    variants = _grade_variants(grade)

    all_questions = []
    seen_ids: set = set()

    # إذا لم تتوفر أي صيغة — أرجع كل الأسئلة (fallback للأسئلة القديمة)
    search_variants = variants if variants else [grade] if grade else []

    # ═══ حقول آمنة فقط — بدون answer ═══
    SAFE_FIELDS = "id, grade, lesson, subject, q_type, question, options, image_url"

    for v in search_variants:
        v_stripped = v.strip()
        query = supabase.table("questions").select(SAFE_FIELDS).eq("grade", v_stripped)
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
            res = supabase.table("questions").select(SAFE_FIELDS)\
                .eq("grade", v).ilike("lesson", f"%{lesson.strip()}%").execute()
            for q in (res.data or []):
                if q["id"] not in seen_ids:
                    seen_ids.add(q["id"])
                    all_questions.append(q)

    return all_questions


@app.post("/api/student/check_answer")
async def check_answer(request: Request):
    """
    التحقق من إجابة الطالب على السيرفر
    يُرجع is_correct + correct_answer عند الخطأ (ليُعرض في مستشفى الأرقام)
    Body JSON: { "question_id": int, "student_answer": str }
    """
    ip = request.client.host if request.client else "unknown"
    if _is_rate_limited(ip, max_calls=120, window_seconds=60):
        raise HTTPException(status_code=429, detail="طلبات كثيرة جداً — انتظر لحظة")

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="صيغة الطلب غير صحيحة — يُتوقع JSON")

    question_id    = body.get("question_id")
    student_answer = body.get("student_answer", "")

    if not question_id or not isinstance(question_id, int):
        raise HTTPException(status_code=400, detail="question_id مطلوب وصحيح")

    # جلب الإجابة الصحيحة من قاعدة البيانات
    res = supabase.table("questions").select("id, answer, q_type").eq("id", question_id).execute()
    if not res.data:
        raise HTTPException(status_code=404, detail="السؤال غير موجود")

    correct_answer  = str(res.data[0].get("answer", "")).strip()
    q_type          = res.data[0].get("q_type", "")
    student_cleaned = str(student_answer).strip()

    # مقارنة غير حساسة لحالة الأحرف + تجاهل المسافات الزائدة
    normalize = lambda s: " ".join((s or "").strip().split())
    is_correct = normalize(correct_answer).lower() == normalize(student_cleaned).lower()

    response_data = {
        "is_correct": is_correct,
        "q_type":     q_type,
    }
    # نُرجع الإجابة الصحيحة فقط عند الخطأ — لعرضها في مستشفى الأرقام
    if not is_correct:
        response_data["correct_answer"] = correct_answer

    return response_data


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
    notif_lifetime_hours: int=Form(default=72),
    admin=Depends(get_current_admin)
):
    # حساب تاريخ انتهاء صلاحية الإشعار (0 = دائم)
    expires_at = None
    if notif_lifetime_hours and notif_lifetime_hours > 0:
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=notif_lifetime_hours)).isoformat()

    payload = {
        "title": title, "exam_type": exam_type, "exam_date": exam_date, "exam_time": exam_time, 
        "target_lesson": target_lesson, "duration": duration, "num_questions": num_questions, 
        "points_per_q": points_per_q, "target_q_type": target_q_type,
        "notif_lifetime_hours": notif_lifetime_hours,
        "expires_at": expires_at
    }
    try:
        supabase.table("exams").insert(payload).execute()
    except Exception as e:
        # لو الأعمدة الجديدة غير موجودة في DB بعد، نُحاول بدون
        err_msg = str(e).lower()
        if "notif_lifetime_hours" in err_msg or "expires_at" in err_msg or "column" in err_msg:
            payload.pop("notif_lifetime_hours", None)
            payload.pop("expires_at", None)
            supabase.table("exams").insert(payload).execute()
        else:
            raise
    return {"status": "success"}

@app.get("/api/exams/upcoming")
async def get_upcoming_exams(student_id: Optional[int] = None, username: Optional[str] = None):
    res = supabase.table("exams").select("*").order("id", desc=True).execute()
    exams = res.data if res.data else []

    if not exams:
        return []

    now = datetime.now(timezone.utc)

    # 1) فلترة الاختبارات منتهية الصلاحية (expires_at سابق للوقت الحالي)
    active_exams = []
    for e in exams:
        exp = e.get("expires_at")
        if exp:
            try:
                # Supabase يُرجع ISO string — نُحوّل لـ datetime
                exp_dt = datetime.fromisoformat(exp.replace("Z", "+00:00"))
                if exp_dt < now:
                    continue  # منتهي
            except Exception:
                pass
        active_exams.append(e)

    # 2) لو فيه student_id أو username، نستبعد الاختبارات المكتملة
    sid = student_id
    if not sid and username:
        st = supabase.table("students").select("id").eq("username", username).execute()
        if st.data:
            sid = st.data[0]["id"]

    if sid:
        try:
            done = supabase.table("exam_completions").select("exam_id").eq("student_id", sid).execute()
            done_ids = {r["exam_id"] for r in (done.data or [])}
            active_exams = [e for e in active_exams if e["id"] not in done_ids]
        except Exception:
            # لو الجدول لسه ما اتعمل — ما نكسر الـ endpoint
            pass

    return active_exams

@app.delete("/api/admin/exams/{exam_id}")
async def delete_exam(exam_id: int, admin=Depends(get_current_admin)):
    supabase.table("exams").delete().eq("id", exam_id).execute()
    return {"status": "success"}

# ─── تسجيل إكمال الاختبار (لإخفائه من إشعارات الطالب) ───
@app.post("/api/student/exam_completed")
async def mark_exam_completed(
    exam_id: int = Form(...),
    student_id: int = Form(...)
):
    # تحقق من وجود الطالب والاختبار
    st = supabase.table("students").select("id").eq("id", student_id).execute()
    if not st.data:
        raise HTTPException(status_code=404, detail="الطالب غير موجود")
    ex = supabase.table("exams").select("id").eq("id", exam_id).execute()
    if not ex.data:
        raise HTTPException(status_code=404, detail="الاختبار غير موجود")

    try:
        # upsert: لو موجود مسبقاً ما نكرّره
        existing = supabase.table("exam_completions").select("id")\
            .eq("exam_id", exam_id).eq("student_id", student_id).execute()
        if not existing.data:
            supabase.table("exam_completions").insert({
                "exam_id": exam_id,
                "student_id": student_id,
                "completed_at": datetime.now(timezone.utc).isoformat()
            }).execute()
    except Exception as e:
        # لو الجدول غير موجود، نُعيد رسالة واضحة
        raise HTTPException(
            status_code=500,
            detail=f"جدول exam_completions غير متوفر — شغّل migration أولاً: {e}"
        )
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
async def save_result(
    request: Request,
    student_id: int=Form(...), student_name: str=Form(...),
    lesson: str=Form(...), score: int=Form(...), total: int=Form(...)
):
    ip = request.client.host if request.client else "unknown"
    if _is_rate_limited(ip, max_calls=30, window_seconds=60):
        raise HTTPException(status_code=429, detail="طلبات كثيرة جداً")
    if score < 0 or total <= 0 or score > total:
        raise HTTPException(status_code=400, detail="بيانات غير صحيحة")
    if total > 200:
        raise HTTPException(status_code=400, detail="عدد أسئلة غير منطقي")
    if len(lesson.strip()) < 2 or len(lesson) > 300:
        raise HTTPException(status_code=400, detail="اسم درس غير صحيح")
    # التحقق أن الطالب موجود ونتيجة واحدة لكل درس/جلسة
    st = supabase.table("students").select("id,username").eq("id", student_id).execute()
    if not st.data:
        raise HTTPException(status_code=404, detail="الطالب غير موجود")
    supabase.table("results").insert({
        "student_id": student_id,
        "student_name": student_name[:100],
        "lesson": lesson[:300],
        "score": score,
        "total": total
    }).execute()

    # ═══ تحديث last_active للطالب عند حفظ النتيجة ═══
    try:
        supabase.table("students").update({
            "last_active": datetime.now(timezone.utc).isoformat()
        }).eq("id", student_id).execute()
    except Exception:
        pass

    return {"status": "success"}

@app.post("/api/student/heartbeat")
async def student_heartbeat(student_id: int = Form(...)):
    """تحديث last_active للطالب — يُستدعى من العميل كل دقيقة أثناء النشاط"""
    try:
        supabase.table("students").update({
            "last_active": datetime.now(timezone.utc).isoformat()
        }).eq("id", student_id).execute()
        return {"status": "ok"}
    except Exception:
        return {"status": "skipped"}


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
async def arena_websocket(websocket: WebSocket, student_name: str, grade: str, token: Optional[str] = None):
    """
    WebSocket Arena — يقبل توكن JWT اختياري كـ query parameter (?token=...)
    - لو التوكن موجود وصحيح: نستخدم بيانات الـ JWT (أكثر أماناً)
    - لو مش موجود: نقبل الاسم من URL للتوافق مع العملاء القدامى (سنُهمل هذا المسار لاحقاً)
    """
    # نقوم بفك تشفير الأسماء والصفوف التي قد تحتوي على مسافات
    clean_name = unquote(student_name)
    clean_grade = unquote(grade)
    verified = False

    # محاولة التحقق من التوكن إن وُجد
    if token:
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            if payload.get("role") == "student":
                sid = payload.get("sub")
                if sid:
                    # جلب البيانات الحقيقية من DB لاستبدال الاسم/الصف القادم من URL
                    try:
                        st = supabase.table("students").select("full_name,grade,is_active")\
                             .eq("id", int(sid)).execute()
                        if st.data:
                            # منع الحسابات المعطلة من الدخول للساحة
                            if st.data[0].get("is_active") is False:
                                await websocket.close(code=1008, reason="account_disabled")
                                return
                            clean_name = st.data[0].get("full_name", clean_name)
                            clean_grade = st.data[0].get("grade", clean_grade)
                            verified = True
                    except Exception:
                        pass
        except JWTError:
            # توكن غير صالح — نرفض الاتصال
            await websocket.close(code=1008, reason="invalid_token")
            return

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
    
    # حساب تاريخ الانتهاء — باستخدام relativedelta لتجنب مشكلة ديسمبر
    months = entry.get("months", 1)
    if months == -1:
        expiry = None
    else:
        now = datetime.now(timezone.utc)
        expiry = (now + relativedelta(months=months)).isoformat()
    
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
# --- 14. نظام النخبة (Elite System) ---
# ==========================================

class EliteArenaManager:
    """مدير ساحة مبارزة النخبة — WebSocket مستقل"""
    def __init__(self):
        self.waiting_players: dict = {}
        self.active_rooms:    dict = {}

    async def connect(self, websocket: WebSocket, student_name: str, grade: str):
        await websocket.accept()
        if grade not in self.waiting_players:
            self.waiting_players[grade] = []
        self.waiting_players[grade].append({"ws": websocket, "name": student_name})
        await self.elite_matchmake(grade)

    async def elite_matchmake(self, grade: str):
        queue = self.waiting_players[grade]
        if len(queue) < 2:
            try:
                await queue[-1]["ws"].send_json({"type": "waiting", "msg": "⏳ بحث عن منافس من النخبة..."})
            except: pass
            return
        p1 = queue.pop(0)
        p2 = queue.pop(0)
        room_id = f"elite_{id(p1['ws'])}_{id(p2['ws'])}"
        self.active_rooms[room_id] = {"p1": p1, "p2": p2, "scores": {p1["name"]: 0, p2["name"]: 0}}
        for p, opp in [(p1, p2), (p2, p1)]:
            try:
                await p["ws"].send_json({
                    "type": "matched",
                    "room_id": room_id,
                    "opponent": opp["name"],
                    "msg": f"⚔️ تم إيجاد منافس: {opp['name']}"
                })
            except: pass

    async def broadcast_score(self, room_id: str, sender_name: str, new_score: int):
        room = self.active_rooms.get(room_id)
        if not room: return
        room["scores"][sender_name] = new_score
        for key in ["p1", "p2"]:
            try:
                await room[key]["ws"].send_json({
                    "type": "score_update",
                    "scores": room["scores"]
                })
            except: pass

    async def disconnect(self, websocket: WebSocket, grade: str):
        if grade in self.waiting_players:
            self.waiting_players[grade] = [
                p for p in self.waiting_players[grade] if p["ws"] != websocket
            ]

elite_arena_manager = EliteArenaManager()


@app.websocket("/api/elite/arena/ws/{student_name}/{grade}")
async def elite_arena_websocket(websocket: WebSocket, student_name: str, grade: str):
    """WebSocket لساحة مبارزة النخبة"""
    from urllib.parse import unquote
    clean_name  = unquote(student_name)
    clean_grade = unquote(grade)
    await elite_arena_manager.connect(websocket, clean_name, clean_grade)
    try:
        while True:
            data = await websocket.receive_json()
            if data.get("type") == "score_update":
                await elite_arena_manager.broadcast_score(
                    data["room_id"], clean_name, data["score"]
                )
    except WebSocketDisconnect:
        await elite_arena_manager.disconnect(websocket, clean_grade)


@app.post("/api/elite/request")
async def submit_elite_request(
    request: Request,
    student_id: int = Form(...),
    username:   str = Form(...),
    full_name:  str = Form(...),
    grade:      str = Form(...),
    xp:         int = Form(default=0),
    lessons_85: int = Form(default=0),
):
    """طلب انضمام تلقائي لنادي النخبة"""
    ip = request.client.host if request.client else "unknown"
    if _is_rate_limited(ip, max_calls=5, window_seconds=3600):
        raise HTTPException(status_code=429, detail="تم الإرسال مسبقاً")
    # تحقق: هل قدّم طلباً سابقاً؟
    existing = supabase.table("elite_requests").select("id,status")         .eq("student_id", student_id).execute()
    if existing.data:
        st = existing.data[0]["status"]
        if st == "approved": return {"status": "already_elite"}
        if st == "pending":  return {"status": "pending"}
    supabase.table("elite_requests").insert({
        "student_id": student_id, "username": username,
        "full_name":  full_name,  "grade":    grade,
        "xp":         xp,         "lessons_85": lessons_85,
        "status":     "pending"
    }).execute()
    return {"status": "submitted"}


@app.get("/api/elite/check/{student_id}")
async def check_elite_status(student_id: int):
    """هل الطالب معتمد كفائق؟"""
    res = supabase.table("students").select("is_elite").eq("id", student_id).execute()
    if res.data:
        return {"is_elite": bool(res.data[0].get("is_elite", False))}
    return {"is_elite": False}


@app.get("/api/elite/questions")
async def get_elite_questions(grade: str = "", lesson: str = ""):
    """أسئلة النخبة — مصنّفة"""
    query = supabase.table("questions").select(
        "id,grade,lesson,subject,q_type,question,options,answer,image_url,difficulty"
    ).eq("is_elite", True)
    if grade:   query = query.eq("grade", grade.strip())
    if lesson:  query = query.ilike("lesson", lesson.strip())
    res = query.execute()
    return res.data or []


@app.get("/api/elite/leaderboard")
async def elite_leaderboard():
    """ترتيب الفائقين — استعلام واحد بدلاً من N+1"""
    # ═══ 1) جلب كل طلاب النخبة (استعلام واحد) ═══
    res = supabase.table("students").select(
        "id,full_name,grade,school_name,avatar_url"
    ).eq("is_elite", True).execute()
    students = res.data or []

    if not students:
        return []

    # ═══ 2) جلب كل النتائج لهم دفعة واحدة (استعلام واحد باستخدام in_) ═══
    student_ids = [st["id"] for st in students]
    all_results = supabase.table("results").select("student_id,score,total")\
        .in_("student_id", student_ids).execute().data or []

    # ═══ 3) تجميع النتائج حسب الطالب في الذاكرة ═══
    results_by_student = {}
    for r in all_results:
        sid = r.get("student_id")
        if sid is None:
            continue
        results_by_student.setdefault(sid, []).append(r)

    # ═══ 4) بناء لوحة الترتيب ═══
    board = []
    for st in students:
        results = results_by_student.get(st["id"], [])
        total_correct = sum(x.get("score", 0) or 0 for x in results)
        total_q = sum(x.get("total", 0) or 0 for x in results if (x.get("total") or 0) > 0)
        accuracy = round((total_correct / total_q * 100)) if total_q > 0 else 0
        board.append({**st, "xp": total_correct, "accuracy": accuracy, "tests": len(results)})

    board.sort(key=lambda x: (-x["xp"], -x["accuracy"]))
    return board[:50]


# ── ADMIN: إدارة النخبة ──
@app.get("/api/admin/elite/requests")
async def get_elite_requests(admin=Depends(get_current_admin)):
    res = supabase.table("elite_requests").select("*").order("created_at", desc=True).execute()
    return res.data or []


@app.post("/api/admin/elite/approve/{request_id}")
async def approve_elite(request_id: int, admin=Depends(get_current_admin)):
    req = supabase.table("elite_requests").select("*").eq("id", request_id).execute()
    if not req.data: raise HTTPException(status_code=404, detail="الطلب غير موجود")
    r = req.data[0]
    supabase.table("students").update({
        "is_elite": True,
        "elite_approved_at": datetime.now(timezone.utc).isoformat()
    }).eq("id", r["student_id"]).execute()
    supabase.table("elite_requests").update({"status": "approved"}).eq("id", request_id).execute()
    return {"status": "approved"}


@app.post("/api/admin/elite/reject/{request_id}")
async def reject_elite(request_id: int, admin=Depends(get_current_admin)):
    supabase.table("elite_requests").update({"status": "rejected"}).eq("id", request_id).execute()
    return {"status": "rejected"}


@app.post("/api/admin/elite/revoke/{student_id}")
async def revoke_elite(student_id: int, admin=Depends(get_current_admin)):
    supabase.table("students").update({"is_elite": False}).eq("id", student_id).execute()
    supabase.table("elite_requests").update({"status": "rejected"})         .eq("student_id", student_id).execute()
    return {"status": "revoked"}


@app.post("/api/admin/elite/grant/{student_id}")
async def grant_elite_manually(student_id: int, admin=Depends(get_current_admin)):
    """منح لقب الفائق يدوياً"""
    supabase.table("students").update({
        "is_elite": True,
        "elite_approved_at": datetime.now(timezone.utc).isoformat()
    }).eq("id", student_id).execute()
    return {"status": "granted"}


@app.get("/api/admin/elite/members")
async def get_elite_members(admin=Depends(get_current_admin)):
    res = supabase.table("students").select(
        "id,full_name,username,grade,school_name,is_elite,elite_approved_at"
    ).eq("is_elite", True).execute()
    return res.data or []


# ==========================================
# --- الإشعارات العامة ---
# ==========================================
@app.post("/api/admin/notifications")
async def send_notification(
    request: Request,
    title:    str = Form(...),
    body:     str = Form(...),
    grade:    str = Form(default="all"),
    priority: str = Form(default="normal"),
    type:     str = Form(default="announcement"),
    admin=Depends(get_current_admin)
):
    """إرسال إشعار للطلاب — يُخزَّن في Supabase"""
    ip = request.client.host if request.client else "unknown"
    if _is_rate_limited(ip, max_calls=20, window_seconds=60):
        raise HTTPException(status_code=429, detail="طلبات كثيرة جداً")
    row = {
        "title":    title.strip()[:200],
        "body":     body.strip()[:500],
        "grade":    grade,
        "priority": priority,
        "type":     type,
        "is_active": True,
    }
    try:
        supabase.table("notifications").insert(row).execute()
    except Exception as e:
        print(f"notifications insert error: {e}")
    return {"status": "success", "message": "تم إرسال الإشعار"}


@app.get("/api/notifications")
async def get_notifications(grade: str = ""):
    """جلب الإشعارات النشطة للطلاب"""
    try:
        if grade and grade != "all":
            res1 = supabase.table("notifications").select("*").eq("is_active", True).eq("grade", grade).order("created_at", desc=True).limit(5).execute()
            res2 = supabase.table("notifications").select("*").eq("is_active", True).eq("grade", "all").order("created_at", desc=True).limit(5).execute()
            data = (res1.data or []) + (res2.data or [])
            data.sort(key=lambda x: x.get("created_at", ""), reverse=True)
            return data[:10]
        res = supabase.table("notifications").select("*").eq("is_active", True).order("created_at", desc=True).limit(10).execute()
        return res.data or []
    except Exception:
        return []


@app.delete("/api/admin/notifications/{notif_id}")
async def delete_notification(notif_id: int, admin=Depends(get_current_admin)):
    """تعطيل إشعار"""
    try:
        supabase.table("notifications").update({"is_active": False}).eq("id", notif_id).execute()
    except Exception:
        pass
    return {"status": "success"}


# ==========================================
# --- endpoints إدارة الحسابات ---
# ==========================================

@app.get("/api/admin/students/full")
async def get_all_students_full(admin=Depends(get_current_admin)):
    """جلب قائمة الطلاب كاملة مع is_active"""
    res = supabase.table("students").select(
        "id, full_name, username, grade, school_name, avatar_url, is_active, is_elite, created_at, last_active"
    ).order("full_name").execute()
    return res.data or []


@app.post("/api/admin/students/{student_id}/toggle")
async def toggle_student(student_id: int, is_active: str = Form(...), admin=Depends(get_current_admin)):
    """تعطيل أو تفعيل حساب طالب"""
    active = is_active.lower() not in ('false', '0', 'no')
    supabase.table("students").update({"is_active": active}).eq("id", student_id).execute()
    return {"status": "success", "is_active": active}


@app.delete("/api/admin/students/{student_id}/delete")
async def delete_student(student_id: int, request: Request, admin=Depends(get_current_admin)):
    """حذف طالب نهائياً — يتطلب كلمة مرور الأدمن"""
    body = await request.form()
    admin_pass = body.get("admin_password", "")
    if not admin_pass or not (admin_pass == ADMIN_PASSWORD or verify_password(admin_pass, ADMIN_PASSWORD)):
        raise HTTPException(status_code=403, detail="كلمة مرور الأدمن خاطئة")
    supabase.table("results").delete().eq("student_id", student_id).execute()
    supabase.table("elite_requests").delete().eq("student_id", student_id).execute()
    res = supabase.table("students").delete().eq("id", student_id).execute()
    if not res.data:
        raise HTTPException(status_code=404, detail="الطالب غير موجود")
    return {"status": "deleted"}


@app.get("/api/admin/teachers")
async def get_all_teachers(admin=Depends(get_current_admin)):
    """جلب قائمة المعلمين"""
    res = supabase.table("teachers").select(
        "id, full_name, username, subject, is_active, created_at"
    ).order("full_name").execute()
    return res.data or []


@app.post("/api/admin/teachers/{teacher_id}/toggle")
async def toggle_teacher(teacher_id: int, is_active: str = Form(...), admin=Depends(get_current_admin)):
    """تعطيل أو تفعيل حساب معلم"""
    active = is_active.lower() not in ('false', '0', 'no')
    supabase.table("teachers").update({"is_active": active}).eq("id", teacher_id).execute()
    return {"status": "success", "is_active": active}


@app.delete("/api/admin/teachers/{teacher_id}/delete")
async def delete_teacher(teacher_id: int, request: Request, admin=Depends(get_current_admin)):
    """حذف معلم نهائياً — يتطلب كلمة مرور الأدمن"""
    body = await request.form()
    admin_pass = body.get("admin_password", "")
    if not admin_pass or not (admin_pass == ADMIN_PASSWORD or verify_password(admin_pass, ADMIN_PASSWORD)):
        raise HTTPException(status_code=403, detail="كلمة مرور الأدمن خاطئة")
    res = supabase.table("teachers").delete().eq("id", teacher_id).execute()
    if not res.data:
        raise HTTPException(status_code=404, detail="المعلم غير موجود")
    return {"status": "deleted"}


@app.post("/api/admin/teachers/add")
async def add_teacher_admin(
    full_name: str = Form(...),
    username:  str = Form(...),
    password:  str = Form(...),
    subject:   str = Form(default="رياضيات"),
    admin=Depends(get_current_admin)
):
    """إضافة معلم جديد من لوحة الأدمن"""
    if len(password) < 6:
        raise HTTPException(status_code=400, detail="كلمة المرور أقل من 6 أحرف")
    existing = supabase.table("teachers").select("username").eq("username", username).execute()
    if existing.data:
        raise HTTPException(status_code=400, detail="اسم المستخدم موجود مسبقاً")
    supabase.table("teachers").insert({
        "full_name": full_name.strip(),
        "username":  username.strip().lower(),
        "password":  hash_password(password),
        "subject":   subject.strip(),
        "is_active": True,
    }).execute()
    return {"status": "success", "message": f"تم إضافة المعلم {full_name}"}

# ==========================================
# --- 14. نظام التحضيرات الملكية ---
# ==========================================
# SQL لإنشاء الجدول في Supabase (نفّذه مرة واحدة):
# CREATE TABLE lesson_preparations (
#   id              BIGSERIAL PRIMARY KEY,
#   grade           TEXT NOT NULL,
#   semester        TEXT NOT NULL,
#   unit            TEXT NOT NULL,
#   lesson          TEXT NOT NULL,
#   concepts        TEXT DEFAULT '',
#   warm_up         TEXT DEFAULT '',
#   activities      TEXT DEFAULT '',
#   formative_eval  TEXT DEFAULT '',
#   summative_eval  TEXT DEFAULT '',
#   attachments     JSONB DEFAULT '[]',
#   created_at      TIMESTAMPTZ DEFAULT NOW(),
#   updated_at      TIMESTAMPTZ DEFAULT NOW(),
#   UNIQUE(grade, semester, unit, lesson)
# );


@app.get("/api/preparations")
async def get_preparation(grade: str, semester: str, unit: str, lesson: str):
    """جلب تحضير درس محدد — متاح بدون مصادقة للعرض"""
    try:
        res = supabase.table("lesson_preparations").select("*") \
            .eq("grade",    grade.strip()) \
            .eq("semester", semester.strip()) \
            .eq("unit",     unit.strip()) \
            .eq("lesson",   lesson.strip()) \
            .execute()
        if res.data:
            return res.data[0]
        return {
            "id": None, "concepts": "", "warm_up": "", "activities": "",
            "formative_eval": "", "summative_eval": "", "attachments": []
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/admin/preparations")
async def save_preparation(request: Request, admin=Depends(get_current_admin)):
    """حفظ أو تحديث تحضير درس — يتطلب صلاحيات الأدمن"""
    ip = request.client.host if request.client else "unknown"
    if _is_rate_limited(ip, max_calls=30, window_seconds=60):
        raise HTTPException(status_code=429, detail="طلبات كثيرة جداً")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="صيغة الطلب غير صحيحة")

    grade    = (body.get("grade",    "") or "").strip()
    semester = (body.get("semester", "") or "").strip()
    unit     = (body.get("unit",     "") or "").strip()
    lesson   = (body.get("lesson",   "") or "").strip()

    if not all([grade, semester, unit, lesson]):
        raise HTTPException(status_code=400, detail="الصف والفصل والوحدة والدرس مطلوبة")

    row = {
        "grade":          grade,
        "semester":       semester,
        "unit":           unit,
        "lesson":         lesson,
        "concepts":       (body.get("concepts")       or "")[:5000],
        "warm_up":        (body.get("warm_up")        or "")[:5000],
        "activities":     (body.get("activities")     or "")[:10000],
        "formative_eval": (body.get("formative_eval") or "")[:5000],
        "summative_eval": (body.get("summative_eval") or "")[:5000],
        "attachments":    body.get("attachments") or [],
        "updated_at":     datetime.now(timezone.utc).isoformat(),
    }

    existing = supabase.table("lesson_preparations").select("id") \
        .eq("grade", grade).eq("semester", semester) \
        .eq("unit",  unit).eq("lesson",   lesson).execute()

    if existing.data:
        supabase.table("lesson_preparations") \
            .update(row).eq("id", existing.data[0]["id"]).execute()
        return {"status": "updated"}
    else:
        supabase.table("lesson_preparations").insert(row).execute()
        return {"status": "created"}


@app.post("/api/admin/preparations/attachment")
async def upload_preparation_attachment(
    file: UploadFile = File(...),
    admin=Depends(get_current_admin)
):
    """رفع مرفق لتحضير الدرس (PDF، صورة، HTML، فيديو، SCORM)"""
    if not file.filename:
        raise HTTPException(status_code=400, detail="لم يُرسل ملف")

    ext  = os.path.splitext(file.filename)[1].lower()
    name = f"prep_{uuid.uuid4().hex}{ext}"
    content_bytes = await file.read()

    mime = file.content_type or "application/octet-stream"
    if ext in [".zip", ".scorm"]:  mime = "application/zip"
    elif ext in [".html", ".htm"]: mime = "text/html"

    supabase.storage.from_("resources").upload(
        path=name, file=content_bytes,
        file_options={"content-type": mime}
    )
    url = supabase.storage.from_("resources").get_public_url(name)

    file_type = "file"
    if   ext in [".pdf"]:                                   file_type = "pdf"
    elif ext in [".html", ".htm"]:                          file_type = "html"
    elif ext in [".zip", ".scorm"]:                         file_type = "scorm"
    elif ext in [".mp4", ".webm", ".ogg"]:                  file_type = "video"
    elif ext in [".jpg", ".jpeg", ".png", ".gif", ".webp"]: file_type = "image"

    return {"url": url, "name": file.filename, "type": file_type, "mime": mime}


@app.delete("/api/admin/preparations/{prep_id}")
async def delete_preparation(prep_id: int, admin=Depends(get_current_admin)):
    """حذف تحضير درس كامل"""
    supabase.table("lesson_preparations").delete().eq("id", prep_id).execute()
    return {"status": "deleted"}



# ==========================================
# --- 15. اشتراك المعلمين ---
# ==========================================

@app.post("/api/teacher/subscription/activate")
async def activate_teacher_subscription(
    code:       str = Form(...),
    teacher_id: Optional[int] = Form(default=None)
):
    """تفعيل كود اشتراك من قِبَل المعلم"""
    code_upper = code.strip().upper()

    res = supabase.table("subscription_codes").select("*").eq("code", code_upper).execute()
    if not res.data:
        raise HTTPException(status_code=404, detail="الكود غير موجود")

    entry = res.data[0]

    if entry.get("is_used"):
        raise HTTPException(status_code=400, detail="هذا الكود مستخدَم مسبقاً")

    # التحقق من نوع المستخدم — الكود يجب أن يكون للمعلم أو عاماً
    user_type = entry.get("user_type", "student")
    if user_type == "student":
        raise HTTPException(status_code=403, detail="هذا الكود مخصص للطلاب فقط")

    # حساب تاريخ الانتهاء
    months = entry.get("months", 1)
    if months == -1:
        expiry = None
    else:
        now    = datetime.now(timezone.utc)
        expiry = (now.replace(
            month=(((now.month - 1) + months) % 12) + 1,
            year=now.year + (((now.month - 1) + months) // 12)
        )).isoformat()

    update_data = {
        "is_used":              True,
        "used_at":              datetime.now(timezone.utc).isoformat(),
        "activated_by_student": teacher_id,
    }
    supabase.table("subscription_codes").update(update_data).eq("id", entry["id"]).execute()

    return {
        "status": "success",
        "months": months,
        "expiry": expiry,
        "note":   entry.get("note", "")
    }


@app.get("/api/teacher/subscription/check")
async def check_teacher_subscription(teacher_id: int):
    """التحقق من حالة اشتراك المعلم"""
    try:
        res = supabase.table("subscription_codes").select("*") \
            .eq("activated_by_student", teacher_id) \
            .eq("is_used", True) \
            .eq("user_type", "teacher") \
            .order("used_at", desc=True) \
            .limit(1).execute()

        if not res.data:
            return {"active": False, "expiry": None, "months": 0}

        entry  = res.data[0]
        months = entry.get("months", 1)
        expiry = None

        if months == -1:
            return {"active": True, "expiry": None, "months": -1, "label": "👑 دائم"}

        used_at = entry.get("used_at")
        if used_at:
            from datetime import timezone as _tz
            activated = datetime.fromisoformat(used_at.replace("Z", "+00:00"))
            expiry_dt = activated.replace(
                month=(((activated.month - 1) + months) % 12) + 1,
                year=activated.year + (((activated.month - 1) + months) // 12)
            )
            now_utc = datetime.now(timezone.utc)
            expiry  = expiry_dt.isoformat()
            active  = expiry_dt > now_utc
            return {"active": active, "expiry": expiry, "months": months}

        return {"active": True, "expiry": None, "months": months}
    except Exception as e:
        return {"active": False, "expiry": None, "months": 0}


# ==========================================
# --- 13. تشغيل المحرك المركزي ---
# ==========================================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)