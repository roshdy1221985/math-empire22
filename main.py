import os
import json
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

def _is_rate_limited(ip: str, max_calls: int, window_seconds: int, key_prefix: str = "") -> bool:
    """يتحقق إذا تجاوز الـ IP الحد المسموح — يُرجع True إذا محظور
    
    key_prefix: لفصل الحدود حسب نوع الطلب (login vs check_answer vs parent_search)
    مثال: _is_rate_limited(ip, 10, 60, "login") لا يتداخل مع check_answer
    """
    key = f"{key_prefix}:{ip}" if key_prefix else ip
    now = _time.time()
    calls = _rate_store[key]
    # احتفظ فقط بالطلبات داخل النافذة الزمنية
    _rate_store[key] = [t for t in calls if now - t < window_seconds]
    if len(_rate_store[key]) >= max_calls:
        return True
    _rate_store[key].append(now)
    return False


# ══════════════════════════════════════════════════
# 🛡️ حماية رفع الملفات
# ══════════════════════════════════════════════════
ALLOWED_FILE_EXTENSIONS = {
    # مستندات
    ".pdf", ".doc", ".docx", ".ppt", ".pptx", ".xls", ".xlsx", ".txt",
    # صور
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg",
    # فيديو/صوت
    ".mp4", ".webm", ".mp3", ".wav", ".m4a",
}

MAX_FILE_SIZE_MB = 30  # الحد الأقصى لحجم الملف بالميجابايت
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024


def _validate_upload(file_content: bytes, filename: str, allowed_exts: set = None) -> str:
    """
    يتحقق من ملف مرفوع — يرفع HTTPException إذا فشل
    يُرجع الـ extension الآمن (مع نقطة)
    
    التحققات:
    1. الملف ليس فارغاً
    2. الحجم ≤ MAX_FILE_SIZE_BYTES
    3. الـ extension في القائمة المسموحة
    4. لا يحتوي path traversal (../, ./, /)
    """
    if not file_content:
        raise HTTPException(status_code=400, detail="الملف فارغ")
    
    if len(file_content) > MAX_FILE_SIZE_BYTES:
        size_mb = len(file_content) / (1024 * 1024)
        raise HTTPException(
            status_code=413,
            detail=f"الملف كبير جداً ({size_mb:.1f} MB). الحد الأقصى {MAX_FILE_SIZE_MB} MB"
        )
    
    if not filename:
        raise HTTPException(status_code=400, detail="اسم الملف مفقود")
    
    # منع path traversal
    if "/" in filename or "\\" in filename or ".." in filename:
        raise HTTPException(status_code=400, detail="اسم الملف يحتوي على رموز ممنوعة")
    
    # استخراج وفحص الـ extension
    ext = os.path.splitext(filename)[1].lower().strip()
    if not ext:
        raise HTTPException(status_code=400, detail="الملف بدون امتداد")
    
    allowed = allowed_exts if allowed_exts else ALLOWED_FILE_EXTENSIONS
    if ext not in allowed:
        raise HTTPException(
            status_code=415,
            detail=f"امتداد '{ext}' غير مسموح. المسموح: {', '.join(sorted(allowed))}"
        )
    
    return ext


def _is_safe_url(url: str) -> bool:
    """يتحقق من سلامة URL خارجي — يمنع javascript:, data:, file:, إلخ"""
    if not url:
        return False
    url_lower = url.strip().lower()
    # نقبل فقط http/https
    if not (url_lower.startswith("https://") or url_lower.startswith("http://")):
        return False
    # نمنع localhost / private IPs (يتطلب extra parsing لكن الأساس)
    blocked_hosts = ["localhost", "127.0.0.1", "0.0.0.0", "169.254.", "::1"]
    for host in blocked_hosts:
        if host in url_lower:
            return False
    return True


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

# ═══ Web Push Notifications (VAPID) ═══
VAPID_PUBLIC_KEY  = os.environ.get("VAPID_PUBLIC_KEY", "")
VAPID_PRIVATE_KEY = os.environ.get("VAPID_PRIVATE_KEY", "")
VAPID_CLAIMS_SUB  = os.environ.get("VAPID_CLAIMS_SUB", "mailto:rashdy.sayed@example.com")

# pywebpush قد لا يكون مثبتاً — نستورده بحذر
try:
    from pywebpush import webpush, WebPushException  # type: ignore
    PUSH_ENABLED = bool(VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY)
except ImportError:
    PUSH_ENABLED = False
    print("⚠️ pywebpush غير مثبت — سيتم تخطي push notifications")


def _send_push_to_endpoint(subscription_info: dict, payload: dict) -> bool:
    """يُرسل push لاشتراك واحد. يُرجع True عند النجاح."""
    if not PUSH_ENABLED:
        return False
    try:
        webpush(
            subscription_info=subscription_info,
            data=json.dumps(payload, ensure_ascii=False),
            vapid_private_key=VAPID_PRIVATE_KEY,
            vapid_claims={"sub": VAPID_CLAIMS_SUB}
        )
        return True
    except WebPushException as e:
        # لو 410/404 → الاشتراك منتهي، احذفه
        if e.response and e.response.status_code in (410, 404):
            try:
                supabase.table("push_subscriptions").delete().eq(
                    "endpoint", subscription_info.get("endpoint", "")
                ).execute()
            except Exception:
                pass
        return False
    except Exception:
        return False


def _push_to_student(student_id: int, title: str, body: str,
                     url: str = "/student", tag: str = "general",
                     icon: str = "/static/icon-192.png", require_interaction: bool = False) -> int:
    """يُرسل push لكل اشتراكات طالب معيّن. يُرجع عدد الإرسالات الناجحة."""
    if not PUSH_ENABLED:
        return 0
    try:
        res = supabase.table("push_subscriptions").select(
            "endpoint, p256dh, auth"
        ).eq("student_id", student_id).execute()
        subs = res.data or []
    except Exception:
        return 0
    
    sent = 0
    payload = {
        "title": title,
        "body": body,
        "url": url,
        "tag": tag,
        "icon": icon,
        "requireInteraction": require_interaction,
    }
    for s in subs:
        info = {
            "endpoint": s["endpoint"],
            "keys": {"p256dh": s["p256dh"], "auth": s["auth"]}
        }
        if _send_push_to_endpoint(info, payload):
            sent += 1
    return sent


def _push_to_grade(grade: str, title: str, body: str, url: str = "/student", tag: str = "general") -> int:
    """يُرسل push لكل طلاب صف معيّن"""
    if not PUSH_ENABLED:
        return 0
    try:
        # اجلب IDs الطلاب في الصف
        st_res = supabase.table("students").select("id").eq("grade", grade).execute()
        student_ids = [s["id"] for s in (st_res.data or [])]
        if not student_ids:
            return 0
        # اجلب اشتراكاتهم
        sub_res = supabase.table("push_subscriptions").select(
            "endpoint, p256dh, auth, student_id"
        ).in_("student_id", student_ids).execute()
        subs = sub_res.data or []
    except Exception:
        return 0
    
    sent = 0
    payload = {"title": title, "body": body, "url": url, "tag": tag, "icon": "/static/icon-192.png"}
    for s in subs:
        info = {"endpoint": s["endpoint"], "keys": {"p256dh": s["p256dh"], "auth": s["auth"]}}
        if _send_push_to_endpoint(info, payload):
            sent += 1
    return sent



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
    """
    جلب الأسئلة كاملةً للأدمن — مع pagination تلقائي
    لأن Supabase يحدد كل query بـ 1000 صف افتراضياً
    """
    all_questions = []
    page_size = 1000
    offset = 0
    max_iterations = 50  # حد أقصى للأمان (50,000 سؤال)
    
    for _ in range(max_iterations):
        try:
            res = supabase.table("questions").select("*").order("id", desc=True).range(offset, offset + page_size - 1).execute()
            batch = res.data or []
            if not batch:
                break
            all_questions.extend(batch)
            if len(batch) < page_size:
                break  # آخر صفحة
            offset += page_size
        except Exception as e:
            print(f"questions pagination error at offset {offset}: {e}")
            break
    
    return all_questions

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
    # ═══ تحقق آمن من الملف ═══
    content = await file.read()
    file_extension = _validate_upload(content, file.filename or "")

    file_name = f"res_{uuid.uuid4().hex}{file_extension}"

    supabase.storage.from_("resources").upload(
        path=file_name,
        file=content,
        file_options={"content-type": file.content_type or "application/octet-stream"}
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
            # ═══ تحقق آمن من الملف ═══
            content        = await pdf.read()
            file_extension = _validate_upload(content, pdf.filename)
            file_name      = f"res_{uuid.uuid4().hex}{file_extension}"
            content_type   = pdf.content_type or "application/pdf"
            supabase.storage.from_("resources").upload(
                path=file_name, file=content,
                file_options={"content-type": content_type}
            )
            resource_url = supabase.storage.from_("resources").get_public_url(file_name)
        else:
            if not external_url:
                raise HTTPException(status_code=400, detail="يرجى إدخال الرابط الخارجي")
            # ═══ تحقق من سلامة الرابط الخارجي (منع javascript:, file:, إلخ) ═══
            if not _is_safe_url(external_url):
                raise HTTPException(status_code=400, detail="الرابط غير صالح — يجب أن يبدأ بـ https:// أو http://")
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
    """قائمة المصادر التعليمية — متاحة لكل المستخدمين (لا تكشف بيانات حساسة)
    تُرجع: lesson, resource_type, resource_label, external_url, file_url
    """
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
    """
    تحديث last_active للطالب + حفظ session bucket
    يُستدعى كل دقيقة من العميل أثناء النشاط
    
    Bucket = 5 دقائق → الطالب يُسجَّل مرة واحدة في كل bucket
    وقت الطالب اليومي = عدد buckets فريدة × 5 دقائق
    """
    now = datetime.now(timezone.utc)
    try:
        # 1. تحديث last_active في students (للتوافق)
        supabase.table("students").update({
            "last_active": now.isoformat()
        }).eq("id", student_id).execute()
        
        # 2. حفظ session bucket (مدة 5 دقائق)
        # نقرّب الوقت لأقرب 5 دقائق (12:00, 12:05, 12:10, ...)
        bucket_minute = (now.minute // 5) * 5
        bucket = now.replace(minute=bucket_minute, second=0, microsecond=0)
        
        # جلب بيانات الطالب لتسجيلها مع الجلسة
        try:
            stu_res = supabase.table("students").select("full_name, grade").eq("id", student_id).limit(1).execute()
            stu_data = stu_res.data[0] if stu_res.data else {}
        except Exception:
            stu_data = {}
        
        # upsert: إن كان الـ bucket موجود، نحدّث last_seen + counter
        try:
            existing = supabase.table("student_sessions").select("id, heartbeat_count")\
                .eq("student_id", student_id).eq("session_bucket", bucket.isoformat()).limit(1).execute()
            if existing.data:
                supabase.table("student_sessions").update({
                    "last_seen": now.isoformat(),
                    "heartbeat_count": (existing.data[0].get("heartbeat_count", 1) or 1) + 1
                }).eq("id", existing.data[0]["id"]).execute()
            else:
                supabase.table("student_sessions").insert({
                    "student_id": student_id,
                    "student_name": stu_data.get("full_name", ""),
                    "grade": stu_data.get("grade", ""),
                    "session_bucket": bucket.isoformat(),
                    "last_seen": now.isoformat(),
                    "heartbeat_count": 1
                }).execute()
        except Exception as e:
            # الجدول قد لا يكون موجوداً بعد
            print(f"[heartbeat session] {str(e)[:100]}")
        
        return {"status": "ok"}
    except Exception:
        return {"status": "skipped"}


@app.get("/api/admin/stats/daily_activity")
async def get_daily_activity_stats(
    days: int = 7,
    admin = Depends(get_current_admin)
):
    """
    📊 إحصائيات الحضور اليومي — حقيقية ومن الـ buckets
    
    Returns:
        - daily_stats: قائمة بآخر N أيام (اليوم + N-1 يوم سابقاً)
            * date: التاريخ
            * unique_students: عدد الطلاب الفريدين
            * total_minutes: إجمالي الدقائق المُحتسبة (بكل الطلاب)
            * avg_minutes_per_student: متوسط الدقائق لكل طالب
        - today_live: الطلاب النشطون الآن (آخر 5 دقائق)
        - today_total_unique: إجمالي طلاب اليوم الفريدين
    """
    from datetime import datetime, timezone, timedelta
    
    days = max(1, min(days, 30))  # حد بين 1 و 30
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    range_start = today_start - timedelta(days=days - 1)
    
    # جلب كل sessions في النطاق المطلوب (مع pagination)
    all_sessions = []
    offset = 0
    for _ in range(50):
        try:
            res = supabase.table("student_sessions").select(
                "student_id, student_name, grade, session_bucket, last_seen, heartbeat_count"
            ).gte("session_bucket", range_start.isoformat()).order("session_bucket", desc=True).range(offset, offset + 999).execute()
            batch = res.data or []
            if not batch:
                break
            all_sessions.extend(batch)
            if len(batch) < 1000:
                break
            offset += 1000
        except Exception as e:
            print(f"[daily_activity] {e}")
            break
    
    # تجميع حسب التاريخ
    from collections import defaultdict
    daily = defaultdict(lambda: {"buckets": 0, "students": set(), "by_grade": defaultdict(set)})
    
    for s in all_sessions:
        bucket_str = s.get("session_bucket", "")
        if not bucket_str:
            continue
        try:
            dt = datetime.fromisoformat(bucket_str.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            date_key = dt.date().isoformat()
            daily[date_key]["buckets"] += 1
            sid = s.get("student_id")
            if sid:
                daily[date_key]["students"].add(sid)
                grade = s.get("grade") or "غير محدد"
                daily[date_key]["by_grade"][grade].add(sid)
        except Exception:
            continue
    
    # بناء قائمة آخر N أيام (حتى لو لا توجد بيانات)
    daily_stats = []
    for i in range(days):
        d = (today_start - timedelta(days=days - 1 - i)).date()
        key = d.isoformat()
        info = daily.get(key, {"buckets": 0, "students": set(), "by_grade": defaultdict(set)})
        unique = len(info["students"])
        total_min = info["buckets"] * 5
        daily_stats.append({
            "date": key,
            "day_name": d.strftime("%A"),  # سيُترجم في الواجهة
            "unique_students": unique,
            "total_minutes": total_min,
            "total_hours": round(total_min / 60, 1),
            "avg_minutes_per_student": round(total_min / unique, 1) if unique > 0 else 0,
            "grades_count": len(info["by_grade"]),
        })
    
    # طلاب اليوم
    today_key = today_start.date().isoformat()
    today_info = daily.get(today_key, {"buckets": 0, "students": set()})
    
    # نشطون الآن (آخر 5 دقائق)
    five_min_ago = now - timedelta(minutes=5)
    live_students = set()
    for s in all_sessions:
        try:
            seen = datetime.fromisoformat(s.get("last_seen", "").replace("Z", "+00:00"))
            if seen.tzinfo is None:
                seen = seen.replace(tzinfo=timezone.utc)
            if seen >= five_min_ago:
                sid = s.get("student_id")
                if sid:
                    live_students.add(sid)
        except Exception:
            continue
    
    return {
        "daily_stats": daily_stats,
        "today_live": len(live_students),
        "today_total_unique": len(today_info["students"]),
        "today_total_minutes": today_info["buckets"] * 5,
        "now": now.isoformat(),
    }


@app.get("/api/admin/stats/student_time/{student_id}")
async def get_student_time_breakdown(
    student_id: int,
    days: int = 30,
    admin = Depends(get_current_admin)
):
    """⏱️ تفاصيل وقت طالب معيّن خلال آخر N يوم"""
    from datetime import datetime, timezone, timedelta
    days = max(1, min(days, 90))
    range_start = datetime.now(timezone.utc) - timedelta(days=days)
    
    sessions = []
    offset = 0
    for _ in range(20):
        try:
            res = supabase.table("student_sessions").select(
                "session_bucket, heartbeat_count"
            ).eq("student_id", student_id).gte("session_bucket", range_start.isoformat()).order("session_bucket", desc=True).range(offset, offset + 999).execute()
            batch = res.data or []
            if not batch:
                break
            sessions.extend(batch)
            if len(batch) < 1000:
                break
            offset += 1000
        except Exception:
            break
    
    # تجميع يومي
    from collections import defaultdict
    daily = defaultdict(int)
    for s in sessions:
        try:
            dt = datetime.fromisoformat(s["session_bucket"].replace("Z", "+00:00"))
            daily[dt.date().isoformat()] += 5  # كل bucket = 5 دقائق
        except Exception:
            continue
    
    total_minutes = sum(daily.values())
    days_active   = len(daily)
    
    return {
        "student_id":      student_id,
        "total_minutes":   total_minutes,
        "total_hours":     round(total_minutes / 60, 1),
        "days_active":     days_active,
        "avg_per_day":     round(total_minutes / days_active, 1) if days_active else 0,
        "daily_breakdown": [{"date": k, "minutes": v} for k, v in sorted(daily.items())],
    }





@app.post("/api/student/update_profile")
async def student_update_profile(
    student_id: int = Form(...),
    full_name: str  = Form(default=""),
    school_name: str = Form(default=""),
    avatar_url: str = Form(default="")
):
    """
    تحديث بيانات ملف الطالب الشخصي (الاسم، المدرسة، الأفاتار).
    لا يمكن تغيير اسم المستخدم أو كلمة المرور أو الصف من هنا.
    """
    update_data = {}
    if full_name.strip():
        update_data["full_name"] = full_name.strip()[:120]
    if school_name.strip():
        update_data["school_name"] = school_name.strip()[:120]
    if avatar_url.strip():
        update_data["avatar_url"] = avatar_url.strip()[:500]

    if not update_data:
        raise HTTPException(status_code=400, detail="لا توجد بيانات للتحديث")

    try:
        res = supabase.table("students").update(update_data).eq("id", student_id).execute()
        if not res.data:
            raise HTTPException(status_code=404, detail="الطالب غير موجود")
        # نُرجع البيانات المحدّثة (بدون كلمة المرور)
        student = res.data[0]
        student.pop("password", None)
        return {"status": "success", "user": student}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"فشل تحديث البيانات: {str(e)}")


@app.get("/api/config/public")
async def get_public_config():
    """يُعيد إعدادات عامة آمنة للواجهة (مثل Supabase URL و anon key للـ Realtime)"""
    return {
        "supabase_url": SUPABASE_URL,
        "supabase_key": SUPABASE_KEY,  # anon key — آمن للعرض العام
    }


@app.get("/api/leaderboard")
async def get_lb():
    """لوحة الصدارة — مع pagination كامل لجميع النتائج"""
    all_results = []
    offset = 0
    for _ in range(50):  # حد أقصى 50,000 نتيجة
        try:
            res = supabase.table("results").select("student_name, score, grade").range(offset, offset + 999).execute()
            batch = res.data or []
            if not batch:
                break
            all_results.extend(batch)
            if len(batch) < 1000:
                break
            offset += 1000
        except Exception as e:
            print(f"leaderboard pagination error: {e}")
            break
    
    lb = {}
    grades = {}
    for r in all_results:
        name = r.get("student_name") or ""
        if not name: continue
        lb[name] = lb.get(name, 0) + (r.get("score") or 0)
        if "grade" in r and r["grade"]:
            grades[name] = r["grade"]
    
    sorted_lb = sorted(lb.items(), key=lambda x: x[1], reverse=True)
    return [{"student_name": k, "total_points": v, "grade": grades.get(k, "")} for k, v in sorted_lb]

@app.get("/api/parent/search/{query:path}")
async def parent_search(query: str, request: Request):
    """
    بحث ولي الأمر — يقبل **كود ولي الأمر فقط** (RS-XXXXX) للحفاظ على خصوصية الطلاب
    تم تقييد البحث بالـ ID/username/الاسم لمنع كشف بيانات الطلاب لأي شخص.
    Rate limit: 20 محاولة/دقيقة لكل IP لمنع brute force على الكودات
    """
    # ═══ Rate limiting لمنع تخمين الأكواد ═══
    ip = request.client.host if request.client else "unknown"
    if _is_rate_limited(ip, max_calls=20, window_seconds=60, key_prefix="parent_search"):
        raise HTTPException(status_code=429, detail="⏳ محاولات كثيرة — انتظر دقيقة")

    clean = unquote(query).strip()
    if not clean:
        return {"found": False, "message": "يرجى إدخال كود ولي الأمر"}

    # ═══ نقبل فقط: parent_code (RS-XXXXX) أو الكود بدون البادئة ═══
    pc = clean.upper() if clean.upper().startswith("RS-") else f"RS-{clean.upper()}"

    # تحقق من الصيغة: RS- + 4-10 أحرف/أرقام
    import re as _re
    if not _re.match(r'^RS-[A-Z0-9]{4,10}$', pc):
        return {"found": False, "message": "صيغة الكود غير صحيحة. مثال: RS-AB12C"}

    st = supabase.table("students").select(
        "id, full_name, grade, username, created_at"
    ).eq("parent_code", pc).execute()

    if not st.data:
        return {"found": False, "message": "لم يعثر على طالب بهذا الكود"}

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
    """جلب قائمة جميع الطلاب للأدمن (للربط بأكواد الاشتراك والنخبة)"""
    res = supabase.table("students").select("id, full_name, grade, username, parent_code").order("full_name").execute()
    return res.data if res.data else []


def _count_active_recent(results: list, days: int = 7) -> int:
    """يحسب عدد الطلاب الفريدين الذين شاركوا في آخر N أيام"""
    from datetime import datetime, timezone, timedelta
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    active_ids = set()
    for r in results:
        ts = r.get("timestamp", "")
        if not ts:
            continue
        try:
            if isinstance(ts, str):
                ts = ts.replace("Z", "+00:00")
                dt = datetime.fromisoformat(ts)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                if dt >= cutoff:
                    sid = r.get("student_id")
                    if sid:
                        active_ids.add(sid)
        except Exception:
            continue
    return len(active_ids)


@app.post("/api/student/forgot_password")
async def student_forgot_password(
    request: Request,
    username: str       = Form(...),
    parent_code: str    = Form(...),
    new_password: str   = Form(...),
):
    """
    استعادة كلمة مرور طالب — يتطلب كود ولي الأمر للأمان
    Rate-limit: 5 محاولات / دقيقة لكل IP
    """
    import re
    
    # 🛡️ rate limiting يدوي
    ip = request.client.host if request.client else "unknown"
    if _is_rate_limited(ip, max_calls=5, window_seconds=60, key_prefix="forgot_pwd"):
        raise HTTPException(status_code=429, detail="محاولات كثيرة — انتظر دقيقة وحاول مرة أخرى")
    
    # تحقق من شكل الكود
    if not re.match(r'^RS-[A-Z0-9]{4,12}$', parent_code.strip().upper()):
        raise HTTPException(status_code=400, detail="كود ولي الأمر غير صالح")
    if len(new_password) < 6:
        raise HTTPException(status_code=400, detail="كلمة المرور قصيرة (6+ أحرف)")
    if len(username) < 3:
        raise HTTPException(status_code=400, detail="اسم المستخدم غير صالح")

    try:
        # ابحث عن الطالب باسم المستخدم + كود ولي الأمر
        res = supabase.table("students").select("id, username, parent_code").eq(
            "username", username.strip()
        ).eq("parent_code", parent_code.strip().upper()).limit(1).execute()
        
        if not res.data:
            raise HTTPException(
                status_code=404,
                detail="لم نعثر على حساب بهذا الاسم وكود ولي الأمر — تحقق من البيانات"
            )

        student_id = res.data[0]["id"]
        # حدّث كلمة المرور (مع hashing)
        hashed = hash_password(new_password)
        supabase.table("students").update({
            "password": hashed
        }).eq("id", student_id).execute()
        
        return {"status": "success", "message": "تم تحديث كلمة المرور"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"خطأ: {str(e)[:200]}")


@app.post("/api/admin/update_password")
async def update_admin_password(
    new_password: str = Form(...),
    admin = Depends(get_current_admin)
):
    """
    تحديث كلمة مرور الأدمن — يُحفظ في system_state
    ملاحظة: لا يُحدّث env var ADMIN_PASSWORD مباشرة، لكن يُتيح override
    """
    if len(new_password) < 6:
        raise HTTPException(status_code=400, detail="كلمة المرور قصيرة جداً (6+ أحرف)")
    try:
        # نحفظ في system_state لـ override
        supabase.table("system_state").upsert({
            "key": "admin_password_override",
            "value": new_password.strip(),
            "updated_at": datetime.now(timezone.utc).isoformat()
        }).execute()
        return {"status": "success", "message": "تم تحديث كلمة المرور"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"خطأ: {str(e)[:200]}")


@app.get("/api/admin/reports/full")
async def get_full_report(admin=Depends(get_current_admin)):
    """تقرير شامل للإمبراطورية — الطلاب + النتائج + الإحصائيات"""
    # جلب كل الطلاب (مع pagination)
    students = []
    offset = 0
    for _ in range(20):  # حد أقصى 20,000 طالب
        try:
            res_batch = supabase.table("students").select(
                "id, full_name, grade, username, created_at"
            ).order("full_name").range(offset, offset + 999).execute()
            batch = res_batch.data or []
            if not batch:
                break
            students.extend(batch)
            if len(batch) < 1000:
                break
            offset += 1000
        except Exception as e:
            print(f"students pagination error: {e}")
            break

    # جلب كل النتائج (مع pagination لتجاوز حد 1000)
    results = []
    offset = 0
    page_size = 1000
    for _ in range(50):  # حد أقصى 50,000 نتيجة
        try:
            res_batch = supabase.table("results").select(
                "student_id, student_name, lesson, score, total, timestamp"
            ).order("timestamp", desc=True).range(offset, offset + page_size - 1).execute()
            batch = res_batch.data or []
            if not batch:
                break
            results.extend(batch)
            if len(batch) < page_size:
                break
            offset += page_size
        except Exception as e:
            print(f"results pagination error: {e}")
            break

    # جلب عدد الأسئلة الفعلي (count من Supabase وليس len(data) لأن data محدد بـ 1000)
    try:
        q_res = supabase.table("questions").select("id", count="exact").limit(1).execute()
        total_questions = q_res.count if hasattr(q_res, "count") and q_res.count is not None else 0
    except Exception:
        total_questions = 0

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
            "active_last_7days": _count_active_recent(results, days=7),
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
        "body":     body.strip()[:5000],
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
    """جلب قائمة الطلاب الكاملة + إحصائيات XP والتحديات والوقت الفعلي"""
    # 1. جلب كل الطلاب (pagination)
    students = []
    offset = 0
    for _ in range(20):
        try:
            res = supabase.table("students").select(
                "id, full_name, username, grade, school_name, avatar_url, is_active, is_elite, created_at, last_active"
            ).order("full_name").range(offset, offset + 999).execute()
            batch = res.data or []
            if not batch:
                break
            students.extend(batch)
            if len(batch) < 1000:
                break
            offset += 1000
        except Exception:
            break

    # 2. جلب كل النتائج (pagination) لحساب XP والتحديات
    all_results = []
    offset = 0
    for _ in range(50):
        try:
            res = supabase.table("results").select(
                "student_id, student_name, score, total, timestamp"
            ).range(offset, offset + 999).execute()
            batch = res.data or []
            if not batch:
                break
            all_results.extend(batch)
            if len(batch) < 1000:
                break
            offset += 1000
        except Exception:
            break

    # 3. تجميع إحصائيات لكل طالب
    from collections import defaultdict
    stats = defaultdict(lambda: {"xp": 0, "tests": 0, "score_sum": 0, "total_sum": 0})
    for r in all_results:
        sid = r.get("student_id")
        if not sid:
            continue
        stats[sid]["xp"]        += r.get("score", 0) or 0
        stats[sid]["tests"]     += 1
        stats[sid]["score_sum"] += r.get("score", 0) or 0
        stats[sid]["total_sum"] += r.get("total", 0) or 0

    # 4. جلب وقت الجلسات (آخر 30 يوم) لكل طالب
    from datetime import datetime, timezone, timedelta
    range_30 = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    sessions_by_student = defaultdict(int)  # student_id -> bucket count
    offset = 0
    for _ in range(50):
        try:
            res = supabase.table("student_sessions").select(
                "student_id"
            ).gte("session_bucket", range_30).range(offset, offset + 999).execute()
            batch = res.data or []
            if not batch:
                break
            for s in batch:
                sid = s.get("student_id")
                if sid:
                    sessions_by_student[sid] += 1
            if len(batch) < 1000:
                break
            offset += 1000
        except Exception:
            break

    # 5. دمج البيانات
    enriched = []
    for s in students:
        sid = s.get("id")
        sst = stats.get(sid, {"xp": 0, "tests": 0, "score_sum": 0, "total_sum": 0})
        avg_pct = round((sst["score_sum"] / sst["total_sum"]) * 100, 1) if sst["total_sum"] > 0 else 0
        minutes_30d = sessions_by_student.get(sid, 0) * 5
        enriched.append({
            **s,
            "xp":            sst["xp"],
            "tests":         sst["tests"],
            "avg_score_pct": avg_pct,
            "minutes_30d":   minutes_30d,
            "hours_30d":     round(minutes_30d / 60, 1),
        })

    return enriched


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
# --- 12.5 🎓 نظام السنة الدراسية (Academic Year) ---
# ==========================================
"""
آلية العمل:
- السنة الدراسية: سبتمبر → يوليو (2025-2026 ← مثال)
- 1 أغسطس: أرشفة تلقائية + تصفير XP (لكن الحفاظ على الأوسمة والأفاتار)
- 1 سبتمبر: ترقية تلقائية للصف التالي + لقب "خريج"
- كل عمليات التصفير/الأرشفة idempotent (لن تتكرر في نفس السنة)
"""

# ═══ مخطط ترقية الصفوف ═══
GRADE_PROGRESSION = {
    "الصف الأول الابتدائي":  "الصف الثاني الابتدائي",
    "الصف الثاني الابتدائي": "الصف الثالث الابتدائي",
    "الصف الثالث الابتدائي": "الصف الرابع الابتدائي",
    "الصف الرابع الابتدائي": "الصف الخامس الابتدائي",
    "الصف الخامس الابتدائي": "الصف السادس الابتدائي",
    "الصف السادس الابتدائي": "الصف السابع",
    "الصف السابع":           "الصف الثامن",
    "الصف الثامن":           "الصف التاسع",
    "الصف التاسع":           "الصف العاشر",
    "الصف العاشر":           "الصف الحادي عشر",
    "الصف الحادي عشر":       "الصف الثاني عشر",
    "الصف الثاني عشر":       "خريج الثانوية",  # نهاية المسار
}


def _get_current_academic_year() -> str:
    """يحسب السنة الدراسية الحالية — من سبتمبر لأغسطس"""
    now = datetime.now(timezone.utc)
    if now.month >= 9:
        # من سبتمبر = بداية سنة جديدة
        return f"{now.year}-{now.year + 1}"
    else:
        # من يناير إلى أغسطس = السنة ما زالت الحالية
        return f"{now.year - 1}-{now.year}"


def _get_system_state(key: str, default: str = "") -> str:
    """قراءة قيمة من system_state"""
    try:
        res = supabase.table("system_state").select("value").eq("key", key).execute()
        if res.data and len(res.data) > 0:
            return res.data[0].get("value", default)
    except Exception:
        pass
    return default


def _set_system_state(key: str, value: str):
    """حفظ قيمة في system_state (upsert)"""
    try:
        supabase.table("system_state").upsert({
            "key": key,
            "value": value,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }).execute()
    except Exception as e:
        print(f"⚠️ _set_system_state error: {e}")


async def _archive_student_year(student: dict, academic_year: str) -> dict:
    """أرشفة سنة واحدة لطالب واحد — يُرجع الـ archive record"""
    student_id   = student["id"]
    student_name = student.get("full_name", "")
    grade        = student.get("grade", "")

    # جلب كل نتائج الطالب
    results = supabase.table("results").select("*").eq("student_id", student_id).execute().data or []

    # حساب الإحصائيات
    total_xp        = sum(r.get("score", 0) for r in results)
    challenges_done = len(results)
    avg_score       = 0
    if challenges_done > 0:
        total_max = sum(r.get("total", 0) for r in results)
        if total_max > 0:
            avg_score = round((total_xp / total_max) * 100, 1)

    # أفضل درس
    lesson_scores = {}
    for r in results:
        l = r.get("lesson", "")
        if l and l not in lesson_scores:
            lesson_scores[l] = 0
        if l:
            lesson_scores[l] += r.get("score", 0)
    best_lesson = max(lesson_scores.items(), key=lambda x: x[1])[0] if lesson_scores else ""

    # حساب الترتيب في الصف
    all_in_grade = supabase.table("students").select("id").eq("grade", grade).execute().data or []
    rank_data = []
    for s in all_in_grade:
        s_results = supabase.table("results").select("score").eq("student_id", s["id"]).execute().data or []
        s_xp = sum(r.get("score", 0) for r in s_results)
        rank_data.append((s["id"], s_xp))
    rank_data.sort(key=lambda x: x[1], reverse=True)
    rank_in_grade = next((i + 1 for i, (sid, _) in enumerate(rank_data) if sid == student_id), 0)

    # اللقب
    graduated_title = f"🎓 خريج السنة {academic_year} — {grade}"

    # إدراج في الأرشيف
    archive_record = {
        "student_id":      student_id,
        "student_name":    student_name,
        "academic_year":   academic_year,
        "grade":           grade,
        "total_xp":        total_xp,
        "challenges_done": challenges_done,
        "avg_score":       avg_score,
        "best_lesson":     best_lesson,
        "rank_in_grade":   rank_in_grade,
        "graduated_title": graduated_title,
        "full_history":    results,  # JSONB
        "badges_earned":   [],       # placeholder — client-side badges
    }

    try:
        supabase.table("results_archive").insert(archive_record).execute()
    except Exception as e:
        print(f"⚠️ archive insert failed for {student_name}: {e}")
        return {}

    return archive_record


async def _run_annual_archive(academic_year: str, dry_run: bool = False) -> dict:
    """
    ينفّذ الأرشفة السنوية لكل الطلاب:
    1. يُؤرشف كل نتائج السنة في results_archive
    2. يحذف النتائج القديمة من results (يبدأون من الصفر)
    3. يُضيف اللقب لـ graduation_titles في students
    4. يحفظ تاريخ الأرشفة لمنع التكرار
    
    dry_run=True: يُحصي بدون تنفيذ فعلي
    """
    # تحقق من عدم التكرار
    last = _get_system_state("last_archive_year")
    if last == academic_year and not dry_run:
        return {"status": "already_archived", "academic_year": academic_year, "students_count": 0}

    # جلب كل الطلاب النشطين
    students = supabase.table("students").select(
        "id, full_name, grade, graduation_titles"
    ).execute().data or []

    archived_count = 0
    failed_count   = 0
    archives       = []

    for student in students:
        try:
            archive = await _archive_student_year(student, academic_year)
            if archive:
                archives.append({
                    "student_id":   student["id"],
                    "student_name": student.get("full_name"),
                    "total_xp":     archive.get("total_xp"),
                    "title":        archive.get("graduated_title"),
                })
                
                if not dry_run:
                    # تحديث ألقاب الطالب + مسح نتائجه
                    old_titles = student.get("graduation_titles") or []
                    if isinstance(old_titles, str):
                        import json as _json
                        try: old_titles = _json.loads(old_titles)
                        except: old_titles = []
                    old_titles.append(archive.get("graduated_title"))
                    
                    supabase.table("students").update({
                        "graduation_titles": old_titles,
                        "last_archived_at":  datetime.now(timezone.utc).isoformat(),
                        "current_academic_year": "",  # مؤقت — حتى سبتمبر تأتي
                    }).eq("id", student["id"]).execute()
                    
                    # حذف نتائج السنة المُنقضية
                    supabase.table("results").delete().eq("student_id", student["id"]).execute()
                
                archived_count += 1
        except Exception as e:
            print(f"❌ archive error for {student.get('full_name')}: {e}")
            failed_count += 1

    if not dry_run:
        _set_system_state("last_archive_year", academic_year)

    return {
        "status":          "success" if not dry_run else "dry_run",
        "academic_year":   academic_year,
        "students_count":  archived_count,
        "failed_count":    failed_count,
        "archives":        archives[:20],  # أول 20 فقط في الرد
    }


async def _run_grade_promotion(target_year: str, dry_run: bool = False) -> dict:
    """
    ترقية كل الطلاب للصف التالي:
    — تُنفّذ في سبتمبر (بداية السنة الجديدة)
    — تُحدّث grade + current_academic_year
    """
    last_promo = _get_system_state("last_promotion_year")
    if last_promo == target_year and not dry_run:
        return {"status": "already_promoted", "academic_year": target_year, "students_count": 0}

    students = supabase.table("students").select("id, full_name, grade").execute().data or []

    promoted   = 0
    graduated  = 0
    promotions = []

    for s in students:
        current_grade = s.get("grade", "").strip()
        next_grade    = GRADE_PROGRESSION.get(current_grade)
        
        if not next_grade:
            continue
        
        if next_grade == "خريج الثانوية":
            graduated += 1
            if not dry_run:
                supabase.table("students").update({
                    "is_active": False,
                    "grade": next_grade,
                    "grade_promoted_at": datetime.now(timezone.utc).isoformat()
                }).eq("id", s["id"]).execute()
        else:
            promoted += 1
            if not dry_run:
                supabase.table("students").update({
                    "grade": next_grade,
                    "current_academic_year": target_year,
                    "grade_promoted_at": datetime.now(timezone.utc).isoformat()
                }).eq("id", s["id"]).execute()
        
        promotions.append({
            "student_id":    s["id"],
            "student_name":  s.get("full_name"),
            "from_grade":    current_grade,
            "to_grade":      next_grade,
        })

    if not dry_run:
        _set_system_state("last_promotion_year", target_year)

    return {
        "status":         "success" if not dry_run else "dry_run",
        "academic_year":  target_year,
        "promoted":       promoted,
        "graduated":      graduated,
        "details":        promotions[:20],
    }


# ═══ Endpoints عامة (متاحة للطلاب والأدمن) ═══

@app.get("/api/academic/current_year")
async def get_current_year():
    """السنة الدراسية الحالية + حالة الأرشفة"""
    now = datetime.now(timezone.utc)
    current_year = _get_current_academic_year()
    last_archive = _get_system_state("last_archive_year")
    
    # هل يجب عرض تنبيه للطالب بنهاية السنة؟
    show_end_warning = now.month == 7  # يوليو = شهر التحذير
    
    return {
        "current_year":      current_year,
        "last_archived":     last_archive,
        "month":             now.month,
        "show_end_warning":  show_end_warning,
        "year_ends_on":      f"{now.year if now.month >= 9 else now.year}-07-31",
    }


@app.get("/api/student/archive/{student_id}")
async def get_student_archive(student_id: int):
    """جلب أرشيف الطالب (كل سنواته السابقة)"""
    res = supabase.table("results_archive").select(
        "academic_year, grade, total_xp, challenges_done, avg_score, "
        "best_lesson, rank_in_grade, graduated_title, archived_at"
    ).eq("student_id", student_id).order("archived_at", desc=True).execute()
    
    return {
        "archives": res.data if res.data else [],
        "count":    len(res.data) if res.data else 0,
    }


@app.get("/api/student/{student_id}/year_summary")
async def get_year_summary(student_id: int):
    """ملخص السنة الحالية للطالب — يُعرض في يوليو قبل الأرشفة"""
    st = supabase.table("students").select("full_name, grade").eq("id", student_id).execute()
    if not st.data:
        raise HTTPException(status_code=404, detail="الطالب غير موجود")
    
    results = supabase.table("results").select("*").eq("student_id", student_id).execute().data or []
    
    total_xp = sum(r.get("score", 0) for r in results)
    challenges = len(results)
    avg_pct = 0
    if challenges > 0:
        total_max = sum(r.get("total", 0) for r in results)
        if total_max > 0:
            avg_pct = round((total_xp / total_max) * 100, 1)
    
    # أفضل 3 دروس
    lesson_scores = {}
    for r in results:
        l = r.get("lesson", "")
        if l:
            lesson_scores[l] = lesson_scores.get(l, 0) + r.get("score", 0)
    top_lessons = sorted(lesson_scores.items(), key=lambda x: x[1], reverse=True)[:3]
    
    return {
        "student":          st.data[0],
        "academic_year":    _get_current_academic_year(),
        "total_xp":         total_xp,
        "challenges_done":  challenges,
        "avg_score":        avg_pct,
        "top_lessons":      [{"lesson": l, "xp": x} for l, x in top_lessons],
    }


# ═══ Endpoints للأدمن فقط (تحكم يدوي) ═══

@app.post("/api/admin/academic/archive_year")
async def trigger_archive(
    request: Request,
    admin=Depends(get_current_admin)
):
    """أرشفة سنوية يدوية (يستخدمها الأدمن أو Cron)"""
    body = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    academic_year = body.get("academic_year", _get_current_academic_year())
    dry_run       = bool(body.get("dry_run", False))
    
    result = await _run_annual_archive(academic_year, dry_run=dry_run)
    return result


@app.post("/api/admin/academic/promote_grades")
async def trigger_promotion(
    request: Request,
    admin=Depends(get_current_admin)
):
    """ترقية جماعية للصف التالي"""
    body = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    target_year = body.get("academic_year", _get_current_academic_year())
    dry_run     = bool(body.get("dry_run", False))
    
    result = await _run_grade_promotion(target_year, dry_run=dry_run)
    return result


@app.get("/api/admin/academic/archives")
async def list_all_archives(admin=Depends(get_current_admin)):
    """عرض كل الأرشيفات السنوية (مجمعة حسب السنة)"""
    res = supabase.table("results_archive").select(
        "id, student_id, student_name, academic_year, grade, total_xp, "
        "challenges_done, avg_score, rank_in_grade, archived_at"
    ).order("archived_at", desc=True).execute()
    
    archives = res.data or []
    
    # تجميع حسب السنة
    by_year = {}
    for a in archives:
        year = a.get("academic_year", "—")
        if year not in by_year:
            by_year[year] = []
        by_year[year].append(a)
    
    return {
        "total_archives": len(archives),
        "by_year":        by_year,
    }


# ═══ Auto-check في كل request (خفيف جداً) ═══
_LAST_AUTO_CHECK = {"date": None}

@app.middleware("http")
async def auto_academic_tasks(request: Request, call_next):
    """
    Middleware يتحقق مرة في اليوم من:
    - 1 أغسطس: تشغيل الأرشفة التلقائية
    - 1 سبتمبر: تشغيل ترقية الصفوف
    """
    try:
        today = datetime.now(timezone.utc).date()
        
        # مرة في اليوم فقط
        if _LAST_AUTO_CHECK["date"] != today:
            _LAST_AUTO_CHECK["date"] = today
            
            # 1 أغسطس → أرشفة
            if today.month == 8 and today.day == 1:
                academic_year = f"{today.year - 1}-{today.year}"
                last = _get_system_state("last_archive_year")
                if last != academic_year:
                    print(f"🎓 [AUTO] بدء الأرشفة السنوية: {academic_year}")
                    try:
                        result = await _run_annual_archive(academic_year, dry_run=False)
                        print(f"✅ [AUTO] أرشفة: {result}")
                    except Exception as e:
                        print(f"❌ [AUTO] خطأ في الأرشفة: {e}")
            
            # 1 سبتمبر → ترقية
            if today.month == 9 and today.day == 1:
                academic_year = f"{today.year}-{today.year + 1}"
                last_promo = _get_system_state("last_promotion_year")
                if last_promo != academic_year:
                    print(f"🎓 [AUTO] بدء ترقية الصفوف: {academic_year}")
                    try:
                        result = await _run_grade_promotion(academic_year, dry_run=False)
                        print(f"✅ [AUTO] ترقية: {result}")
                    except Exception as e:
                        print(f"❌ [AUTO] خطأ في الترقية: {e}")
    except Exception as e:
        print(f"⚠️ auto_academic_tasks error (non-fatal): {e}")
    
    response = await call_next(request)
    return response


# ==========================================
# --- 13. تشغيل المحرك المركزي ---
# ==========================================


# ==========================================
# --- 12.6 📘 الدروس التفاعلية (HTML Lessons) ---
# ==========================================

# CDNs المسموح بها داخل ملفات HTML
ALLOWED_CDN_HOSTS = {
    "fonts.googleapis.com", "fonts.gstatic.com",
    "cdnjs.cloudflare.com", "cdn.jsdelivr.net",
    "unpkg.com", "cdn.tailwindcss.com",
}

DANGEROUS_HTML_PATTERNS = [
    r'fetch\s*\(', r'XMLHttpRequest', r'navigator\.sendBeacon',
    r'WebSocket\s*\(', r'EventSource\s*\(',
    r'localStorage', r'sessionStorage', r'document\.cookie', r'indexedDB',
    r'\beval\s*\(', r'new\s+Function\s*\(',
    r'setTimeout\s*\(\s*[\'"`]', r'setInterval\s*\(\s*[\'"`]',
    r'<iframe', r'<frame', r'<embed', r'<object',
    r'import\s*\([\'"]', r'importScripts\s*\(',
    r'<meta\s+[^>]*http-equiv\s*=\s*[\'"]?refresh',
    r'<form\s+[^>]*action\s*=\s*[\'"]https?://',
    r'navigator\.serviceWorker', r'navigator\.clipboard',
    r'window\.location\s*=', r'location\.href\s*=', r'location\.replace',
    r'window\.open', r'window\.top', r'window\.parent',
]

MAX_HTML_SIZE_MB = 2
MAX_HTML_SIZE_BYTES = MAX_HTML_SIZE_MB * 1024 * 1024


def _scan_html_threats(html_text: str) -> list:
    import re as _re
    warnings = []
    for pattern in DANGEROUS_HTML_PATTERNS:
        try:
            matches = _re.findall(pattern, html_text, flags=_re.IGNORECASE)
            if matches:
                sev = "high" if any(x in pattern for x in ["eval", "Function", "localStorage", "cookie", "fetch"]) else "medium"
                warnings.append({"pattern": pattern, "count": len(matches), "severity": sev})
        except Exception:
            pass
    return warnings


def _sanitize_html_lesson(html_text: str):
    """ينظّف HTML — يُرجع (cleaned, report)"""
    import re as _re
    original_size = len(html_text)
    removed = {"iframes": 0, "bad_scripts": 0, "meta_refresh": 0}
    cleaned = html_text

    # 1. حذف iframe/frame/embed/object
    for tag in ["iframe", "frame", "embed", "object"]:
        pattern = rf"<{tag}\b[^>]*>.*?</{tag}>"
        count = len(_re.findall(pattern, cleaned, flags=_re.IGNORECASE | _re.DOTALL))
        cleaned = _re.sub(pattern, "", cleaned, flags=_re.IGNORECASE | _re.DOTALL)
        self_close = rf"<{tag}\b[^>]*/?>"
        count += len(_re.findall(self_close, cleaned, flags=_re.IGNORECASE))
        cleaned = _re.sub(self_close, "", cleaned, flags=_re.IGNORECASE)
        if tag == "iframe":
            removed["iframes"] = count

    # 2. meta refresh
    meta_pattern = r'<meta\s+[^>]*http-equiv\s*=\s*[\'"]?refresh[^>]*>'
    count = len(_re.findall(meta_pattern, cleaned, flags=_re.IGNORECASE))
    cleaned = _re.sub(meta_pattern, "", cleaned, flags=_re.IGNORECASE)
    removed["meta_refresh"] = count

    # 3. scripts خارجية من نطاقات غير مسموحة
    def _check_script(match):
        src = match.group(1).lower()
        if src.startswith("//"): src = "https:" + src
        if not src.startswith(("http://", "https://")):
            return match.group(0)
        try:
            from urllib.parse import urlparse
            host = urlparse(src).netloc.lower()
            if host.startswith("www."): host = host[4:]
            allowed = any(host == a or host.endswith("." + a) for a in ALLOWED_CDN_HOSTS)
            if not allowed:
                removed["bad_scripts"] += 1
                return ""
        except Exception:
            removed["bad_scripts"] += 1
            return ""
        return match.group(0)

    script_src_pattern = r'<script\b[^>]*\bsrc\s*=\s*[\'"]([^\'"]+)[\'"][^>]*>\s*</script>'
    cleaned = _re.sub(script_src_pattern, _check_script, cleaned, flags=_re.IGNORECASE)

    report = {
        "original_size": original_size,
        "cleaned_size": len(cleaned),
        "removed": removed,
        "warnings": _scan_html_threats(cleaned),
    }
    return cleaned, report


def _wrap_html_lesson_safe(html_text: str) -> str:
    """يضيف CSP + secure links"""
    import re as _re
    csp = (
        "default-src 'self' data: blob:; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net https://unpkg.com; "
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com data:; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net https://unpkg.com https://cdn.tailwindcss.com; "
        "img-src 'self' data: https:; "
        "connect-src 'none'; "
        "frame-ancestors 'none'; "
        "base-uri 'none'; "
        "form-action 'none';"
    )
    csp_tag = f'<meta http-equiv="Content-Security-Policy" content="{csp}">'
    if "<head>" in html_text.lower():
        result = _re.sub(r"(<head[^>]*>)", r"\\1\n" + csp_tag, html_text, count=1, flags=_re.IGNORECASE)
    elif "<html" in html_text.lower():
        result = _re.sub(r"(<html[^>]*>)", r"\\1\n<head>\n" + csp_tag + "\n</head>", html_text, count=1, flags=_re.IGNORECASE)
    else:
        result = csp_tag + "\n" + html_text
    return result


@app.post("/api/admin/html_lessons")
async def upload_html_lesson(
    title: str        = Form(...),
    grade: str        = Form(...),
    semester: str     = Form(default=""),
    unit: str         = Form(default=""),
    lesson: str       = Form(...),
    description: str  = Form(default=""),
    file: UploadFile  = File(...),
    admin = Depends(get_current_admin)
):
    """رفع درس HTML تفاعلي — مع تنظيف أمني"""
    content_bytes = await file.read()
    if not content_bytes:
        raise HTTPException(status_code=400, detail="الملف فارغ")
    if len(content_bytes) > MAX_HTML_SIZE_BYTES:
        size_mb = len(content_bytes) / (1024 * 1024)
        raise HTTPException(status_code=413, detail=f"الملف كبير جداً ({size_mb:.1f} MB). الحد الأقصى {MAX_HTML_SIZE_MB} MB")
    filename = (file.filename or "").strip()
    if not filename:
        raise HTTPException(status_code=400, detail="اسم الملف مفقود")
    ext = os.path.splitext(filename)[1].lower()
    if ext not in {".html", ".htm"}:
        raise HTTPException(status_code=415, detail="الامتداد يجب .html أو .htm")
    if ".." in filename or "/" in filename or "\\" in filename:
        raise HTTPException(status_code=400, detail="اسم الملف يحتوي رموز ممنوعة")

    try:
        html_text = content_bytes.decode("utf-8")
    except UnicodeDecodeError:
        try:
            html_text = content_bytes.decode("windows-1256")
        except Exception:
            raise HTTPException(status_code=400, detail="الملف ليس UTF-8")

    cleaned, report = _sanitize_html_lesson(html_text)
    final_html = _wrap_html_lesson_safe(cleaned)

    file_name = f"html_lesson_{uuid.uuid4().hex}.html"
    try:
        supabase.storage.from_("resources").upload(
            path=file_name,
            file=final_html.encode("utf-8"),
            file_options={"content-type": "text/html; charset=utf-8"}
        )
        file_url = supabase.storage.from_("resources").get_public_url(file_name)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"فشل رفع الملف: {str(e)[:200]}")

    row = {
        "title": title[:200],
        "grade": grade[:100],
        "semester": (semester or "")[:100],
        "unit": (unit or "")[:200],
        "lesson": lesson[:300],
        "description": (description or "")[:500],
        "file_url": file_url,
        "file_size_kb": len(final_html.encode("utf-8")) // 1024,
        "sanitized": True,
    }
    try:
        supabase.table("html_lessons").insert(row).execute()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"فشل الحفظ: {str(e)[:200]}")

    return {
        "status": "success",
        "file_url": file_url,
        "sanitization": report,
        "message": f"حُذف: {report['removed']['iframes']} iframe، {report['removed']['bad_scripts']} script خارجي"
    }


@app.get("/api/html_lessons")
async def list_html_lessons(grade: str = "", lesson: str = ""):
    """قائمة الدروس التفاعلية"""
    query = supabase.table("html_lessons").select(
        "id, title, grade, semester, unit, lesson, description, file_url, file_size_kb, uploaded_at, view_count"
    )
    if grade:  query = query.eq("grade", grade)
    if lesson: query = query.eq("lesson", lesson)
    res = query.order("uploaded_at", desc=True).execute()
    return res.data or []


@app.post("/api/html_lessons/{lesson_id}/view")
async def increment_view_count(lesson_id: int):
    """زيادة عداد المشاهدات"""
    try:
        res = supabase.table("html_lessons").select("view_count").eq("id", lesson_id).execute()
        if res.data:
            current = res.data[0].get("view_count", 0) or 0
            supabase.table("html_lessons").update({"view_count": current + 1}).eq("id", lesson_id).execute()
        return {"status": "ok"}
    except Exception:
        return {"status": "error"}


@app.delete("/api/admin/html_lessons/{lesson_id}")
async def delete_html_lesson(lesson_id: int, admin = Depends(get_current_admin)):
    """حذف درس تفاعلي"""
    res = supabase.table("html_lessons").select("file_url").eq("id", lesson_id).execute()
    if res.data:
        file_url = res.data[0].get("file_url", "")
        file_name = file_url.rsplit("/", 1)[-1] if "/" in file_url else ""
        if file_name and file_name.startswith("html_lesson_"):
            try:
                supabase.storage.from_("resources").remove([file_name])
            except Exception:
                pass
    supabase.table("html_lessons").delete().eq("id", lesson_id).execute()
    return {"status": "deleted"}




# ═══════════════════════════════════════════════════════════════
# 📡 PUSH NOTIFICATIONS — تسجيل + إرسال
# ═══════════════════════════════════════════════════════════════
@app.get("/api/push/vapid_public_key")
async def get_vapid_public_key():
    """يُرجع المفتاح العام للعميل ليُسجّل اشتراك push"""
    return {"key": VAPID_PUBLIC_KEY, "enabled": PUSH_ENABLED}


@app.post("/api/push/subscribe")
async def push_subscribe(
    student_id: int = Form(...),
    endpoint: str   = Form(...),
    p256dh: str     = Form(...),
    auth: str       = Form(...),
    user_agent: str = Form(default=""),
):
    """تسجيل اشتراك push من جهاز الطالب"""
    if not endpoint or not p256dh or not auth:
        raise HTTPException(status_code=400, detail="بيانات الاشتراك ناقصة")
    try:
        # حذف اشتراك سابق بنفس endpoint إن وُجد
        supabase.table("push_subscriptions").delete().eq("endpoint", endpoint).execute()
        # إدراج الجديد
        supabase.table("push_subscriptions").insert({
            "student_id": student_id,
            "endpoint":   endpoint,
            "p256dh":     p256dh,
            "auth":       auth,
            "user_agent": user_agent[:500],
        }).execute()
        return {"status": "ok"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"خطأ: {str(e)[:200]}")


@app.post("/api/push/unsubscribe")
async def push_unsubscribe(endpoint: str = Form(...)):
    """إلغاء اشتراك push"""
    try:
        supabase.table("push_subscriptions").delete().eq("endpoint", endpoint).execute()
    except Exception:
        pass
    return {"status": "ok"}


@app.post("/api/admin/push/send_to_student/{student_id}")
async def admin_push_to_student(
    student_id: int,
    title: str = Form(...),
    body: str  = Form(...),
    url: str   = Form(default="/student"),
    admin = Depends(get_current_admin),
):
    """إرسال push يدوي لطالب"""
    sent = _push_to_student(student_id, title, body, url=url, tag="admin_push")
    return {"sent": sent, "enabled": PUSH_ENABLED}


# ═══════════════════════════════════════════════════════════════
# 📓 ADMIN TASKS — دفتر الأعمال
# ═══════════════════════════════════════════════════════════════
@app.get("/api/admin/tasks")
async def list_tasks(status: str = "", admin = Depends(get_current_admin)):
    """قائمة المهام (يمكن فلترتها بالحالة)"""
    try:
        q = supabase.table("admin_tasks").select("*")
        if status:
            q = q.eq("status", status)
        res = q.order("priority").order("due_date", nullsfirst=False).order("created_at", desc=True).execute()
        return res.data or []
    except Exception as e:
        return {"error": str(e)[:200]}


@app.post("/api/admin/tasks")
async def create_task(
    title: str       = Form(...),
    description: str = Form(default=""),
    priority: str    = Form(default="normal"),
    category: str    = Form(default="general"),
    due_date: str    = Form(default=""),
    admin = Depends(get_current_admin)
):
    """إضافة مهمة جديدة"""
    if priority not in ("low", "normal", "high", "urgent"):
        priority = "normal"
    row = {
        "title": title.strip()[:200],
        "description": description.strip()[:2000],
        "priority": priority,
        "category": category[:50],
        "status": "pending",
    }
    if due_date:
        row["due_date"] = due_date
    try:
        res = supabase.table("admin_tasks").insert(row).execute()
        return {"status": "created", "id": res.data[0]["id"] if res.data else None}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)[:200])


@app.put("/api/admin/tasks/{task_id}")
async def update_task(
    task_id: int,
    title: str       = Form(default=None),
    description: str = Form(default=None),
    priority: str    = Form(default=None),
    status: str      = Form(default=None),
    due_date: str    = Form(default=None),
    admin = Depends(get_current_admin)
):
    """تحديث مهمة"""
    update = {"updated_at": datetime.now(timezone.utc).isoformat()}
    if title is not None:       update["title"]       = title.strip()[:200]
    if description is not None: update["description"] = description.strip()[:2000]
    if priority is not None:    update["priority"]    = priority
    if status is not None:
        update["status"] = status
        if status == "done":
            update["completed_at"] = datetime.now(timezone.utc).isoformat()
    if due_date is not None:    update["due_date"]    = due_date or None
    try:
        supabase.table("admin_tasks").update(update).eq("id", task_id).execute()
        return {"status": "updated"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)[:200])


@app.delete("/api/admin/tasks/{task_id}")
async def delete_task(task_id: int, admin = Depends(get_current_admin)):
    try:
        supabase.table("admin_tasks").delete().eq("id", task_id).execute()
        return {"status": "deleted"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)[:200])


# ═══════════════════════════════════════════════════════════════
# 🎯 MOTIVATIONAL NOTIFICATIONS — تحفيز الطلاب تلقائياً
# ═══════════════════════════════════════════════════════════════
def _was_motivation_sent_today(student_id: int, notif_type: str) -> bool:
    """فحص هل أُرسل هذا النوع لهذا الطالب اليوم"""
    try:
        from datetime import date
        today = date.today().isoformat()
        res = supabase.table("motivation_log").select("id").eq(
            "student_id", student_id
        ).eq("notif_type", notif_type).eq("notif_date", today).limit(1).execute()
        return bool(res.data)
    except Exception:
        return False


def _log_motivation(student_id: int, notif_type: str):
    """سجّل أن الإشعار أُرسل"""
    try:
        supabase.table("motivation_log").insert({
            "student_id": student_id,
            "notif_type": notif_type,
        }).execute()
    except Exception:
        pass


# قوالب الرسائل التحفيزية (يمكن للأدمن تخصيصها لاحقاً)
MOTIVATION_TEMPLATES = {
    "inactive_3days": {
        "titles": [
            "🏰 إمبراطوريتك تشتاق إليك!",
            "⚔️ أبطالك ينتظرون عودتك",
            "👑 العرش يحتاج بطله",
        ],
        "bodies": [
            "غبت عن المنصة 3 أيام — تعال خض تحدياً جديداً وارفع نقاطك! ⚡",
            "لا تترك أصدقاءك يسبقونك في الترتيب — عد للمعركة! 🏆",
            "تحدٍ جديد بانتظارك في ساحة المبارزة — اضغط وابدأ! 🎯",
        ],
    },
    "inactive_7days": {
        "titles": [
            "🚨 أسبوع كامل بدون تحديات!",
            "💔 افتقدناك في إمبراطوريتنا",
        ],
        "bodies": [
            "مرّ أسبوع — استعد عرشك بحلّ تحدٍ سريع الآن! 5 دقائق فقط ⏱️",
            "زملاؤك حصلوا على 200+ XP هذا الأسبوع — لا تتأخر عنهم! 🎖️",
        ],
    },
    "streak_break": {
        "titles": ["🔥 لا تكسر سلسلة إنجازاتك!"],
        "bodies": ["كنت في طريقك لرقم قياسي — حلّ تحدٍ واحد فقط لتحافظ على السلسلة! 💪"],
    },
    "morning_motivation": {
        "titles": [
            "☀️ صباح المبارزات!",
            "🌅 يوم جديد لتحديات جديدة",
        ],
        "bodies": [
            "ابدأ يومك بحلّ تحدٍ سريع — 10 دقائق تعطيك طاقة لليوم كله! ⚡",
            "أبطال اليوم يبدؤون باكراً — كن منهم! 🏆",
        ],
    },
    "evening_reminder": {
        "titles": ["🌙 لم تتحدّ اليوم بعد!"],
        "bodies": ["لا تنهي يومك بدون تحدٍ واحد على الأقل — اكسب نقاطك! ⭐"],
    },
}


import random as _random_mod


@app.post("/api/admin/motivation/send_inactive")
async def send_motivation_inactive(
    days: int = Form(default=3),
    admin = Depends(get_current_admin)
):
    """
    إرسال إشعار تحفيزي للطلاب غير النشطين منذ N أيام
    يفحص آخر heartbeat ويُرسل push للطلاب الغائبين
    """
    from datetime import datetime, timezone, timedelta
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    
    notif_type = f"inactive_{days}days" if days in (3, 7) else "inactive_3days"
    
    # اجلب كل الطلاب
    try:
        students_res = supabase.table("students").select(
            "id, full_name, last_active"
        ).execute()
        students = students_res.data or []
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)[:200])
    
    template = MOTIVATION_TEMPLATES.get(notif_type, MOTIVATION_TEMPLATES["inactive_3days"])
    sent_count = 0
    skipped_count = 0
    
    for st in students:
        sid = st["id"]
        last_active = st.get("last_active")
        
        # تخطّى الطلاب النشطين
        if last_active:
            try:
                la_dt = datetime.fromisoformat(last_active.replace("Z", "+00:00"))
                if la_dt.tzinfo is None:
                    la_dt = la_dt.replace(tzinfo=timezone.utc)
                if la_dt > cutoff:
                    continue  # نشط — تخطَّ
            except Exception:
                pass
        
        # تخطّى لو أُرسل اليوم
        if _was_motivation_sent_today(sid, notif_type):
            skipped_count += 1
            continue
        
        # اختر رسالة عشوائية
        title = _random_mod.choice(template["titles"])
        body  = _random_mod.choice(template["bodies"])
        
        sent = _push_to_student(sid, title, body, url="/student", tag=notif_type)
        if sent > 0:
            _log_motivation(sid, notif_type)
            sent_count += 1
    
    return {
        "sent": sent_count,
        "skipped_today": skipped_count,
        "total_inactive_students": len(students),
        "push_enabled": PUSH_ENABLED,
    }


@app.post("/api/admin/motivation/send_custom")
async def send_motivation_custom(
    title: str        = Form(...),
    body: str         = Form(...),
    target: str       = Form(default="all"),  # all / grade:X / student:N
    url: str          = Form(default="/student"),
    admin = Depends(get_current_admin)
):
    """إرسال رسالة تحفيزية مخصصة"""
    if not title or not body:
        raise HTTPException(status_code=400, detail="title و body مطلوبان")
    
    sent = 0
    if target.startswith("student:"):
        try:
            sid = int(target.split(":")[1])
            sent = _push_to_student(sid, title, body, url=url, tag="custom_motivation")
        except Exception:
            pass
    elif target.startswith("grade:"):
        grade = target.split(":", 1)[1]
        sent = _push_to_grade(grade, title, body, url=url, tag="custom_motivation")
    else:
        # all — لكل الطلاب
        try:
            res = supabase.table("students").select("id").execute()
            for s in (res.data or []):
                sent += _push_to_student(s["id"], title, body, url=url, tag="custom_motivation")
        except Exception:
            pass
    
    return {"sent": sent, "push_enabled": PUSH_ENABLED}


@app.get("/api/admin/motivation/templates")
async def get_motivation_templates(admin = Depends(get_current_admin)):
    """قوالب الرسائل التحفيزية الجاهزة"""
    return MOTIVATION_TEMPLATES



if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)