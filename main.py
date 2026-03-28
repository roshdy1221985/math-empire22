import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, List
from urllib.parse import unquote

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Request, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import FileResponse, JSONResponse
from passlib.context import CryptContext
from jose import JWTError, jwt

# استيراد مكتبة السحاب (Supabase)
from supabase import create_client, Client

# ==========================================
# --- 1. الإعدادات الأمنية والاتصال ---
# ==========================================
SECRET_KEY = "ROYAL_MATH_968_OMAN" 
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480 

# بيانات الاتصال بخزنة Supabase
SUPABASE_URL = "https://xlgttngreiuihutjrlev.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InhsZ3R0bmdyZWl1aWh1dGpybGV2Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzQxMTY0OTgsImV4cCI6MjA4OTY5MjQ5OH0.4Il0UbMK0a2e-2B-OyB1uoyZ6mIv2cP1NeRCM-0fTKw"

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

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    print(f"Error occurred: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={"status": "error", "message": "عطل في الديوان الملكي", "details": str(exc)},
    )

app.add_middleware(
    CORSMiddleware, 
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"], 
    allow_headers=["*"]
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
async def admin_login(username: str = Form(...), password: str = Form(...)):
    if username == "admin" and password == "Roshdy@2026":
        token = create_access_token(data={"sub": username})
        return {"access_token": token, "token_type": "bearer"}
    raise HTTPException(status_code=401, detail="بيانات دخول المعلم خاطئة")

@app.post("/api/teacher/login")
async def teacher_login(username: str = Form(...), password: str = Form(...)):
    res = supabase.table("teachers").select("*").eq("username", username).execute()
    if res.data and verify_password(password, res.data[0]['password']):
        return {"status": "success", "user": res.data[0]}
    if username == "teacher" and password == "Oman2026":
        return {"status": "success", "user": {"full_name": "معلم رياضيات"}}
    raise HTTPException(status_code=401, detail="بيانات الدخول خاطئة")

@app.post("/api/student/register")
async def register_student(full_name: str=Form(...), username: str=Form(...), password: str=Form(...), grade: str=Form(...)):
    existing = supabase.table("students").select("username").eq("username", username).execute()
    if existing.data: raise HTTPException(status_code=400, detail="المستخدم موجود مسبقاً")
    supabase.table("students").insert({"full_name": full_name, "username": username, "password": hash_password(password), "grade": grade}).execute()
    return {"status": "success"}

@app.post("/api/student/login")
async def login_student(username: str = Form(...), password: str = Form(...)):
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
        "score": points // 10, 
        "total": points // 10
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
    res = supabase.table("grades").select("*, semesters(*, units(*, lessons(*)))").execute()
    return res.data

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
async def get_all_questions():
    res = supabase.table("questions").select("*").order("id", desc=True).execute()
    return res.data if res.data else []

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
    # الحل الجذري: أخذ امتداد الملف فقط (.pdf) وربطه برقم سري (UUID) 
    # لتجنب مشاكل الحروف العربية في قاعدة بيانات التخزين السحابي
    file_extension = os.path.splitext(file.filename)[1]
    file_name = f"res_{uuid.uuid4().hex}{file_extension}"
    
    content = await file.read()
    
    # رفع الملف بالتشفير الجديد الآمن مع تحديد نوع الملف (content-type)
    supabase.storage.from_("resources").upload(
        path=file_name, 
        file=content,
        file_options={"content-type": file.content_type}
    )
    file_url = supabase.storage.from_("resources").get_public_url(file_name)
    
    # حفظ البيانات بالاسم العربي في الجدول ليستعرضه المعلم بشكل جميل
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
async def upload_summary(lesson: str=Form(...), pdf: UploadFile=File(...), admin=Depends(get_current_admin)):
    try:
        file_extension = os.path.splitext(pdf.filename)[1]
        file_name = f"sum_{uuid.uuid4().hex}{file_extension}"
        content = await pdf.read()
        supabase.storage.from_("resources").upload(path=file_name, file=content, file_options={"content-type": "application/pdf"})
        pdf_url = supabase.storage.from_("resources").get_public_url(file_name)
        try:
             supabase.table("summaries").upsert({"lesson": lesson, "pdf_url": pdf_url}, on_conflict="lesson").execute()
        except:
             supabase.table("summaries").delete().eq("lesson", lesson).execute()
             supabase.table("summaries").insert({"lesson": lesson, "pdf_url": pdf_url}).execute()
        return {"status": "success", "url": pdf_url}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/admin/summaries_list")
async def get_summaries():
    res = supabase.table("summaries").select("*").execute()
    return res.data if res.data else []

@app.delete("/api/admin/summaries/{lesson:path}")
async def delete_summary(lesson: str, admin=Depends(get_current_admin)):
    clean_lesson = unquote(lesson)
    supabase.table("summaries").delete().eq("lesson", clean_lesson).execute()
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
            lb[r['student_name']] = lb.get(r['student_name'], 0) + (r['score'] * 100)
    sorted_lb = sorted(lb.items(), key=lambda x: x[1], reverse=True)[:10]
    return [{"student_name": k, "total_points": v} for k, v in sorted_lb]

@app.get("/api/parent/search/{name:path}")
async def parent_search(name: str):
    clean_name = unquote(name)
    st = supabase.table("students").select("id, full_name, grade").ilike("full_name", f"%{clean_name}%").execute()
    if not st.data: return {"found": False}
    student = st.data[0]
    history = supabase.table("results").select("*").eq("student_id", student["id"]).order("timestamp", desc=True).execute().data
    return {"found": True, "student": student, "history": history or []}

# ==========================================
# --- 10. تشغيل المحرك المركزي ---
# ==========================================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)