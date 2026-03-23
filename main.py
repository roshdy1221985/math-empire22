import os
import uuid
from datetime import datetime, timedelta
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

SUPABASE_URL = "https://xlgttngreiuihutjrlev.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InhsZ3R0bmdyZWl1aWh1dGpybGV2Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzQxMTY0OTgsImV4cCI6MjA4OTY5MjQ5OH0.4Il0UbMK0a2e-2B-OyB1uoyZ6mIv2cP1NeRCM-0fTKw"

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

def hash_password(password: str): return pwd_context.hash(password)
def verify_password(plain, hashed): return pwd_context.verify(plain, hashed)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# ==========================================
# --- 2. تهيئة التطبيق ومعالجة الأخطاء ---
# ==========================================
app = FastAPI()

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"status": "error", "message": "عطل في الديوان الملكي", "details": str(exc)},
    )

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
for folder in ["static", "templates"]:
    path = os.path.join(BASE_DIR, folder)
    if not os.path.exists(path): os.makedirs(path)

templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

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
# --- 3. مسارات العرض (HTML) ---
# ==========================================
@app.api_route("/", methods=["GET", "HEAD"])
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
async def get_manifest():
    if os.path.exists("manifest.json"): return FileResponse("manifest.json")
    raise HTTPException(status_code=404)

@app.get("/favicon.ico")
async def get_favicon():
    path = os.path.join(BASE_DIR, "static", "teacher.jpg")
    return FileResponse(path) if os.path.exists(path) else {"message": "No favicon"}

# ==========================================
# --- 4. نظام الدخول والطلاب ---
# ==========================================
@app.post("/api/admin/login")
async def admin_login(username: str = Form(...), password: str = Form(...)):
    if username == "admin" and password == "Roshdy@2026":
        token = create_access_token(data={"sub": username})
        return {"access_token": token, "token_type": "bearer"}
    raise HTTPException(status_code=401, detail="بيانات دخول المعلم خاطئة")

@app.post("/api/student/register")
async def register_student(full_name: str=Form(...), username: str=Form(...), password: str=Form(...), grade: str=Form(...)):
    existing = supabase.table("students").select("username").eq("username", username).execute()
    if existing.data: raise HTTPException(status_code=400, detail="المستخدم موجود")
    supabase.table("students").insert({"full_name": full_name, "username": username, "password": hash_password(password), "grade": grade}).execute()
    return {"status": "success"}

@app.post("/api/student/login")
async def login_student(username: str = Form(...), password: str = Form(...)):
    res = supabase.table("students").select("*").eq("username", username).execute()
    if res.data and verify_password(password, res.data[0]['password']):
        user = res.data[0]
        user.pop('password', None)
        return {"status": "success", "user": user}
    raise HTTPException(status_code=401, detail="بيانات خاطئة")

@app.post("/api/student/update")
async def update_student(student_id: int=Form(...), full_name: str=Form(...), school_name: str=Form(None), avatar_url: str=Form(None)):
    supabase.table("students").update({"full_name": full_name, "school_name": school_name, "avatar_url": avatar_url}).eq("id", student_id).execute()
    return {"status": "success"}

# ==========================================
# --- 5. إدارة المنهج الدراسي (النظام الديناميكي) ---
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

@app.get("/api/curriculum/structure")
async def get_full_structure():
    res = supabase.table("grades").select("*, semesters(*, units(*, lessons(*)))").execute()
    return res.data

# ==========================================
# --- 6. ديوان المعلمين (تخزين سحابي دائم) ---
# ==========================================
@app.post("/api/admin/teacher-resources")
async def upload_resource(title: str=Form(...), category: str=Form(...), file: UploadFile=File(...), admin=Depends(get_current_admin)):
    file_name = f"res_{uuid.uuid4().hex}{os.path.splitext(file.filename)[1]}"
    content = await file.read()
    supabase.storage.from_("resources").upload(path=file_name, file=content, file_options={"content-type": file.content_type})
    file_url = supabase.storage.from_("resources").get_public_url(file_name)
    supabase.table("teacher_resources").insert({"title": title, "category": category, "file_url": file_url}).execute()
    return {"status": "success"}

@app.get("/api/teacher-resources")
async def get_resources():
    res = supabase.table("teacher_resources").select("*").execute()
    return res.data if res.data else []

@app.delete("/api/admin/teacher-resources/{res_id}")
async def delete_resource(res_id: int, admin=Depends(get_current_admin)):
    supabase.table("teacher_resources").delete().eq("id", res_id).execute()
    return {"status": "success"}

# ==========================================
# --- 7. بنك الأسئلة والامتحانات (سحابي) ---
# ==========================================
@app.post("/api/admin/questions")
async def add_question(
    grade: str=Form(...), lesson: str=Form(...), subject: str=Form(...), 
    q_type: str=Form(...), question: str=Form(...), options: str=Form(""), 
    answer: str=Form(...), image: UploadFile=File(None), admin=Depends(get_current_admin)
):
    img_url = ""
    if image:
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
async def edit_question(
    q_id: int, grade: str=Form(...), lesson: str=Form(...), subject: str=Form(...), 
    q_type: str=Form(...), question: str=Form(...), options: str=Form(""), 
    answer: str=Form(...), image: UploadFile=File(None), admin=Depends(get_current_admin)
):
    update_data = {"grade": grade, "lesson": lesson, "subject": subject, "q_type": q_type, "question": question, "options": options, "answer": answer}
    if image:
        img_name = f"q_img_{uuid.uuid4().hex}{os.path.splitext(image.filename)[1]}"
        content = await image.read()
        supabase.storage.from_("resources").upload(path=img_name, file=content, file_options={"content-type": image.content_type})
        update_data["image_url"] = supabase.storage.from_("resources").get_public_url(img_name)
    supabase.table("questions").update(update_data).eq("id", q_id).execute()
    return {"status": "success"}

@app.get("/api/admin/questions")
async def get_all_questions():
    res = supabase.table("questions").select("*").order("id", desc=True).execute()
    return res.data if res.data else []

@app.delete("/api/admin/questions/{q_id}")
async def delete_question(q_id: int, admin=Depends(get_current_admin)):
    supabase.table("questions").delete().eq("id", q_id).execute()
    return {"status": "success"}

@app.post("/api/admin/exams")
async def create_exam(
    title: str=Form(...), exam_type: str=Form(...), exam_date: str=Form(...), 
    exam_time: str=Form(...), target_lesson: str=Form(...), duration: int=Form(...),
    num_questions: int=Form(...), points_per_q: int=Form(...), target_q_type: str=Form(...),
    admin=Depends(get_current_admin)
):
    supabase.table("exams").insert({
        "title": title, "exam_type": exam_type, "exam_date": exam_date, "exam_time": exam_time, 
        "target_lesson": target_lesson, "duration": duration, "num_questions": num_questions, 
        "points_per_q": points_per_q, "target_q_type": target_q_type
    }).execute()
    return {"status": "success"}

@app.get("/api/exams/upcoming")
async def get_upcoming():
    res = supabase.table("exams").select("*").order("exam_date", desc=False).execute()
    return res.data if res.data else []

# ==========================================
# --- 8. الملخصات والنتائج والبحث ---
# ==========================================
@app.post("/api/admin/summaries")
async def upload_summary(lesson: str=Form(...), pdf: UploadFile=File(...), admin=Depends(get_current_admin)):
    file_name = f"sum_{uuid.uuid4().hex}.pdf"
    content = await pdf.read()
    supabase.storage.from_("resources").upload(path=file_name, file=content, file_options={"content-type": "application/pdf"})
    pdf_url = supabase.storage.from_("resources").get_public_url(file_name)
    supabase.table("summaries").upsert({"lesson": lesson, "pdf_url": pdf_url}, on_conflict="lesson").execute()
    return {"status": "success"}

@app.get("/api/admin/summaries_list")
async def get_summaries():
    res = supabase.table("summaries").select("*").execute()
    return res.data if res.data else []

@app.delete("/api/admin/summaries/{lesson:path}")
async def delete_summary(lesson: str, admin=Depends(get_current_admin)):
    supabase.table("summaries").delete().eq("lesson", unquote(lesson)).execute()
    return {"status": "success"}

@app.get("/api/student/summaries/{lesson:path}")
async def get_student_summary(lesson: str):
    res = supabase.table("summaries").select("pdf_url").eq("lesson", unquote(lesson)).execute()
    return {"pdf_url": res.data[0]["pdf_url"]} if res.data else {"pdf_url": None}

@app.post("/api/student/results")
async def save_result(student_id: int=Form(...), student_name: str=Form(...), lesson: str=Form(...), score: int=Form(...), total: int=Form(...)):
    supabase.table("results").insert({"student_id": student_id, "student_name": student_name, "lesson": lesson, "score": score, "total": total}).execute()
    return {"status": "success"}

@app.get("/api/leaderboard")
async def get_lb():
    res = supabase.table("results").select("student_name, score").execute().data
    lb = {}
    if res:
        for r in res: lb[r['student_name']] = lb.get(r['student_name'], 0) + (r['score'] * 100)
    return [{"student_name": k, "total_points": v} for k, v in sorted(lb.items(), key=lambda x: x[1], reverse=True)[:10]]

@app.get("/api/parent/search/{name:path}")
async def parent_search(name: str):
    st = supabase.table("students").select("id, full_name, grade").ilike("full_name", f"%{unquote(name)}%").execute()
    if not st.data: return {"found": False}
    student = st.data[0]
    history = supabase.table("results").select("*").eq("student_id", student["id"]).order("timestamp", desc=True).execute().data
    return {"found": True, "student": student, "history": history or []}

# ==========================================
# --- 9. التشغيل النهائي ---
# ==========================================
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 10000))
    print(f"🚀 إمبراطورية الرياضيات الملكية تنطلق سحابياً على بورت {port}...")
    uvicorn.run(app, host="0.0.0.0", port=port)