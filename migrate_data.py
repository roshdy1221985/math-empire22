import sqlite3
from supabase import create_client

# إعدادات الاتصال بالسحاب
URL = "https://xlgttngreiuihutjrlev.supabase.co"
KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InhsZ3R0bmdyZWl1aWh1dGpybGV2Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzQxMTY0OTgsImV4cCI6MjA4OTY5MjQ5OH0.4Il0UbMK0a2e-2B-OyB1uoyZ6mIv2cP1NeRCM-0fTKw"
supabase = create_client(URL, KEY)

def migrate_all():
    db_path = 'royal_platform' # اسم ملفك كما هو موجود في الصورة
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    print(f"🚀 انطلاق عملية 'المدد الملكي' لنقل البيانات من {db_path}...")

    tables_to_migrate = [
        {"name": "students", "cols": "full_name, username, password, grade, school_name, avatar_url"},
        {"name": "questions", "cols": "grade, lesson, subject, q_type, question, options, answer, image_url"},
        {"name": "results", "cols": "student_id, student_name, lesson, score, total, timestamp"},
        {"name": "exams", "cols": "title, exam_type, exam_date, exam_time, target_lesson, duration, num_questions, points_per_q, target_q_type"},
        {"name": "summaries", "cols": "lesson, pdf_url"}
    ]

    for table in tables_to_migrate:
        try:
            print(f"📦 جاري فحص جدول {table['name']}...")
            cursor.execute(f"SELECT {table['cols']} FROM {table['name']}")
            rows = cursor.fetchall()
            
            if not rows:
                print(f"⚠️ الجدول {table['name']} فارغ، تم التخطي.")
                continue

            col_names = table['cols'].split(", ")
            for row in rows:
                data = {col_names[i]: row[i] for i in range(len(col_names))}
                supabase.table(table['name']).insert(data).execute()
            
            print(f"✅ تم نقل {len(rows)} سجل في جدول {table['name']} بنجاح!")
            
        except Exception as e:
            print(f"❌ تعثر نقل {table['name']}: {e}")

    conn.close()
    print("\n🏁 اكتملت الهجرة الكبرى! إمبراطوريتك الآن محصنة سحابياً بالكامل.")

if __name__ == "__main__":
    migrate_all()