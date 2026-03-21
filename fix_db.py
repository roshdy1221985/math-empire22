import sqlite3

# الاتصال بالقاعدة (الخزنة الملكية الموحدة)
conn = sqlite3.connect('royal_platform.db')
cursor = conn.cursor()

print("🚀 جاري صيانة وتحديث الخزنة الملكية (royal_platform.db)...")

# قائمة بالأعمدة المطلوب التأكد من وجودها لضمان عمل المنصة
columns_to_add = [
    ("results", "student_id", "INTEGER"),
    ("students", "school_name", "TEXT"),
    ("students", "avatar_url", "TEXT")
]

for table, col, col_type in columns_to_add:
    try:
        # محاولة إضافة العمود في حال عدم وجوده
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}")
        print(f"✅ تم إضافة العمود '{col}' بنجاح إلى جدول {table}.")
    except sqlite3.OperationalError:
        # إذا كان العمود موجوداً بالفعل، سيتجاهل الخطأ ويطبع هذه الرسالة
        print(f"ℹ️ العمود '{col}' موجود بالفعل في جدول {table}.")

# حفظ التغييرات وإغلاق الاتصال
conn.commit()
conn.close()

print("\n✨ اكتملت الصيانة بنجاح! الخزنة الآن جاهزة للانطلاق العالمي.")