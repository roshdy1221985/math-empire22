import sqlite3

def get_db_connection():
    # الاتصال بقاعدة البيانات royal_platform الموجودة في المجلد الرئيسي
    conn = sqlite3.connect('royal_platform') 
    conn.row_factory = sqlite3.Row
    return conn

# دالة أولية للتأكد من وجود جدول الملخصات (لتجنب أخطاء الـ 404 لاحقاً)
def init_db():
    conn = get_db_connection()
    # يمكنك إضافة استعلامات إنشاء الجداول هنا إذا كانت مفقودة
    conn.close()