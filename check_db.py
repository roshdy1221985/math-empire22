import sqlite3

def check():
    conn = sqlite3.connect('royal_platform.db')
    cursor = conn.cursor()
    
    # 1. جلب أسماء كافة الجداول
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    
    print("📋 الجداول الموجودة في القاعدة:")
    for table in tables:
        # جلب عدد الصفوف في كل جدول
        cursor.execute(f"SELECT count(*) FROM {table[0]}")
        count = cursor.fetchone()[0]
        print(f" - جدول: {table[0]} (يحتوي على {count} سطر)")

    conn.close()

if __name__ == "__main__":
    check()