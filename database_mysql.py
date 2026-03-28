import mysql.connector
import os
import hashlib
import json


# =========================
# Database Connection
# =========================
def get_connection():
    return mysql.connector.connect(
        host="127.0.0.1",
        user="root",
        password="",
        database="arcane_db",
        auth_plugin="mysql_native_password"
    )


# =========================
# USERS
# =========================
def create_users_table():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            full_name VARCHAR(100) NOT NULL DEFAULT '',
            name VARCHAR(100) NOT NULL DEFAULT '',
            email VARCHAR(255) NOT NULL UNIQUE,
            password_hash VARCHAR(64) NOT NULL,
            salt VARCHAR(64) NOT NULL DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    cursor.close()
    conn.close()


def create_user(name, email, password):
    salt = os.urandom(16).hex()
    hashed = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (name, full_name, email, password_hash, salt) VALUES (%s, %s, %s, %s, %s)",
        (name, name, email, hashed, salt)
    )
    conn.commit()
    user_id = cursor.lastrowid
    cursor.close()
    conn.close()
    return user_id


def get_user_by_email(email):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE email=%s LIMIT 1", (email,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    return user


def verify_user(email, password):
    user = get_user_by_email(email)
    if not user:
        return None
    salt = user.get("salt", "")
    hashed = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    if hashed == user["password_hash"]:
        return user
    return None


# =========================
# SECTORS
# =========================
def get_sector_id_by_name(sector_name):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id FROM sectors WHERE LOWER(TRIM(name)) = LOWER(TRIM(%s))",
        (sector_name,)
    )
    result = cursor.fetchone()
    cursor.close()
    conn.close()
    return result[0] if result else None


# =========================
# PROJECTS
# =========================
def insert_project(user_id, sector_name, sector_id, name, description, dataset_path=None, analysis_type=None):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO projects (user_id, sector, sector_id, name, description, dataset_path, analysis_type, status)
        VALUES (%s, %s, %s, %s, %s, %s, %s, 'pending')
        """,
        (user_id, sector_name, sector_id, name, description, dataset_path, analysis_type)
    )
    conn.commit()
    project_id = cursor.lastrowid
    cursor.close()
    conn.close()
    return project_id


def get_project_by_id(project_id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT id, user_id, sector, name, description, dataset_path, analysis_type, status, created_at FROM projects WHERE id = %s",
        (project_id,)
    )
    row = cursor.fetchone()
    cursor.close()
    conn.close()
    return row


def get_projects_by_user(user_id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT id, sector, name, description, dataset_path, analysis_type, status, created_at FROM projects WHERE user_id = %s ORDER BY created_at DESC",
        (user_id,)
    )
    projects = cursor.fetchall()
    cursor.close()
    conn.close()
    return projects


def update_project_status(project_id, status):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE projects SET status=%s WHERE id=%s", (status, project_id))
    conn.commit()
    cursor.close()
    conn.close()


# =========================
# PIPELINE RESULTS
# =========================
def save_pipeline_result(project_id, data: dict):
    conn = get_connection()
    cursor = conn.cursor()

    # حذف النتيجة القديمة إن وجدت
    cursor.execute("DELETE FROM pipeline_results WHERE project_id = %s", (project_id,))

    cursor.execute(
        """
        INSERT INTO pipeline_results (
            project_id, rows_count, cols_count,
            missing_before, missing_after, duplicates_removed,
            model_accuracy, model_precision, model_recall, model_f1,
            model_r2, model_mse, model_mae,
            chart_labels, chart_data, chart_column,
            target_column, feature_importance
        ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """,
        (
            project_id,
            data.get("rows_count", 0),
            data.get("cols_count", 0),
            data.get("missing_before", 0),
            data.get("missing_after", 0),
            data.get("duplicates_removed", 0),
            data.get("model_accuracy"),
            data.get("model_precision"),
            data.get("model_recall"),
            data.get("model_f1"),
            data.get("model_r2"),
            data.get("model_mse"),
            data.get("model_mae"),
            json.dumps(data.get("chart_labels", [])),
            json.dumps(data.get("chart_data", [])),
            data.get("chart_column", ""),
            data.get("target_column", ""),
            json.dumps(data.get("feature_importance", {})),
        )
    )
    conn.commit()
    cursor.close()
    conn.close()


def get_pipeline_result(project_id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT * FROM pipeline_results WHERE project_id = %s ORDER BY created_at DESC LIMIT 1",
        (project_id,)
    )
    row = cursor.fetchone()
    cursor.close()
    conn.close()
    if row:
        for field in ["chart_labels", "chart_data", "feature_importance"]:
            if row.get(field):
                try:
                    row[field] = json.loads(row[field])
                except Exception:
                    row[field] = []
    return row


# =========================
# DASHBOARD STATS
# =========================
def get_dashboard_stats(user_id):
    """إرجاع إحصائيات حقيقية للداشبورد"""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    # عدد المشاريع الكلي
    cursor.execute("SELECT COUNT(*) as total FROM projects WHERE user_id=%s", (user_id,))
    total_projects = cursor.fetchone()['total']

    # عدد المشاريع المكتملة (pipeline ran)
    cursor.execute("SELECT COUNT(*) as done FROM projects WHERE user_id=%s AND status='completed'", (user_id,))
    completed = cursor.fetchone()['done']

    # متوسط الـ accuracy من pipeline_results
    cursor.execute("""
        SELECT AVG(pr.model_accuracy) as avg_acc
        FROM pipeline_results pr
        JOIN projects p ON p.id = pr.project_id
        WHERE p.user_id = %s AND pr.model_accuracy IS NOT NULL
    """, (user_id,))
    row = cursor.fetchone()
    avg_accuracy = round((row['avg_acc'] or 0) * 100, 1)

    # توزيع القطاعات
    cursor.execute("""
        SELECT COALESCE(sector,'Other') as sector, COUNT(*) as cnt
        FROM projects WHERE user_id=%s
        GROUP BY sector ORDER BY cnt DESC
    """, (user_id,))
    sector_dist = cursor.fetchall()

    # أحدث 6 مشاريع
    cursor.execute("""
        SELECT p.id, p.name, p.sector, p.analysis_type, p.status, p.created_at,
               pr.model_accuracy, pr.model_r2
        FROM projects p
        LEFT JOIN pipeline_results pr ON pr.project_id = p.id
        WHERE p.user_id = %s
        ORDER BY p.created_at DESC LIMIT 6
    """, (user_id,))
    recent_projects = cursor.fetchall()

    cursor.close()
    conn.close()

    return {
        'total_projects': total_projects,
        'completed_models': completed,
        'avg_accuracy': avg_accuracy,
        'sector_dist': sector_dist,
        'recent_projects': recent_projects,
    }
