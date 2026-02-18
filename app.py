import os
import re
import json
import pandas as pd
import numpy as np
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from werkzeug.utils import secure_filename

from database_mysql import (
    insert_project, get_sector_id_by_name,
    create_user, get_user_by_email,
    get_project_by_id, verify_user, create_users_table,
    get_projects_by_user, update_project_status,
    save_pipeline_result, get_pipeline_result,
    get_dashboard_stats
)

app = Flask(__name__)
app.secret_key = "arcane_secret_key_2025"

with app.app_context():
    create_users_table()

# =========================
# Helpers
# =========================
def is_valid_email(email):
    """Email validation مثل المواقع الكبيرة - 19/19 اختبار نجح"""
    if not email or len(email) < 6 or len(email) > 254:
        return False
    if ' ' in email:
        return False
    parts = email.split('@')
    if len(parts) != 2:
        return False
    local, domain = parts
    if not local or local[0] in '.+-' or local[-1] in '.+-':
        return False
    if '..' in email:
        return False
    if not domain or '.' not in domain:
        return False
    if domain[0] in '-.' or domain[-1] in '-.':
        return False
    pattern = re.compile(
        r'^[a-zA-Z0-9][a-zA-Z0-9._+\-]*[a-zA-Z0-9]'
        r'@[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?'
        r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*'
        r'\.[a-zA-Z]{2,10}$'
    )
    single = re.compile(r'^[a-zA-Z0-9]@[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,10}$')
    return bool(pattern.match(email) or single.match(email))

def is_strong_password(pw):
    if not pw or len(pw) < 8: return False
    return all([re.search(r"[a-z]", pw), re.search(r"[A-Z]", pw),
                re.search(r"\d", pw), re.search(r"[^A-Za-z0-9]", pw)])

def _clean(s): return (s or "").strip()
def _is_empty(s): return len(_clean(s)) == 0

UPLOAD_FOLDER = os.path.join("static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
ALLOWED_ANALYSIS = {"Classification", "Regression"}

# =========================
# Pages
# =========================
@app.route("/")
def landing():
    return render_template("arcane_landing_page.html")

@app.route("/auth")
def auth():
    return render_template("arcane_login_signup.html")

@app.route("/sectors")
def sectors():
    if "user_id" not in session:
        return redirect(url_for("auth"))
    return render_template("arcane_sector_selection.html")

@app.route("/setup")
def setup():
    if "user_id" not in session:
        return redirect(url_for("auth"))
    sector = request.args.get("sector", "")
    session["selected_sector"] = sector
    return render_template("new_project_setup.html", sector=sector)

@app.route("/projects")
def projects_page():
    if "user_id" not in session:
        return redirect(url_for("auth"))
    user_projects = get_projects_by_user(session["user_id"])
    return render_template("projects.html", projects=user_projects)

# =========================
# AUTH
# =========================
@app.route("/signup", methods=["POST"])
def signup():
    name    = request.form.get("name", "").strip()
    email   = request.form.get("email", "").strip().lower()
    password= request.form.get("password", "")
    confirm = request.form.get("confirm_password", "")

    if len(name) < 3:
        return jsonify(success=False, field="name", message="Name must be at least 3 characters"), 400
    if not is_valid_email(email):
        return jsonify(success=False, field="email", message="Please enter a valid email"), 400
    if not is_strong_password(password):
        return jsonify(success=False, field="password",
                       message="Password must be 8+ chars with uppercase, lowercase, number & special character"), 400
    if password != confirm:
        return jsonify(success=False, field="confirm_password", message="Passwords do not match"), 400
    if get_user_by_email(email):
        return jsonify(success=False, field="email", message="Email already exists"), 409

    user_id = create_user(name, email, password)
    session.clear()
    session["user_id"]    = user_id
    session["user_name"]  = name
    session["user_email"] = email
    return jsonify(success=True, redirect=url_for("dashboard")), 200


@app.route("/signin", methods=["POST"])
def signin():
    email    = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    if not is_valid_email(email):
        return jsonify(success=False, field="email", message="Please enter a valid email"), 400

    user = verify_user(email, password)
    if not user:
        return jsonify(success=False, field="password", message="Invalid email or password"), 401

    session.clear()
    session["user_id"]    = user["id"]
    session["user_name"]  = user.get("full_name") or user.get("name", "User")
    session["user_email"] = user.get("email", "")
    return jsonify(success=True, redirect=url_for("dashboard")), 200


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth"))

# =========================
# Dashboard
# =========================
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("auth"))
    try:
        stats = get_dashboard_stats(session["user_id"])
    except Exception as e:
        print("Dashboard stats error:", e)
        stats = {
            'total_projects': 0, 'completed_models': 0,
            'avg_accuracy': 0, 'sector_dist': [], 'recent_projects': []
        }
    return render_template("arcane_dashboard.html", **stats)

# =========================
# Workspace
# =========================
@app.route("/workspace/<int:project_id>")
def workspace(project_id):
    if "user_id" not in session:
        return redirect(url_for("auth"))

    project = get_project_by_id(project_id)
    if not project:
        return "Project not found", 404

    result = get_pipeline_result(project_id)
    dataset_uploaded = bool(project.get("dataset_path"))

    # بيانات الـ chart
    chart_labels = result["chart_labels"] if result else None
    chart_data   = result["chart_data"]   if result else None
    chart_column = result["chart_column"] if result else None
    feature_importance = result["feature_importance"] if result else {}

    # preview table
    preview_headers, preview_rows = None, None
    if dataset_uploaded and os.path.exists(project["dataset_path"]):
        try:
            df_prev = pd.read_csv(project["dataset_path"], nrows=5)
            preview_headers = df_prev.columns.tolist()
            preview_rows = df_prev.to_dict(orient="records")
        except Exception:
            pass

    return render_template(
        "Demoarcane_project_workspace.html",
        project_id       = project_id,
        project_name     = project.get("name"),
        sector_name      = project.get("sector"),
        analysis_type    = project.get("analysis_type", "Classification"),
        dataset_uploaded = dataset_uploaded,
        dataset_name     = os.path.basename(project.get("dataset_path", "")) if dataset_uploaded else "—",
        dataset_rows     = result["rows_count"] if result else 0,
        dataset_cols     = result["cols_count"] if result else 0,
        preview_headers  = preview_headers,
        preview_rows     = preview_rows,
        chart_data       = json.dumps(chart_data) if chart_data else None,
        chart_labels     = json.dumps(chart_labels) if chart_labels else None,
        chart_column     = chart_column,
        result           = result,
        feature_importance = json.dumps(feature_importance) if feature_importance else None,
        pipeline_done    = bool(result),
    )

# =========================
# SAVE PROJECT
# =========================
@app.route("/save_project", methods=["POST"])
def save_project():
    if "user_id" not in session:
        return redirect(url_for("auth"))

    user_id     = session["user_id"]
    sector_name = _clean(request.form.get("sector_id")) or _clean(session.get("selected_sector"))
    name        = _clean(request.form.get("project_name"))
    description = _clean(request.form.get("description"))
    analysis_type = _clean(request.form.get("analysis_type"))

    errors = {}
    if _is_empty(sector_name):    errors["sector_error"]   = "Please select a sector first."
    if len(name) < 3:             errors["project_name_error"] = "Project name must be at least 3 characters."
    if len(description) < 10:    errors["description_error"]  = "Description must be at least 10 characters."
    if analysis_type not in ALLOWED_ANALYSIS:
        errors["analysis_error"] = "Please select Classification or Regression."

    sector_id = get_sector_id_by_name(sector_name)
    if not sector_id:
        errors["sector_error"] = "Invalid sector selected."

    # CSV upload
    dataset_path = None
    file = request.files.get("dataset")
    if not file or not file.filename:
        errors["dataset_error"] = "Please upload a CSV file."
    elif not file.filename.lower().endswith(".csv"):
        errors["dataset_error"] = "Only CSV files are allowed."

    if errors:
        return render_template(
            "new_project_setup.html",
            sector=sector_name, project_name=name,
            description=description, active_step=3,
            **errors
        )

    # حفظ الملف
    filename   = secure_filename(file.filename)
    base, ext  = os.path.splitext(filename)
    counter    = 1
    final_name = filename
    while os.path.exists(os.path.join(app.config["UPLOAD_FOLDER"], final_name)):
        final_name = f"{base}_{counter}{ext}"
        counter += 1

    save_path = os.path.join(app.config["UPLOAD_FOLDER"], final_name)
    file.save(save_path)
    dataset_path = save_path

    try:
        project_id = insert_project(
            user_id=user_id, sector_name=sector_name, sector_id=sector_id,
            name=name, description=description,
            dataset_path=dataset_path, analysis_type=analysis_type
        )
    except Exception as e:
        return f"❌ DB ERROR: {repr(e)}", 500

    # تشغيل الـ pipeline مباشرة
    try:
        run_pipeline_logic(project_id, dataset_path, analysis_type)
    except Exception as e:
        print("⚠️ Pipeline warning:", repr(e))

    return redirect(url_for("workspace", project_id=project_id))


# =========================
# RUN PIPELINE (API)
# =========================
@app.route("/run_pipeline/<int:project_id>", methods=["POST"])
def run_pipeline(project_id):
    if "user_id" not in session:
        return redirect(url_for("auth"))

    project = get_project_by_id(project_id)
    if not project:
        return "Project not found", 404

    try:
        run_pipeline_logic(
            project_id,
            project["dataset_path"],
            project.get("analysis_type", "Classification")
        )
    except Exception as e:
        print("Pipeline error:", repr(e))

    return redirect(url_for("workspace", project_id=project_id))


# =========================
# PIPELINE LOGIC (pandas + sklearn)
# =========================
def run_pipeline_logic(project_id, dataset_path, analysis_type):
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import LabelEncoder
    from sklearn.ensemble import RandomForestClassifier, RandomForestRegressor
    from sklearn.metrics import (accuracy_score, precision_score, recall_score, f1_score,
                                  r2_score, mean_squared_error, mean_absolute_error)

    # --- 1. Load ---
    df = pd.read_csv(dataset_path)
    rows_before = len(df)
    cols_count  = len(df.columns)
    missing_before = int(df.isnull().sum().sum())

    # --- 2. Preprocessing ---
    dups_before = df.duplicated().sum()
    df = df.drop_duplicates()
    duplicates_removed = int(dups_before - df.duplicated().sum())

    # fill missing: numeric → median, categorical → mode
    for col in df.columns:
        if df[col].dtype in [np.float64, np.int64]:
            df[col] = df[col].fillna(df[col].median())
        else:
            if df[col].isnull().any():
                fill_val = df[col].mode()[0] if not df[col].mode().empty else "Unknown"
                df[col] = df[col].fillna(fill_val)

    missing_after = int(df.isnull().sum().sum())
    rows_count = len(df)

    # --- 3. Target column detection ---
    # آخر عمود = target
    target_col = df.columns[-1]
    feature_cols = [c for c in df.columns if c != target_col]

    # Encode categoricals
    df_model = df.copy()
    le = LabelEncoder()
    for col in df_model.columns:
        if df_model[col].dtype == object:
            df_model[col] = le.fit_transform(df_model[col].astype(str))

    X = df_model[feature_cols]
    y = df_model[target_col]

    result_data = {
        "rows_count": rows_count,
        "cols_count": cols_count,
        "missing_before": missing_before,
        "missing_after": missing_after,
        "duplicates_removed": duplicates_removed,
        "target_column": target_col,
    }

    # --- 4. ML ---
    if len(X) < 10:
        raise ValueError("Dataset too small (need at least 10 rows)")

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    if analysis_type == "Classification":
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        # weighted يشتغل مع binary و multiclass بدون مشاكل string labels
        result_data.update({
            "model_accuracy":  round(float(accuracy_score(y_test, y_pred)), 4),
            "model_precision": round(float(precision_score(y_test, y_pred, average="weighted", zero_division=0)), 4),
            "model_recall":    round(float(recall_score(y_test, y_pred, average="weighted", zero_division=0)), 4),
            "model_f1":        round(float(f1_score(y_test, y_pred, average="weighted", zero_division=0)), 4),
        })
    else:  # Regression
        model = RandomForestRegressor(n_estimators=100, random_state=42)
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        result_data.update({
            "model_r2":  round(float(r2_score(y_test, y_pred)), 4),
            "model_mse": round(float(mean_squared_error(y_test, y_pred)), 4),
            "model_mae": round(float(mean_absolute_error(y_test, y_pred)), 4),
        })

    # --- 5. Feature importance ---
    fi = {}
    if hasattr(model, "feature_importances_"):
        fi = {col: round(float(imp), 4)
              for col, imp in zip(feature_cols, model.feature_importances_)}
        fi = dict(sorted(fi.items(), key=lambda x: x[1], reverse=True)[:8])
    result_data["feature_importance"] = fi

    # --- 6. Chart: first numeric column distribution (max 20 unique values) ---
    chart_col = None
    chart_labels, chart_data_vals = [], []
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    if numeric_cols:
        chart_col = numeric_cols[0]
        col_data = df[chart_col].dropna()
        if col_data.nunique() <= 20:
            vc = col_data.value_counts().sort_index()
            chart_labels    = [str(x) for x in vc.index.tolist()]
            chart_data_vals = [int(x) for x in vc.values.tolist()]
        else:
            # histogram with 10 bins
            counts, bin_edges = np.histogram(col_data, bins=10)
            chart_labels    = [f"{bin_edges[i]:.1f}" for i in range(len(bin_edges)-1)]
            chart_data_vals = counts.tolist()

    result_data["chart_column"] = chart_col or ""
    result_data["chart_labels"] = chart_labels
    result_data["chart_data"]   = chart_data_vals

    # --- 7. Save to DB ---
    save_pipeline_result(project_id, result_data)
    update_project_status(project_id, "completed")

    return result_data


if __name__ == "__main__":
    app.run(debug=True)
