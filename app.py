import os
import re
import json
import smtplib
import secrets
import pandas as pd
import numpy as np
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
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
# Email Config (update with real credentials)
# =========================
# =========================
# EMAIL SETUP - REQUIRED STEPS:
# 1. Go to myaccount.google.com -> Security -> 2-Step Verification -> Turn ON
# 2. Then go to: myaccount.google.com/apppasswords
# 3. Create App Password -> choose "Mail" -> copy the 16-char password
# 4. Paste the 16-char password in SMTP_PASS below (spaces are OK)
# =========================
SMTP_HOST    = "smtp.gmail.com"
SMTP_PORT    = 587
SMTP_USER    = "arcane.analytics.platform@gmail.com"  # Your Gmail address
SMTP_PASS    = "abcd efgh ijkl mnop"                  # 16-char Gmail App Password
FRONTEND_URL = "http://127.0.0.1:5000"

# In-memory store for reset tokens  {token: email}
reset_tokens = {}

# =========================
# Sector validation rules
# =========================
SECTOR_RULES = {
    "Commerce": {
        "description": "Sales, inventory, customer behaviour, financial forecasting",
        "required_types": ["numeric"],
        "min_cols": 3,
        "min_rows": 10,
        "recommended_keywords": ["sales","revenue","price","quantity","customer","product","order","profit","cost","inventory","stock"],
        "forbidden_keywords": ["patient","diagnosis","glucose","blood","disease","symptom","grade","score","student","gpa"],
    },
    "Healthcare": {
        "description": "Patient data, diagnosis, lab results, medical records",
        "required_types": ["numeric"],
        "min_cols": 3,
        "min_rows": 10,
        "recommended_keywords": ["patient","age","bmi","glucose","blood","pressure","diagnosis","disease","symptom","outcome","insulin","cancer","heart"],
        "forbidden_keywords": ["sales","revenue","profit","inventory","product","price","student","grade","gpa","election","votes"],
    },
    "Education": {
        "description": "Student performance, attendance, grades, engagement",
        "required_types": ["numeric"],
        "min_cols": 3,
        "min_rows": 10,
        "recommended_keywords": ["student","grade","score","attendance","gpa","course","exam","pass","fail","performance","class","subject","teacher"],
        "forbidden_keywords": ["patient","diagnosis","glucose","revenue","sales","profit","votes","election"],
    },
    "Government": {
        "description": "Public services, citizen satisfaction, policy, infrastructure",
        "required_types": ["numeric"],
        "min_cols": 3,
        "min_rows": 10,
        "recommended_keywords": ["satisfaction","service","citizen","public","government","policy","infrastructure","rating","survey","feedback","region","department"],
        "forbidden_keywords": ["patient","diagnosis","glucose","revenue","sales","student","grade"],
    },
}

def validate_dataset_for_sector(df, sector_name):
    """Validate CSV columns against sector expectations. Returns (ok, warnings, errors)"""
    rules = SECTOR_RULES.get(sector_name, {})
    if not rules:
        return True, [], []

    errors   = []
    warnings = []
    cols_lower = [c.lower() for c in df.columns]
    cols_str   = " ".join(cols_lower)

    # Min rows / cols
    if len(df) < rules["min_rows"]:
        errors.append(f"Dataset has only {len(df)} rows. Minimum required: {rules['min_rows']}.")
    if len(df.columns) < rules["min_cols"]:
        errors.append(f"Dataset has only {len(df.columns)} columns. Minimum required: {rules['min_cols']}.")

    # Must have at least one numeric column
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    if len(numeric_cols) == 0:
        errors.append("Dataset must have at least one numeric column for analysis.")

    # Check forbidden keywords (strong sector mismatch signal)
    forbidden_found = [kw for kw in rules.get("forbidden_keywords",[]) if kw in cols_str]
    if len(forbidden_found) >= 2:
        errors.append(
            f"This dataset does not appear to match the '{sector_name}' sector. "
            f"Columns suggest a different domain (found: {', '.join(forbidden_found[:3])}). "
            f"Expected: {rules['description']}."
        )

    # Check recommended keywords (soft warning if none match)
    recommended_found = [kw for kw in rules.get("recommended_keywords",[]) if kw in cols_str]
    if len(recommended_found) == 0 and len(forbidden_found) == 0:
        warnings.append(
            f"None of the expected column names for '{sector_name}' were detected. "
            f"Make sure your data is relevant to: {rules['description']}."
        )

    return (len(errors) == 0), warnings, errors

# =========================
# Helpers
# =========================
def is_valid_email(email):
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
    tld = domain.split('.')[-1]
    if not re.match(r'^[a-zA-Z]{2,10}$', tld):
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
ALLOWED_ANALYSIS = {"Classification", "Regression", "Forecasting", "Clustering"}

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
    name     = request.form.get("name", "").strip()
    email    = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    confirm  = request.form.get("confirm_password", "")

    if len(name) < 3:
        return jsonify(success=False, field="name", message="Name must be at least 3 characters"), 400
    if not is_valid_email(email):
        return jsonify(success=False, field="email", message="Please enter a valid email address"), 400
    if not is_strong_password(password):
        return jsonify(success=False, field="password",
                       message="Password must be 8+ chars with uppercase, lowercase, number & special character"), 400
    if password != confirm:
        return jsonify(success=False, field="confirm_password", message="Passwords do not match"), 400
    if get_user_by_email(email):
        return jsonify(success=False, field="email", message="This email is already registered"), 409

    create_user(name, email, password)
    return jsonify(
        success=True, registered=True,
        message=f"🎉 Account created! Welcome, {name}. Please sign in to continue.",
        redirect=url_for("auth") + "?mode=signin&registered=1"), 200


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
# FORGOT PASSWORD
# =========================
@app.route("/forgot_password", methods=["POST"])
def forgot_password():
    email = request.form.get("email", "").strip().lower()

    if not is_valid_email(email):
        return jsonify(success=False, message="Please enter a valid email address"), 400

    user = get_user_by_email(email)
    # Always return success to prevent email enumeration
    if not user:
        return jsonify(
            success=True,
            message=f"If an account with {email} exists, a reset link has been sent."
        ), 200

    # Generate secure token
    token = secrets.token_urlsafe(32)
    reset_tokens[token] = email

    reset_link = f"{FRONTEND_URL}/reset_password/{token}"

    # Send email
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "ARCANE — Password Reset Request"
        msg["From"]    = f"ARCANE Platform <{SMTP_USER}>"
        msg["To"]      = email

        user_name = user.get("full_name") or user.get("name", "User")

        html_body = f"""
        <html><body style="font-family:Arial,sans-serif;background:#f5f7fa;padding:20px;">
        <div style="max-width:500px;margin:0 auto;background:white;border-radius:16px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,0.1);">
            <div style="background:linear-gradient(135deg,#667eea,#764ba2);padding:30px;text-align:center;">
                <h1 style="color:white;margin:0;font-size:24px;">🔐 ARCANE</h1>
                <p style="color:rgba(255,255,255,0.85);margin:8px 0 0;">AI-Powered Analytics Platform</p>
            </div>
            <div style="padding:30px;">
                <h2 style="color:#1e293b;">Hello, {user_name}!</h2>
                <p style="color:#64748b;line-height:1.6;">
                    We received a request to reset your ARCANE account password.<br>
                    Click the button below to set a new password:
                </p>
                <div style="text-align:center;margin:30px 0;">
                    <a href="{reset_link}" style="
                        background:linear-gradient(135deg,#667eea,#764ba2);
                        color:white;padding:14px 32px;border-radius:10px;
                        text-decoration:none;font-weight:600;font-size:16px;
                        display:inline-block;">
                        Reset My Password
                    </a>
                </div>
                <p style="color:#94a3b8;font-size:13px;">
                    This link expires in 1 hour. If you didn't request this, please ignore this email.
                </p>
                <hr style="border:none;border-top:1px solid #e2e8f0;margin:20px 0;">
                <p style="color:#94a3b8;font-size:12px;text-align:center;">
                    © 2025 ARCANE Platform — University of Tabuk
                </p>
            </div>
        </div>
        </body></html>
        """
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, email, msg.as_string())

        return jsonify(
            success=True,
            message=f"Password reset link sent to {email}. Please check your inbox and spam folder."
        ), 200

    except smtplib.SMTPAuthenticationError:
        print("Email error: SMTPAuthenticationError — check SMTP_USER and SMTP_PASS in app.py")
        return jsonify(
            success=False,
            message="Email service is not configured yet. Please contact the administrator or set up Gmail App Password in app.py."
        ), 500

    except Exception as e:
        print(f"Email send error: {repr(e)}")
        return jsonify(
            success=False,
            message=f"Failed to send email: {str(e)[:100]}. Please try again later."
        ), 500


@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    email = reset_tokens.get(token)
    if not email:
        return "<h2>⚠️ Invalid or expired reset link.</h2><a href='/auth'>Go to Login</a>", 400

    if request.method == "POST":
        new_pw = request.form.get("password", "")
        confirm_pw = request.form.get("confirm_password", "")
        if not is_strong_password(new_pw):
            return render_template("reset_password.html", token=token,
                error="Password must be 8+ chars with uppercase, lowercase, number & special character")
        if new_pw != confirm_pw:
            return render_template("reset_password.html", token=token, error="Passwords do not match")
        # TODO: update password in DB
        del reset_tokens[token]
        return redirect(url_for("auth") + "?mode=signin&reset=1")

    return render_template("reset_password.html", token=token)


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
        stats = {'total_projects':0,'completed_models':0,'avg_accuracy':0,'sector_dist':[],'recent_projects':[]}
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
    chart_labels = result["chart_labels"] if result else None
    chart_data   = result["chart_data"]   if result else None
    chart_column = result["chart_column"] if result else None
    feature_importance = result["feature_importance"] if result else {}

    preview_headers, preview_rows = None, None
    if dataset_uploaded and os.path.exists(project["dataset_path"]):
        try:
            df_prev = pd.read_csv(project["dataset_path"], nrows=5)
            preview_headers = df_prev.columns.tolist()
            preview_rows = df_prev.to_dict(orient="records")
        except Exception:
            pass

    user_name  = session.get("user_name", "User")
    user_email = session.get("user_email", "")
    user_initial = user_name[0].upper() if user_name else "U"

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
        user_name        = user_name,
        user_email       = user_email,
        user_initial     = user_initial,
        sector_warnings  = result.get("sector_warnings", []) if result else [],
    )


# =========================
# SAVE PROJECT
# =========================
@app.route("/save_project", methods=["POST"])
def save_project():
    if "user_id" not in session:
        return redirect(url_for("auth"))

    user_id       = session["user_id"]
    sector_name   = _clean(request.form.get("sector_id")) or _clean(session.get("selected_sector"))
    name          = _clean(request.form.get("project_name"))
    description   = _clean(request.form.get("description"))
    analysis_type = _clean(request.form.get("analysis_type"))

    errors = {}
    if _is_empty(sector_name):    errors["sector_error"]        = "Please select a sector first."
    if len(name) < 3:             errors["project_name_error"]  = "Project name must be at least 3 characters."
    if len(description) < 10:     errors["description_error"]   = "Description must be at least 10 characters."
    if analysis_type not in ALLOWED_ANALYSIS:
        errors["analysis_error"] = "Please select a valid analysis type."

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
            description=description, active_step=3, **errors
        )

    # Save file
    filename   = secure_filename(file.filename)
    base, ext  = os.path.splitext(filename)
    counter    = 1
    final_name = filename
    while os.path.exists(os.path.join(app.config["UPLOAD_FOLDER"], final_name)):
        final_name = f"{base}_{counter}{ext}"
        counter += 1

    save_path = os.path.join(app.config["UPLOAD_FOLDER"], final_name)
    file.save(save_path)

    # --- Sector validation BEFORE creating project ---
    try:
        df_check = pd.read_csv(save_path)
        sector_ok, sector_warnings, sector_errors = validate_dataset_for_sector(df_check, sector_name)
        if not sector_ok:
            os.remove(save_path)  # Clean up uploaded file
            return render_template(
                "new_project_setup.html",
                sector=sector_name, project_name=name,
                description=description, active_step=3,
                dataset_error=" | ".join(sector_errors)
            )
    except Exception as e:
        sector_warnings = []
        print("Sector validation error:", e)

    dataset_path = save_path

    try:
        project_id = insert_project(
            user_id=user_id, sector_name=sector_name, sector_id=sector_id,
            name=name, description=description,
            dataset_path=dataset_path, analysis_type=analysis_type
        )
    except Exception as e:
        return f"❌ DB ERROR: {repr(e)}", 500

    # Run pipeline
    try:
        run_pipeline_logic(project_id, dataset_path, analysis_type, sector_name, sector_warnings)
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
            project.get("analysis_type", "Classification"),
            project.get("sector", ""),
            []
        )
    except Exception as e:
        print("Pipeline error:", repr(e))

    return redirect(url_for("workspace", project_id=project_id))


# =========================
# PIPELINE LOGIC
# =========================
def run_pipeline_logic(project_id, dataset_path, analysis_type, sector_name="", sector_warnings=None):
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import LabelEncoder
    from sklearn.ensemble import RandomForestClassifier, RandomForestRegressor
    from sklearn.cluster import KMeans
    from sklearn.metrics import (accuracy_score, precision_score, recall_score, f1_score,
                                  r2_score, mean_squared_error, mean_absolute_error,
                                  silhouette_score, davies_bouldin_score)

    if sector_warnings is None:
        sector_warnings = []

    # --- 1. Load ---
    df = pd.read_csv(dataset_path)
    rows_before   = len(df)
    cols_count    = len(df.columns)
    missing_before = int(df.isnull().sum().sum())

    # --- 2. Preprocessing ---
    dups_before = df.duplicated().sum()
    df = df.drop_duplicates()
    duplicates_removed = int(dups_before - df.duplicated().sum())

    for col in df.columns:
        if df[col].dtype in [np.float64, np.int64]:
            df[col] = df[col].fillna(df[col].median())
        else:
            if df[col].isnull().any():
                fill_val = df[col].mode()[0] if not df[col].mode().empty else "Unknown"
                df[col] = df[col].fillna(fill_val)

    missing_after = int(df.isnull().sum().sum())
    rows_count    = len(df)

    # --- 3. Target column ---
    target_col   = df.columns[-1]
    feature_cols = [c for c in df.columns if c != target_col]

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
        "analysis_type": analysis_type,
        "sector_warnings": sector_warnings,
    }

    if len(X) < 10:
        raise ValueError("Dataset too small (need at least 10 rows)")

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # ==================== Classification ====================
    if analysis_type == "Classification":
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        result_data.update({
            "model_accuracy":  round(float(accuracy_score(y_test, y_pred)), 4),
            "model_precision": round(float(precision_score(y_test, y_pred, average="weighted", zero_division=0)), 4),
            "model_recall":    round(float(recall_score(y_test, y_pred, average="weighted", zero_division=0)), 4),
            "model_f1":        round(float(f1_score(y_test, y_pred, average="weighted", zero_division=0)), 4),
        })

    # ==================== Regression ====================
    elif analysis_type == "Regression":
        model = RandomForestRegressor(n_estimators=100, random_state=42)
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        result_data.update({
            "model_r2":  round(float(r2_score(y_test, y_pred)), 4),
            "model_mse": round(float(mean_squared_error(y_test, y_pred)), 4),
            "model_mae": round(float(mean_absolute_error(y_test, y_pred)), 4),
        })

    # ==================== Clustering ====================
    elif analysis_type == "Clustering":
        # Determine optimal k (2–8)
        best_k, best_score = 2, -999
        max_k = min(8, len(X) - 1)
        for k in range(2, max_k + 1):
            km = KMeans(n_clusters=k, random_state=42, n_init=10)
            labels = km.fit_predict(X)
            if len(set(labels)) > 1:
                sc = silhouette_score(X, labels)
                if sc > best_score:
                    best_score = sc
                    best_k = k

        model = KMeans(n_clusters=best_k, random_state=42, n_init=10)
        cluster_labels = model.fit_predict(X)
        db_score = davies_bouldin_score(X, cluster_labels)
        result_data.update({
            "model_clusters": best_k,
            "model_silhouette": round(float(best_score), 4),
            "model_davies_bouldin": round(float(db_score), 4),
        })
        # No feature_importances_ for KMeans
        fi = {}
        result_data["feature_importance"] = fi

    # ==================== Forecasting ====================
    elif analysis_type == "Forecasting":
        # Use regression on time-indexed or ordered data
        numeric_df = df_model.select_dtypes(include=[np.number])
        if numeric_df.shape[1] < 2:
            raise ValueError("Forecasting requires at least 2 numeric columns")

        model = RandomForestRegressor(n_estimators=100, random_state=42)
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)

        # Forecasting-specific metrics
        result_data.update({
            "model_r2":  round(float(r2_score(y_test, y_pred)), 4),
            "model_mse": round(float(mean_squared_error(y_test, y_pred)), 4),
            "model_mae": round(float(mean_absolute_error(y_test, y_pred)), 4),
            "forecast_points": len(y_pred),
            "forecast_mean":   round(float(np.mean(y_pred)), 4),
            "forecast_std":    round(float(np.std(y_pred)), 4),
        })

    # Feature importance (for tree-based models)
    fi = result_data.get("feature_importance", None)
    if fi is None:
        fi = {}
        if hasattr(model, "feature_importances_"):
            fi = {col: round(float(imp), 4)
                  for col, imp in zip(feature_cols, model.feature_importances_)}
            fi = dict(sorted(fi.items(), key=lambda x: x[1], reverse=True)[:8])
    result_data["feature_importance"] = fi

    # --- Chart distribution ---
    chart_col = None
    chart_labels_list, chart_data_vals = [], []
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    if numeric_cols:
        chart_col = numeric_cols[0]
        col_data = df[chart_col].dropna()
        if col_data.nunique() <= 20:
            vc = col_data.value_counts().sort_index()
            chart_labels_list = [str(x) for x in vc.index.tolist()]
            chart_data_vals   = [int(x) for x in vc.values.tolist()]
        else:
            counts, bin_edges = np.histogram(col_data, bins=10)
            chart_labels_list = [f"{bin_edges[i]:.1f}" for i in range(len(bin_edges)-1)]
            chart_data_vals   = counts.tolist()

    result_data["chart_column"] = chart_col or ""
    result_data["chart_labels"] = chart_labels_list
    result_data["chart_data"]   = chart_data_vals

    save_pipeline_result(project_id, result_data)
    update_project_status(project_id, "completed")
    return result_data


if __name__ == "__main__":
    app.run(debug=True)
