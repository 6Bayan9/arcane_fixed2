# ARCANE - Analytics Real-time Cross-sector AI Network Engine
**University of Tabuk | Bachelor Project 2025**

## 🚀 Quick Setup (3 steps)

### 1. Install Python packages
```bash
pip install -r requirements.txt
```

### 2. Setup MySQL Database
- Open **phpMyAdmin** (via XAMPP) or MySQL Workbench
- Create database: `arcane_db`
- Import the file: `arcane_db.sql`

### 3. Run the app
```bash
python app.py
```
Open browser: `http://127.0.0.1:5000`

---

## 📋 User Flow
1. **Landing Page** → Sign Up / Login
2. **Dashboard** → New Project
3. **Select Sector** → Commerce / Healthcare / Education / Government
4. **Project Setup** → Name + Description + CSV Upload + Analysis Type
5. **Workspace** → View EDA + Run Pipeline → See Results

## 🤖 AI Analysis Types
| Type | Status | Algorithm |
|------|--------|-----------|
| Classification | ✅ Available | Random Forest |
| Regression | ✅ Available | Random Forest |
| Forecasting | 🔒 Soon | — |
| Clustering | 🔒 Soon | — |

## 📁 Project Structure
```
arcane_project/
├── app.py              ← Flask backend (routes + pipeline)
├── database_mysql.py   ← All DB functions
├── arcane_db.sql       ← Database schema (import this first)
├── requirements.txt    ← Python packages
├── static/
│   └── uploads/        ← CSV files saved here
└── templates/
    ├── arcane_landing_page.html
    ├── arcane_login_signup.html
    ├── arcane_dashboard.html
    ├── arcane_sector_selection.html
    ├── new_project_setup.html
    ├── Demoarcane_project_workspace.html
    └── projects.html
```

## 🔧 Database Config
Edit `database_mysql.py` → `get_connection()`:
```python
host     = "127.0.0.1"
user     = "root"
password = ""          # ← change if your MySQL has a password
database = "arcane_db"
```
