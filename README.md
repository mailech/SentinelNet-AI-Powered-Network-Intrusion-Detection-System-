# SentinelNet NIDS – Setup & Deployment Guide

## 📁 Project Structure
```
SentinelNet-NIDS/
├── app.py                    ← Flask backend (updated)
├── requirements.txt          ← Python dependencies
├── Procfile                  ← For Render/Railway deploy
├── ml_model/
│   ├── model.pkl
│   ├── scaler.pkl
│   └── feature_names.json
├── data/
│   └── processed/
│       └── NSL_KDD_Test_Clean.csv
├── templates/
│   └── index.html            ← Updated HTML
└── static/
    ├── css/
    │   └── style.css         ← Updated CSS
    └── js/
        └── app.js            ← Updated JS (CSV Analyzer)
```

---

## ✅ File Placement Guide

| Downloaded File | Where to put it |
|---|---|
| `index.html` | `templates/index.html` |
| `style.css`  | `static/css/style.css` |
| `app.js`     | `static/js/app.js` |
| `app.py`     | Root of project |
| `requirements.txt` | Root of project |
| `Procfile`   | Root of project |

---

## 🚀 Run Locally

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the app
python app.py

# 3. Open browser
http://localhost:5000
```

---

## 📂 CSV Analyzer Feature

Upload any CSV file with network traffic data. Supported column names:
- `duration`, `protocol_type`, `src_bytes`, `dst_bytes`
- `count`, `srv_count`, `logged_in`, `same_srv_rate`
- `src_ip`, `dst_ip`, `port` (optional, auto-generated if missing)

After upload you will see:
- ✅ Total packets analysed
- 🚨 Attacks vs Normal count
- 📊 5 charts: Attack types, Split, Severity, Protocol, Confidence
- 📋 Full results table with filter + export

---

## ☁️ Deploy on Render (FREE)

1. Push project to GitHub

2. Go to https://render.com → New → Web Service

3. Connect your GitHub repo

4. Settings:
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn app:app --bind 0.0.0.0:$PORT`
   - **Environment:** Python 3

5. Click **Deploy** — URL will be like `https://sentinelnet.onrender.com`

6. After deploy, open `static/js/app.js` and change:
   ```js
   const API = 'https://your-app-name.onrender.com';
   ```

---

## ☁️ Deploy on Railway (FREE)

1. Go to https://railway.app → New Project → Deploy from GitHub

2. Select your repo — Railway auto-detects Python

3. Add environment variable: `PORT = 5000`

4. Deploy! URL will be shown in dashboard

---

## ☁️ Deploy on Vercel (Frontend Only)

If you want to deploy only the frontend (demo mode without Flask):

1. Put `index.html`, `style.css`, `app.js` in a folder
2. Go to https://vercel.com → Import → drag folder
3. Done! Works fully in demo/offline mode with CSV analyzer

---

## ⚠️ Notes

- **Without ML model:** App runs in heuristic mode (still works, just less accurate)
- **With ML model:** Put `model.pkl`, `scaler.pkl`, `feature_names.json` in `ml_model/` folder
- **CSV Upload:** Works 100% offline without backend — uses local JS heuristic
- **Large CSV files:** Tested up to 50,000 rows — processed in chunks, shows progress
