# 🚀 Deployment Guide — Secure Document Vault v2

## Option 1: Render.com (Recommended — Free & Easy)

### Step 1 — Push to GitHub
1. Create a free account at https://github.com
2. Create a new repository (e.g., `secure-document-vault`)
3. Open terminal in this project folder and run:
```bash
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/secure-document-vault.git
git push -u origin main
```

### Step 2 — Deploy on Render
1. Go to https://render.com and sign up (free)
2. Click **"New +"** → **"Web Service"**
3. Connect your GitHub account and select your repo
4. Fill in the settings:
   - **Name:** secure-document-vault
   - **Runtime:** Python 3
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn run:app --bind 0.0.0.0:$PORT --workers 2 --timeout 120`
5. Under **Environment Variables**, add:
   - `SECRET_KEY` → Click "Generate" for a random value
   - `FLASK_ENV` → `production`
   - `SESSION_COOKIE_SECURE` → `True`
6. Click **"Create Web Service"**
7. Wait ~3 minutes — your app will be live at:
   `https://secure-document-vault.onrender.com`

### ⚠️ Important Notes for Render Free Tier
- Free tier **spins down** after 15 mins of inactivity (first request takes ~30s to wake up)
- Upgrade to Render Starter ($7/month) to keep it always-on
- Files stored in `uploads/`, `encrypted_storage/`, `keys/` are **ephemeral** on free tier
  → Use Render Disk (add in dashboard) or upgrade for persistent storage

---

## Option 2: Railway.app (Easier, Better Free Tier)

1. Go to https://railway.app and sign in with GitHub
2. Click **"New Project"** → **"Deploy from GitHub repo"**
3. Select your repository
4. Railway auto-detects Python — add environment variables:
   - `SECRET_KEY` → any long random string
   - `FLASK_ENV` → `production`
   - `SESSION_COOKIE_SECURE` → `True`
5. It auto-deploys! Your URL will be: `https://yourapp.up.railway.app`

---

## Option 3: Run Locally (Development)

```bash
# 1. Create virtual environment
python -m venv venv

# 2. Activate it
# Windows:
venv\Scripts\activate
# Mac/Linux:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the app
python run.py

# 5. Open browser at:
# http://localhost:5000
```

Default admin login:
- Username: `admin`
- Password: `Admin@1234`
⚠️ Change this immediately after first login!

---

## Security Checklist Before Going Live
- [ ] Change default admin password
- [ ] Set a strong `SECRET_KEY` environment variable
- [ ] Enable `SESSION_COOKIE_SECURE=True` (requires HTTPS)
- [ ] Back up `keys/master.key` — losing it means losing all encrypted files
- [ ] Never commit `.env`, `keys/`, `instance/` to GitHub (already in .gitignore)
