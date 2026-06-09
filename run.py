"""
run.py — Entry point for Secure Document Vault
Usage:
    python run.py              (local development)
    gunicorn run:app           (production)
"""
import os
from app import app, init_db

# Initialise DB on startup
with app.app_context():
    init_db()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') != 'production'
    app.run(debug=debug, host='0.0.0.0', port=port)
