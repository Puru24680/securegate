"""
Vercel Serverless Function Entrypoint for SecureGate Backend
"""
import sys
import os

# Inject backend path into sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
backend_dir = os.path.abspath(os.path.join(current_dir, '..', 'backend'))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app import create_app

app = create_app()

# Expose app for WSGI / Vercel Python runtime
if __name__ == '__main__':
    app.run()
