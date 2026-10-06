"""
SecureGate Backend Runner
"""
import os
from dotenv import load_dotenv

# Load local environment if .env exists
load_dotenv()

from app import create_app

app = create_app()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    host = os.environ.get('HOST', '127.0.0.1')
    debug = os.environ.get('FLASK_DEBUG', '1') == '1'
    print(f"[*] Starting SecureGate Pre-Release Security Gate Backend on http://{host}:{port}")
    app.run(host=host, port=port, debug=debug)
