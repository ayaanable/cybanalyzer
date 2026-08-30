import os
import sys

BACKEND = os.path.join(os.path.dirname(os.path.dirname(__file__)), "backend")

if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from app.main import app
