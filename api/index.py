import sys
import os

# Ensure root project directory is in python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.main import app

# Export ASGI application for Vercel Serverless Function
app = app
