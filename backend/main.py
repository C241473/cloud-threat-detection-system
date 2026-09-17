import os
import datetime
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from backend.config import settings
from backend.database import engine, Base, SessionLocal
from backend.models import User, SecurityLog
from backend.security.auth import hash_password
from backend.routes import auth_routes, log_routes, threat_routes, dashboard_routes
from backend.security_engine.detector import SecurityEngine

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup Database Auto-Migration & Seed Data
    Base.metadata.create_all(bind=engine)
    
    db = SessionLocal()
    try:
        # Seed default Admin & Analyst users if empty
        if db.query(User).count() == 0:
            admin_user = User(
                username="admin",
                email="admin@security.cloud",
                password_hash=hash_password("AdminPass123!"),
                role="admin"
            )
            analyst_user = User(
                username="analyst",
                email="analyst@security.cloud",
                password_hash=hash_password("AnalystPass123!"),
                role="analyst"
            )
            db.add_all([admin_user, analyst_user])
            db.commit()

        # Seed sample initial logs and threats if empty
        if db.query(SecurityLog).count() == 0:
            sample_logs = [
                SecurityLog(ip_address="192.168.1.100", username="john_doe", event_type="LOGIN_SUCCESS", status="SUCCESS", details="Standard user login", timestamp=datetime.datetime.utcnow() - datetime.timedelta(minutes=45)),
                SecurityLog(ip_address="10.0.0.55", username="admin", event_type="LOGIN_SUCCESS", status="SUCCESS", details="Admin portal access", timestamp=datetime.datetime.utcnow() - datetime.timedelta(minutes=30)),
                SecurityLog(ip_address="198.51.100.42", username="guest", event_type="ACCESS_DENIED", status="FAILED", details="Attempted unauthorized path access /admin/config", timestamp=datetime.datetime.utcnow() - datetime.timedelta(minutes=25)),
                SecurityLog(ip_address="198.51.100.42", username="guest", event_type="ACCESS_DENIED", status="FAILED", details="Attempted unauthorized path access /admin/db", timestamp=datetime.datetime.utcnow() - datetime.timedelta(minutes=20)),
                SecurityLog(ip_address="198.51.100.42", username="guest", event_type="ACCESS_DENIED", status="FAILED", details="Attempted unauthorized path access /admin/keys", timestamp=datetime.datetime.utcnow() - datetime.timedelta(minutes=15)),
            ]
            db.add_all(sample_logs)
            db.commit()

            # Process seeded logs through detector
            for l in sample_logs:
                SecurityEngine.process_log(db, l)

    finally:
        db.close()
        
    yield

# Initialize FastAPI App with Lifespan
app = FastAPI(
    title=settings.APP_NAME,
    description="A full-stack Cloud Security Monitoring & Intrusion Threat Detection API",
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS for frontend interaction
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(auth_routes.router)
app.include_router(log_routes.router)
app.include_router(threat_routes.router)
app.include_router(dashboard_routes.router)

# Static Frontend Mount
frontend_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend")
if os.path.exists(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

    @app.get("/", include_in_schema=False)
    def serve_frontend():
        return FileResponse(os.path.join(frontend_dir, "index.html"))
