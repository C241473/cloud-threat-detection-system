# 🔐 Cloud Security Monitoring & Threat Detection System

A complete full-stack Cyber Security solution featuring real-time telemetry log collection, automated threat detection engine (Brute-force, SQL Injection, Rate Limiting, Access Violations, Privileged Escalation), modern dark-mode Security Operations Center (SOC) dashboard, JWT authentication with Argon2 password hashing, and containerized Docker / Vercel deployment.

---

## 🌐 Live Deployment Links

- 🖥️ **Web SOC Dashboard UI**: [https://cloud-threat-detection-system.vercel.app/](https://cloud-threat-detection-system.vercel.app/)
- 📜 **Interactive API Documentation (Swagger)**: [https://cloud-threat-detection-system.vercel.app/docs](https://cloud-threat-detection-system.vercel.app/docs)
- 📐 **OpenAPI JSON Blueprint**: [https://cloud-threat-detection-system.vercel.app/openapi.json](https://cloud-threat-detection-system.vercel.app/openapi.json)

---

## 🏗️ System Architecture

```text
              User / Admin / Analyst
                        │
                        ▼
            ┌───────────────────────┐
            │   Web Dashboard UI    │
            │ (HTML5 / CSS / JS)    │
            └───────────┬───────────┘
                        │
                        ▼
            ┌───────────────────────┐
            │     Python Backend    │
            │       (FastAPI)       │
            └───────────┬───────────┘
                        │
         ┌──────────────┴──────────────┐
         ▼                             ▼
  ┌──────────────┐             ┌──────────────┐
  │ Log Analyzer │             │ Database     │
  │ (Engine)     │             │ SQLite / PG  │
  └──────┬───────┘             └──────────────┘
         │
         ▼
  ┌──────────────┐
  │ Threat Rules │
  │ Engine       │
  └──────┬───────┘
         │
         ▼
  🚨 Alert Dispatcher
         │
         ▼
  ☁️ Docker / Vercel / AWS EC2 Deployment
```

---

## 🧰 Tech Stack

* **Backend**: Python 3.11, FastAPI, Uvicorn, SQLAlchemy, Pydantic v2
* **Security & Auth**: Argon2 Hashing, Passlib, JWT (JSON Web Tokens), OAuth2
* **Database**: SQLite (Local Zero-Config) / PostgreSQL (Production & Docker)
* **Frontend**: HTML5, Modern CSS (SOC Dark Theme), Vanilla JavaScript, Chart.js
* **Metrics**: `psutil` (Real-time CPU, RAM, Disk telemetry)
* **Testing**: Pytest, FastAPI TestClient
* **DevOps**: Docker, Docker Compose, Vercel Serverless

---

## 📂 Project Structure

```text
cloud-security-monitor/
├── api/
│   └── index.py               # Vercel Serverless entry point
├── backend/
│   ├── main.py                # FastAPI entry point & CORS configuration
│   ├── config.py              # App settings & threat threshold config
│   ├── database.py            # SQLAlchemy database engine & sessions
│   ├── models.py              # User, SecurityLog, Threat, SystemMetric ORM
│   ├── schemas.py             # Pydantic validation schemas
│   ├── routes/
│   │   ├── auth_routes.py     # Login, registration & JWT tokens
│   │   ├── log_routes.py      # Telemetry log ingestion & simulator
│   │   ├── threat_routes.py   # Threat alerts & resolution status
│   │   └── dashboard_routes.py# Summary metrics & hardware stats
│   ├── security/
│   │   └── auth.py            # Argon2 password hashing & JWT verification
│   └── security_engine/
│       ├── rules.py           # Intrusion detection rule definitions
│       ├── detector.py        # Central log analysis engine
│       └── geo.py             # Geo-IP location lookup module
├── frontend/
│   ├── index.html             # Interactive Cyber Security Dashboard
│   ├── css/styles.css         # Dark theme SOC styling & alert badges
│   └── js/app.js              # Real-time metrics polling & Chart.js logic
├── tests/
│   ├── test_security_engine.py# Pytest threat engine rule unit tests
│   └── test_api.py            # REST API integration tests
├── .env.example               # Environment variables template
├── Dockerfile                 # Multi-stage Python container build
├── docker-compose.yml         # FastAPI + PostgreSQL container orchestration
├── vercel.json                # Vercel deployment configuration
├── requirements.txt           # Python dependencies
└── README.md                  # Project documentation
```

---

## 🚀 Quick Start Guide

### 1. Local Setup (Without Docker)

```bash
# Clone or navigate to project folder
cd cloud-security-monitor

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start FastAPI App with Live Reload
uvicorn backend.main:app --reload --port 8000
```

Open your browser and visit:
* **Interactive Dashboard**: `http://localhost:8000/`
* **Swagger API Docs**: `http://localhost:8000/docs`

---

### 2. Docker Setup (With PostgreSQL)

```bash
# Start backend and PostgreSQL database containers
docker-compose up --build -d
```

---

## 🛡️ Intrusion Detection Rules

1. **Brute-Force Login Detection**:
   * *Rule*: `5 failed login attempts` from the same IP within `5 minutes`.
   * *Severity*: **HIGH**
2. **SQL Injection & Malicious Payload Detection**:
   * *Rule*: Malicious SQL payloads (`' OR '1'='1'`, `UNION SELECT`, `<script>`).
   * *Severity*: **CRITICAL**
3. **Automated Request Flooding (Rate Limiting)**:
   * *Rule*: `>= 50 requests` from the same IP within `1 minute`.
   * *Severity*: **MEDIUM**
4. **Unauthorized Access Violation**:
   * *Rule*: `3+ ACCESS_DENIED` events for forbidden resources.
   * *Severity*: **HIGH**
5. **Suspicious Privileged Activity**:
   * *Rule*: Failed logins targeted at privileged accounts (`admin`, `root`).
   * *Severity*: **CRITICAL**

---

## 🧪 Running Automated Tests

```bash
# Execute pytest test suite
pytest -v
```

---

## ☁️ AWS / Cloud Deployment Steps

1. Launch an **AWS EC2 Instance** (Ubuntu 22.04 LTS, t2.micro / t3.small).
2. Configure **Security Group** Inbound Rules:
   * Port 22 (SSH), Port 80/443 (HTTP/HTTPS), Port 8000 (FastAPI).
3. SSH into EC2 instance and run:
   ```bash
   docker-compose up --build -d
   ```
