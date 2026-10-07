# SECUREGATE
### Automated Pre-Release Web Application Security Gate

[![CI/CD Pre-Release Gate](https://github.com/securegate/securegate/actions/workflows/security.yml/badge.svg)](https://github.com/securegate/securegate/actions/workflows/security.yml)
[![Engine](https://img.shields.io/badge/Scanner-OWASP%20ZAP%202.14-blue.svg)](https://www.zaproxy.org/)
[![Standards](https://img.shields.io/badge/Security-OWASP%20Top%2010%20%7C%20CWE-purple.svg)](https://owasp.org/www-project-top-ten/)
[![Release Gate](https://img.shields.io/badge/Policy-PASS%20%7C%20REVIEW%20%7C%20BLOCK-success.svg)](#9-release-gate-decision-engine)

> **"Security testing should not end when a scanner finds a vulnerability.  
> SecureGate turns security findings into an actionable release decision."**

---

## 1. Product Overview

In modern DevSecOps pipelines, automated dynamic application security testing (DAST) generates voluminous alert reports that developers and release managers struggle to translate into release decisions. Raw scanner outputs lack organizational policy context, fail to provide clear blocking criteria, and dump hundreds of lines of noise into CI/CD logs.

**SecureGate** bridges this critical gap. SecureGate is the **analysis, decision, reporting, visualization, and release-gating layer** sitting on top of OWASP ZAP. It transforms raw scanner outputs into deterministic release verdicts:

$$\text{TARGET APP} \longrightarrow \text{OWASP ZAP} \longrightarrow \text{ZAP REPORT} \longrightarrow \text{SECUREGATE} \longrightarrow \begin{cases} \mathbf{PASS} & \text{(Deploy)} \\ \mathbf{REVIEW} & \text{(AppSec Sign-Off)} \\ \mathbf{BLOCK} & \text{(Deployment Halted)} \end{cases}$$

---

## 2. Architecture & Workflow

```
┌─────────────────────────┐
│   TARGET APPLICATION    │
│    (OWASP Juice Shop)   │
└────────────┬────────────┘
             │ Dynamic Application Security Testing (DAST)
             ▼
┌─────────────────────────┐
│     OWASP ZAP 2.14      │
│    (Detection Engine)   │
└────────────┬────────────┘
             │ JSON Scan Artifact
             ▼
┌──────────────────────────────────────────────────────────────┐
│                      SECUREGATE BACKEND                      │
│                                                              │
│  ┌────────────────────┐      ┌────────────────────────────┐  │
│  │  ZAP JSON Parser   │ ───► │   Finding Normalization    │  │
│  └────────────────────┘      └─────────────┬──────────────┘  │
│                                            │                 │
│  ┌────────────────────┐      ┌─────────────▼──────────────┐  │
│  │ OWASP / CWE Mapper │ ◄─── │   Severity Classification  │  │
│  └─────────┬──────────┘      └────────────────────────────┘  │
│            │                                                 │
│  ┌─────────▼──────────┐      ┌────────────────────────────┐  │
│  │  Risk Score Engine │ ───► │  Deterministic Gate Policy │  │
│  └────────────────────┘      └─────────────┬──────────────┘  │
└────────────────────────────────────────────┼─────────────────┘
                                             │
                       ┌─────────────────────┴─────────────────────┐
                       ▼                                           ▼
             ┌───────────────────┐                       ┌───────────────────┐
             │   RELEASE GATE    │                       │     SECURITY      │
             │ PASS/REVIEW/BLOCK │                       │ ASSESSMENT REPORT │
             └───────────────────┘                       └───────────────────┘
```

---

## 3. Tech Stack

- **Frontend**: React 18, Vite, TypeScript, Tailwind CSS, Recharts, Lucide Icons
- **Backend**: Python 3.11+, Flask REST API, SQLAlchemy ORM, Marshmallow
- **Database**: SQLite (local development & zero-dependency portability)
- **Security Tools**: OWASP ZAP (Zed Attack Proxy), OWASP Juice Shop (authorized vulnerable target)
- **DevOps**: GitHub Actions (`.github/workflows/security.yml`), Docker, Docker Compose
- **AI Security Analyst (Optional)**: OpenAI API integration with sensitive metadata sanitization and deterministic fallback advisor

---

## 4. Key Features

1. **Robust ZAP Ingestion Engine**:
   - Parses multi-site, single-site, and root-level ZAP JSON schemas
   - Gracefully handles missing attributes and malformed reports
   - Deduplicates findings based on signature, URL, and parameter
2. **Automated OWASP Top 10 & CWE Taxonomy Mapping**:
   - Maps vulnerabilities to OWASP Top 10 (2021) categories
   - Resolves CWE classifications (CWE-89, CWE-79, CWE-1021, etc.)
   - Retains unmapped designations with zero hallucination
3. **Deterministic Severity & Security Scoring Engine**:
   - Computes non-linear Posture Score (0–100) reflecting diminishing risk returns
   - Calculates weighted individual vulnerability risk scores
4. **DevSecOps Release Gate**:
   - Enforces configurable security policies:
     - **Critical / High** $\longrightarrow$ **BLOCK**
     - **Medium** $\longrightarrow$ **REVIEW**
     - **Low / Informational** $\longrightarrow$ **PASS**
5. **Vulnerability Registry & Deep Investigation**:
   - Inspect HTTP method, affected endpoint, injected parameter, and attack evidence
   - Remediation guidance and direct OWASP cheat sheet references
   - Workflow state management (`open`, `reviewed`, `fixed`)
6. **OWASP ZAP REST API Daemon Integration**:
   - Live connectivity checks and real-time latency monitoring for local/remote ZAP daemons (`http://localhost:8080`)
   - Trigger Spider crawls and Active scans on any custom target URL directly from SecureGate
   - Real-time animated progress bar (0%–100%) and streaming terminal log console
   - Interactive diagnostic runner mode for environments without a running Docker container
7. **Production GitHub Actions CI/CD Quality Gate**:
   - Complete `.github/workflows/securegate-ci.yml` workflow ready to drop into any repository
   - Standalone CLI runner `scripts/securegate-gate.py` that halts deployment if gate evaluates to **BLOCK**
   - Automatically writes rich Markdown audit tables into `$GITHUB_STEP_SUMMARY`
8. **Optional AI AppSec Advisor**:
   - Sanitizes sensitive parameters, auth headers, and tokens before inference
   - Generates plain-English executive summaries, technical impact, business risk, and developer action checklists
   - Seamless deterministic fallback when `OPENAI_API_KEY` is not present
9. **Print-Ready Audit Reports & Universal Ingestion**:
   - Standalone printable HTML report exportable as PDF for compliance audits
   - Universal parser ingests standard ZAP JSON, XML-to-JSON, API exports, and ZAP Automation Framework execution logs with 100% accuracy
10. **1-Click Hackathon Demo Mode**:
   - Pre-loaded with realistic OWASP Juice Shop scans, historical releases, and blocking decisions

---

## 5. Local Setup & Quick Start

### Prerequisites
- Python 3.10+
- Node.js 18+ and npm
- (Optional) Docker for running Juice Shop and ZAP locally

### A. Clone and Setup Environment

```bash
cd securegate

# Copy environment template
cp .env.example .env
```

### B. Run Backend

```bash
cd backend

# Install dependencies
pip install -r requirements.txt

# Run test suite (verifies 29 unit & integration tests)
pytest -v

# Start SecureGate API (default: http://127.0.0.1:5000)
python run.py
```

### C. Run Frontend

Open a second terminal:

```bash
cd frontend

# Install dependencies
npm install

# Start Vite development server
npm run dev
```

Open your browser at **http://localhost:5173**.

---

## 6. Target Application & Scanner Demo

### Step 1: Start OWASP Juice Shop (Target)

Run the deliberately vulnerable OWASP Juice Shop container:

```bash
docker run -d --name juiceshop -p 3000:3000 bkimminich/juice-shop
```
Verify Juice Shop is accessible at **http://localhost:3000**.

### Step 2: Run OWASP ZAP Baseline Scan

Using PowerShell (Windows):
```powershell
.\scripts\run_zap_scan.ps1 -TargetUrl "http://localhost:3000" -OutputFile "reports\zap_juiceshop_scan.json"
```

Or using Bash (Linux/macOS):
```bash
./scripts/run_zap_scan.sh http://localhost:3000
```

*Note: If Docker is not installed on your system during the presentation, you can immediately import the bundled real-world scan file in `reports/zap_juiceshop_scan.json` or click the 1-click preset button in the UI!*

### Step 3: Evaluate in SecureGate

1. Click **"Import ZAP Scan"** in the top navigation bar.
2. Either drag & drop `reports/zap_juiceshop_scan.json` or click **"Juice Shop (BLOCK)"** preset.
3. Observe the immediate release verdict: **BLOCKED**.
4. Inspect the findings: SQL Injection on `/rest/products/search`, XSS on `/api/Feedbacks`.
5. Click **"Explain with AI"** on any finding to receive executive and developer guidance.
6. Open **"Security Assessment"** to view and print the executive report.

---

## 7. Automated CI/CD Pipeline (GitHub Actions)

SecureGate includes a complete GitHub Actions workflow (`.github/workflows/security.yml`):

1. Checks out repository and installs Python dependencies.
2. Executes backend unit and release gate verification tests.
3. Launches OWASP Juice Shop container on port 3000.
4. Executes OWASP ZAP baseline scanner container (`zaproxy/zap-stable`).
5. Invokes SecureGate parsing and release policy engine.
6. **Fails the pipeline build** if High or Critical vulnerabilities breach configured thresholds.

---

## 8. REST API Documentation

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Health check & database connection probe |
| `GET` | `/api/projects` | List all registered target applications |
| `POST` | `/api/projects` | Register a new target project |
| `POST` | `/api/projects/seed-demo` | Seed / reset OWASP Juice Shop demo dataset |
| `GET` | `/api/dashboard` | Aggregated posture score, gate decision, charts |
| `GET` | `/api/scans` | Historical scan evaluations |
| `POST` | `/api/scans/upload` | Ingest and parse ZAP JSON report |
| `GET` | `/api/scans/:id` | Scan details and summary metrics |
| `GET` | `/api/findings` | Filterable vulnerability registry |
| `GET` | `/api/findings/:id` | Detailed finding evidence and remediation |
| `PATCH`| `/api/findings/:id` | Update finding status (`open`, `reviewed`, `fixed`) |
| `GET` | `/api/releases` | DevSecOps release gating history timeline |
| `GET` | `/api/reports/:id` | Structured JSON security assessment report |
| `GET` | `/api/reports/:id/html` | Standalone print-ready HTML / PDF view |
| `GET` | `/api/settings` | Current release policy and scanner configuration |
| `PUT` | `/api/settings` | Update release thresholds & environment |
| `POST` | `/api/ai/explain` | AI AppSec Analyst explanation with fallback |

---

## 9. 90-Second Hackathon Demo Workflow

1. **Dashboard (0:00 - 0:25)**: Open SecureGate. Point out the Security Posture Score (e.g. 78/100) and the prominent **BLOCKED** release gate decision caused by 2 High severity vulnerabilities.
2. **Vulnerability Investigation (0:25 - 0:45)**: Click **"Inspect Findings"**. Open **"SQL Injection"**. Highlight the mapped **OWASP A03: Injection**, **CWE-89**, endpoint `/rest/products/search`, attack payload evidence, and remediation guidance.
3. **AI AppSec Analyst (0:45 - 1:05)**: Switch to the **"AI AppSec Analyst"** tab. Show how sanitized vulnerability metadata generates developer action items and business impact analysis.
4. **Importing New Scan (1:05 - 1:20)**: Click **"Import ZAP Scan"** $\longrightarrow$ click **"Hardened Build (PASS)"**. Watch the dashboard instantly update: Score jumps to 96/100, Gate status turns green (**PASSED**).
5. **Audit Report & CI/CD (1:20 - 1:30)**: Click **"Security Assessment"** $\longrightarrow$ show print-friendly report and GitHub Actions gate file.

---

## 10. Security & Ethical Considerations

- **Strict Target Scoping**: SecureGate is designed strictly for pre-release verification of owned and authorized staging/local artifacts (such as local OWASP Juice Shop). It enforces local URL scoping to avoid unauthorized scanning.
- **Credential Redaction**: Before sending vulnerability metadata to any external LLM endpoint, all authorization headers, bearer tokens, passwords, and AWS keys are stripped.
- **Zero Hallucination Gate**: Release decisions are executed **100% deterministically** by the policy engine; the AI layer serves exclusively in an advisory capacity.
