# PhishCheck - Project Structure

## Overview
Full-stack phishing detection platform with FastAPI backend and Vue 3 frontend.

---

## Backend (`/backend/app`)

```
app/
├── api/                    # API Layer
│   ├── routers/
│   │   ├── email.py        # POST /api/v1/analysis/email
│   │   ├── link.py         # POST /api/v1/analysis/link
│   │   ├── file.py         # POST /api/v1/analysis/file
│   │   ├── ai_agent.py     # POST /api/v1/ai
│   │   ├── auth.py         # Login, register, OAuth
│   │   └── dependencies.py # AnalysisContext, auth checks
│   └── routes.py           # Router aggregation
│
├── core/                   # Core Config
│   ├── config.py           # Environment settings
│   ├── database.py         # SQLite init
│   ├── logging.py          # Structured logging
│   └── rate_limit.py       # SlowAPI limiter
│
├── services/               # Business Logic
│   ├── analysis_pipeline.py # Email analysis orchestration
│   ├── auth_service.py      # Auth + rate limits
│   ├── email_parser.py      # EML parsing
│   ├── threat_intel.py      # Threat intel orchestration
│   ├── rag_service.py       # AI chat service
│   └── providers/           # External API clients
│       ├── virustotal.py
│       ├── urlscan.py
│       ├── sublime.py
│       └── ipqs.py
│
├── schemas/                # Pydantic Models
│   ├── email.py            # Email parsing schemas
│   ├── threat_intel.py     # VT, URLscan responses
│   └── chat.py             # AI chat schemas
│
└── main.py                 # FastAPI app factory
```

---

## Frontend (`/frontend/src`)

```
src/
├── views/                  # Page Components
│   ├── AnalysisView.vue    # Email analysis
│   ├── LinkAnalysisView.vue
│   ├── FileAnalysisView.vue
│   ├── LoginView.vue
│   └── AIChatView.vue
│
├── components/             # Reusable UI
│   ├── ui/                 # Shadcn components
│   └── chat/               # AI widget
│
├── stores/                 # Pinia State
│   ├── analysis.ts
│   ├── auth.ts
│   └── chat.ts
│
├── hooks/                  # Composables
│   ├── useAnalysisState.ts
│   └── useThreatIntel.ts
│
└── services/
    └── api.ts              # API client
```

---

## API Endpoints

### Analysis (`/api/v1/analysis/`)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/email` | POST | Analyze .eml file |
| `/link` | POST | Analyze URL |
| `/file` | POST | Analyze file hash |
| `/urlscan/{id}` | GET | Refresh scan |

### AI (`/api/v1/ai/`)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | POST | Chat with AI |
| `/suggestions` | GET | Get suggestions |

---

## External Integrations

| Service | Purpose |
|---------|---------|
| Sublime Security | Email analysis, ML link detection |
| VirusTotal | URL/domain/file reputation |
| URLscan.io | URL scanning + screenshots |
| IPQS | IP reputation |
| Hybrid Analysis | Sandbox file analysis |
| Google Gemini | AI chat assistant |

---

## Key Patterns

- **API Versioning**: `/api/v1/` prefix
- **Dependency Injection**: `AnalysisContext` for auth + rate limits
- **Structured Logging**: JSON (prod) / Colored (dev)
- **Request Tracing**: `X-Request-ID` header

---

*API Docs: http://localhost:8000/api/docs*
