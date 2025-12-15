# PhishCheck - Detailed Project Structure

**Type**: Full-Stack Phishing Detection Platform  
**Backend**: FastAPI (Python 3.11+)  
**Frontend**: Vue 3 + TypeScript + Tailwind CSS

---

## 📁 Complete Directory Structure

```
PhishCheck/
├── backend/                          # Python FastAPI Backend
│   ├── app/
│   │   ├── api/                      # API Layer
│   │   │   ├── routers/              # API Endpoints
│   │   │   │   ├── __init__.py
│   │   │   │   ├── dependencies.py   # Auth context, rate limit checks
│   │   │   │   ├── email.py          # POST /api/v1/analysis/email
│   │   │   │   ├── link.py           # POST /api/v1/analysis/link  
│   │   │   │   ├── file.py           # POST /api/v1/analysis/file
│   │   │   │   ├── ai_agent.py       # POST /api/v1/ai (AI chat)
│   │   │   │   ├── auth.py           # Auth endpoints (login, register, OAuth)
│   │   │   │   ├── health.py         # GET /api/v1/health (health check)
│   │   │   │   └── utils.py          # Utility endpoints
│   │   │   ├── __init__.py
│   │   │   └── routes.py             # Router aggregation
│   │   │
│   │   ├── core/                     # Core Configuration
│   │   │   ├── __init__.py
│   │   │   ├── config.py             # Environment settings (Settings class)
│   │   │   ├── constants.py          # ✨ Centralized constants (NEW)
│   │   │   ├── database.py           # SQLite initialization
│   │   │   ├── logging.py            # Structured logging (JSON/colored)
│   │   │   ├── rate_limit.py         # SlowAPI rate limiter
│   │   │   └── security_headers.py   # ✨ OWASP security headers (NEW)
│   │   │
│   │   ├── services/                 # Business Logic Layer
│   │   │   ├── __init__.py
│   │   │   ├── analysis_pipeline.py  # Email analysis orchestration
│   │   │   ├── auth_service.py       # Auth + session + rate limits
│   │   │   ├── email_parser.py       # EML file parsing (headers, body, attachments)
│   │   │   ├── email_service.py      # Email verification (Resend API)
│   │   │   ├── oauth_service.py      # OAuth flow (Google, Microsoft)
│   │   │   ├── qr_scanner.py         # QR code detection in images
│   │   │   ├── rag_service.py        # AI chat with RAG (Gemini)
│   │   │   ├── threat_intel.py       # Threat intel orchestration
│   │   │   └── providers/            # External API Clients
│   │   │       ├── __init__.py
│   │   │       ├── virustotal.py     # VirusTotal API
│   │   │       ├── urlscan.py        # URLscan.io API
│   │   │       ├── sublime.py        # Sublime Security MDM API
│   │   │       ├── ipqs.py           # IP Quality Score API
│   │   │       └── hybrid_analysis.py # Hybrid Analysis (sandbox)
│   │   │
│   │   ├── models/                   # Database Models (SQLAlchemy)
│   │   │   ├── __init__.py
│   │   │   └── user.py               # User, Session, OAuthState, GuestRateLimit models
│   │   │
│   │   ├── schemas/                  # Pydantic Schemas (validation)
│   │   │   ├── __init__.py
│   │   │   ├── analysis.py           # CombinedAnalysisResult
│   │   │   ├── attachment_analysis.py # Attachment schemas
│   │   │   ├── auth.py               # UserLogin, UserRegister, AuthResponse
│   │   │   ├── chat.py               # ChatRequest, ChatResponse
│   │   │   ├── email.py              # ParsedEmail, EmailHeader, EmailBody
│   │   │   ├── link_analysis.py      # LinkAnalysisResult
│   │   │   ├── mdm.py                # Sublime MDM schemas
│   │   │   └── threat_intel.py       # ThreatIntelReport, VT/URLscan schemas
│   │   │
│   │   ├── utils/                    # Utility Functions
│   │   │   ├── __init__.py
│   │   │   ├── crypto.py             # Token encryption/decryption
│   │   │   └── datetime.py           # Timezone utilities
│   │   │
│   │   ├── knowledge/                # RAG Knowledge Base
│   │   │   ├── email_analysis.md     # Email analysis guide
│   │   │   ├── file_analysis.md      # File analysis guide
│   │   │   ├── link_analysis.md      # Link analysis guide
│   │   │   ├── privacy_summary.md    # Privacy policy summary
│   │   │   ├── terms_summary.md      # Terms of service summary
│   │   │   └── user_guide.md         # User guide
│   │   │
│   │   └── main.py                   # FastAPI application factory
│   │
│   ├── tests/                        # Backend Tests (pytest)
│   │   ├── __init__.py
│   │   ├── test_app.py               # Basic app tests
│   │   ├── test_auth_service.py      # Auth service tests
│   │   ├── test_email_parser.py      # Email parsing tests
│   │   ├── test_sublime_client.py    # Sublime API tests
│   │   └── test_sublime_mdm.py       # Sublime MDM schema tests
│   │
│   ├── scripts/                      # Utility Scripts
│   │   ├── cleanup.py                # Cleanup old sessions/unverified users
│   │   ├── run_sublime.py            # Test Sublime API
│   │   ├── filter_sublime_hits.py    # Parse Sublime responses
│   │   └── api_test.py               # API testing
│   │
│   ├── .env.example                  # Environment variables template
│   ├── requirements.txt              # Python dependencies
│   ├── phishcheck.db                 # SQLite database
│   └── phishcheck.erd                # Database ERD
│
├── frontend/                         # Vue 3 + TypeScript Frontend
│   ├── src/
│   │   │   ├── NotificationsView.vue # Notifications
│   │   │   ├── BillingView.vue       # Future: billing
│   │   │   ├── FeedbackView.vue      # Feedback form
│   │   │   ├── SupportView.vue       # Support/help center
│   │   │   ├── PrivacyPolicyView.vue # Privacy policy
│   │   │   ├── TermsOfServiceView.vue # Terms of service
│   │   │   └── NotFound.vue          # 404 page
│   │   │
│   │   ├── components/               # Reusable Components
│   │   │   ├── auth/                 # Auth Components
│   │   │   │   ├── LoginForm.vue
│   │   │   │   ├── SignupForm.vue
│   │   │   │   └── OAuthButtons.vue
│   │   │   │
│   │   │   ├── chat/                 # AI Chat Components
│   │   │   │   ├── ChatMessage.vue
│   │   │   │   └── ChatInput.vue
│   │   │   │
│   │   │   ├── layout/               # Layout Components
│   │   │   │   ├── Header.vue
│   │   │   │   └── AppSidebar.vue
│   │   │   │
│   │   │   ├── icons/                # Custom Icons
│   │   │   │   ├── IconGoogle.vue
│   │   │   │   └── IconMicrosoft.vue
│   │   │   │
│   │   │   └── ui/                   # Shadcn/vue Components
│   │   │       ├── avatar/
│   │   │       ├── badge/
│   │   │       ├── button/
│   │   │       ├── card/
│   │   │       ├── dialog/
│   │   │       ├── dropdown-menu/
│   │   │       ├── input/
│   │   │       ├── label/
│   │   │       ├── separator/
│   │   │       ├── sheet/
│   │   │       ├── sidebar/
│   │   │       ├── skeleton/
│   │   │       ├── switch/
│   │   │       ├── tooltip/
│   │   │       └── ... (20+ more)
│   │   │
│   │   ├── stores/                   # Pinia State Management
│   │   │   ├── analysis.ts           # Analysis state (results, loading)
│   │   │   ├── auth.ts               # Auth state (user, session)
│   │   │   ├── chat.ts               # AI chat state
│   │   │   ├── api.ts                # API client state
│   │   │   └── sidebar.ts            # Sidebar state
│   │   │
│   │   ├── hooks/                    # Vue Composables
│   │   │   ├── useAnalysisState.ts   # Analysis state management
│   │   │   ├── useThreatIntel.ts     # Threat intel data parsing
│   │   │   ├── useParsedEmail.ts     # Email parsing utilities
│   │   │   ├── useSublimeInsights.ts # Sublime insights parsing
│   │   │   └── useViewport.ts        # Responsive utilities
│   │   │
│   │   ├── services/                 # API Layer
│   │   │   └── api.ts                # Axios API client
│   │   │
│   │   ├── types/                    # TypeScript Types
│   │   │   └── analysis.ts           # Analysis result types
│   │   │
│   │   ├── utils/                    # Utility Functions
│   │   │   └── screenshotUtils.ts    # Screenshot utilities
│   │   │
│   │   ├── lib/                      # Library Functions
│   │   │   └── utils.ts              # cn() utility for Tailwind
│   │   │
│   │   ├── assets/                   # Static Assets
│   │   │   ├── base.css              # Base styles
│   │   │   ├── main.css              # Main styles + Tailwind
│   │   │   └── logo.svg              # Logo
│   │   │
│   │   ├── router/                   # Vue Router
│   │   │   └── index.ts              # Route definitions + guards
│   │   │
│   │   ├── App.vue                   # Root component
│   │   └── main.ts                   # App entry point
│   │
│   ├── public/                       # Public Assets
│   │   └── FullLogo_Transparent_NoBuffer.ico # Favicon
│   │
│   ├── e2e/                          # E2E Tests (Playwright)
│   │   └── vue.spec.ts
│   │
│   ├── components.json               # Shadcn config
│   ├── env.d.ts                      # Environment types
│   ├── index.html                    # HTML entry
│   ├── package.json                  # Node dependencies
│   ├── package-lock.json             # Locked dependencies
│   ├── tailwind.config.ts            # Tailwind configuration
│   ├── tsconfig.json                 # TypeScript config
│   ├── tsconfig.app.json             # App TypeScript config
│   ├── vite.config.ts                # Vite configuration
│   └── vitest.config.ts              # Vitest config (unit tests)
│
├── Project_Structure.md              # This file
├── README.md                         # Project README
├── schema.sql                        # Database schema SQL
└── start.bat                         # Quick start script

```

---

## 🔑 Key Files Explained

### Backend Core Files

| File | Purpose |
|------|---------|
| `main.py` | FastAPI app factory, middleware setup, exception handlers |
| `config.py` | Loads environment variables, validates settings |
| `constants.py` | ✨ Centralized constants (file sizes, limits, timeouts) |
| `security_headers.py` | ✨ OWASP security headers middleware |
| `database.py` | SQLite initialization, table creation |
| `logging.py` | Structured logging (JSON in prod, colored in dev) |
| `rate_limit.py` | SlowAPI configuration for rate limiting |

### Backend Services

| Service | Purpose |
|---------|---------|
| `analysis_pipeline.py` | Orchestrates email analysis (parsing→Sublime→threat intel) |
| `auth_service.py` | Authentication, sessions, rate limits, OAuth |
| `email_parser.py` | Parses .eml files (headers, body, attachments, MIME) |
| `email_service.py` | Sends verification emails via Resend API |
| `oauth_service.py` | OAuth flows for Google and Microsoft |
| `threat_intel.py` | Orchestrates VirusTotal, URLscan, IPQS lookups |
| `rag_service.py` | AI chat with RAG using Google Gemini |
| `qr_scanner.py` | Detects QR codes in email images |

### Backend API Routers

| Router | Endpoints | Purpose |
|--------|-----------|---------|
| `email.py` | `POST /api/v1/analysis/email` | Analyze .eml file |
| `link.py` | `POST /api/v1/analysis/link` | Analyze URL |
| `file.py` | `POST /api/v1/analysis/file` | Analyze file hash |
| `ai_agent.py` | `POST /api/v1/ai` | AI chat assistant |
| `auth.py` | `/login`, `/register`, `/oauth/*` | Authentication |
| `health.py` | `GET /api/v1/health` | Health check endpoint |
| `utils.py` | Various utility endpoints | Helper functions |
| `dependencies.py` | - | Auth context, rate limit checks |

### Frontend Key Components

| Component | Purpose |
|-----------|---------|
| `AnalysisView.vue` | Main email analysis page (file upload, results) |
| `LinkAnalysisView.vue` | URL analysis page |
| `FileAnalysisView.vue` | File hash analysis page |
| `ChatView.vue` | AI chat assistant interface |
| `LoginView.vue` | Login page with OAuth buttons |
| `SignupView.vue` | Registration with email verification |
| `AppSidebar.vue` | Sidebar navigation component |

### Frontend Stores (Pinia)

| Store | Purpose |
|-------|---------|
| `analysis.ts` | Analysis results, loading state, file data |
| `auth.ts` | User session, login/logout, profile |
| `chat.ts` | AI chat messages, streaming responses |
| `api.ts` | API client configuration |
| `sidebar.ts` | Sidebar open/close state |

---

## 🌐 API Endpoints

### Analysis APIs

```
POST   /api/v1/analysis/email      - Analyze .eml file
POST   /api/v1/analysis/link       - Analyze URL
POST   /api/v1/analysis/file       - Analyze file hash
GET    /api/v1/analysis/urlscan/{id} - Refresh URLscan result
```

### Authentication APIs

```
POST   /api/v1/auth/register       - Email/password registration
POST   /api/v1/auth/login          - Email/password login
POST   /api/v1/auth/logout         - Logout (delete session)
GET    /api/v1/auth/me             - Get current user
POST   /api/v1/auth/verify-email   - Verify email with token
POST   /api/v1/auth/resend-verification - Resend verification email

# OAuth
GET    /api/v1/auth/google         - Initiate Google OAuth
GET    /api/v1/auth/google/callback - Google OAuth callback
GET    /api/v1/auth/microsoft      - Initiate Microsoft OAuth
GET    /api/v1/auth/microsoft/callback - Microsoft OAuth callback
POST   /api/v1/auth/disconnect-oauth - Disconnect OAuth
```

### AI APIs

```
POST   /api/v1/ai                  - Chat with AI assistant
GET    /api/v1/ai/suggestions      - Get chat suggestions
```

---

## 🔧 Technology Stack

### Backend
- **Framework**: FastAPI 0.115+
- **Python**: 3.11+
- **Database**: SQLite (ORM: SQLAlchemy)
- **Authentication**: bcrypt, OAuth 2.0
- **Email**: Resend API
- **AI**: Google Gemini
- **Rate Limiting**: SlowAPI
- **Logging**: Structured JSON logging

### Frontend
- **Framework**: Vue 3.5+
- **Language**: TypeScript 5.9+
- **Build Tool**: Vite 7.1+
- **Styling**: Tailwind CSS 4.0
- **UI Components**: Shadcn/vue (Radix Vue)
- **State Management**: Pinia
- **HTTP Client**: Axios
- **Testing**: Vitest, Playwright

### External APIs
- **Sublime Security** - Email analysis + ML link detection
- **VirusTotal** - URL/domain/file reputation
- **URLscan.io** - URL scanning + screenshots
- **IPQS** - IP reputation checking
- **Hybrid Analysis** - Sandbox file analysis (future)
- **Google Gemini** - AI chat assistant
- **Resend** - Email verification service

---

## 📊 Database Schema

### Tables Overview

PhishCheck uses **4 tables** for user management, authentication, and rate limiting:

#### 1. **users** - User Accounts
Stores user account information, email verification status, and daily analysis limits.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Primary key (auto-increment) |
| `email` | VARCHAR(255) | Unique email address |
| `password_hash` | VARCHAR(255) | bcrypt hashed password (nullable for OAuth users) |
| `name` | VARCHAR(255) | Display name |
| `avatar` | VARCHAR(255) | Profile picture URL (nullable) |
| `is_verified` | BOOLEAN | Email verification status (default: false) |
| `is_active` | BOOLEAN | Account active status (default: true) |
| `oauth_provider` | VARCHAR(50) | OAuth provider: google/microsoft (nullable) |
| `oauth_id` | VARCHAR(255) | OAuth user ID (nullable) |
| `oauth_email` | VARCHAR(255) | Email from OAuth provider (nullable) |
| `oauth_access_token` | TEXT | Encrypted OAuth access token (nullable) |
| `oauth_refresh_token` | TEXT | Encrypted OAuth refresh token (nullable) |
| `verification_token` | VARCHAR(255) | Email verification token (nullable) |
| `verification_token_expires` | DATETIME | Token expiry (48 hours) |
| `daily_eml_count` | INTEGER | EML analysis count (limit: 5/day) |
| `daily_link_count` | INTEGER | Link analysis count (limit: 10/day) |
| `daily_file_count` | INTEGER | File analysis count (limit: 8/day) |
| `daily_ai_count` | INTEGER | AI chat count (limit: 20/day) |
| `last_analysis_date` | DATETIME | Last analysis timestamp (for daily reset) |
| `last_login` | DATETIME | Last login timestamp |
| `created_at` | DATETIME | Account creation timestamp |
| `updated_at` | DATETIME | Last update timestamp |

**Daily Limits (Unverified Users)**:
- EML: 5/day
- Link: 10/day
- File: 8/day
- AI: 20/day
- **Verified users**: Unlimited

---

#### 2. **sessions** - User Sessions
Stores active user sessions for authentication.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Primary key (auto-increment) |
| `user_id` | INTEGER | Foreign key → users.id |
| `token` | VARCHAR(255) | Unique session token (stored in httpOnly cookie) |
| `ip_address` | VARCHAR(45) | Client IP address |
| `user_agent` | TEXT | Browser user agent |
| `expires_at` | DATETIME | Session expiry (7 days from creation) |
| `created_at` | DATETIME | Session creation timestamp |

**Session Management**:
- Expiry: 7 days
- Storage: httpOnly cookies (prevents XSS)
- Cleanup: Automatic on expiry or explicit logout

---

#### 3. **oauth_states** - OAuth CSRF Protection
Temporary storage for OAuth state tokens to prevent CSRF attacks.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Primary key (auto-increment) |
| `state` | VARCHAR(255) | Unique random state token |
| `provider` | VARCHAR(50) | OAuth provider: google/microsoft |
| `expires_at` | DATETIME | Token expiry (10 minutes) |
| `created_at` | DATETIME | Creation timestamp |

**OAuth Flow**:
1. Generate random state token before redirect
2. Store in database with 10-minute expiry
3. Verify state on callback
4. Delete after successful validation

---

#### 4. **guest_rate_limits** - Guest IP Rate Limiting
Tracks analysis usage for non-authenticated users by IP address.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Primary key (auto-increment) |
| `ip_address` | VARCHAR(45) | Client IP address (IPv4/IPv6) |
| `daily_eml_count` | INTEGER | EML analysis count (limit: 2/day) |
| `daily_link_count` | INTEGER | Link analysis count (limit: 5/day) |
| `daily_file_count` | INTEGER | File analysis count (limit: 3/day) |
| `last_analysis_date` | DATETIME | Last analysis timestamp (for daily reset) |
| `created_at` | DATETIME | First request timestamp |

**Guest Limits** (Lower to encourage signup):
- EML: 2/day
- Link: 5/day
- File: 3/day
- **AI chat**: Requires login (no guest access)

---

### Database Relationships

```
users (1) ——< (N) sessions
   └─ One user can have multiple active sessions
```

**Foreign Keys**:
- `sessions.user_id` → `users.id` (CASCADE DELETE)

**Indexes**:
- `users.email` - Unique index for fast login lookup
- `sessions.token` - Unique index for session validation
- `sessions.user_id` - Index for user session queries
- `oauth_states.state` - Unique index for OAuth validation
- `guest_rate_limits.ip_address` - Index for IP lookup

---

### Database File

**Location**: `backend/phishcheck.db` (SQLite)  
**ERD Diagram**: `backend/phishcheck.erd` (Visual schema)  
**SQL Schema**: `schema.sql` (Table definitions)

**Initialization**: Automatic on first run via SQLAlchemy models

---

## 🎨 Design Patterns

### Backend
- **Layered Architecture**: API → Services → Models
- **Dependency Injection**: FastAPI dependencies for auth/rate limits
- **Provider Pattern**: External API clients in `providers/`
- **Pipeline Pattern**: Analysis pipeline orchestration
- **Service Layer**: Business logic separated from API

### Frontend
- **Composition API**: Modern Vue 3 patterns
- **Composables**: Reusable hooks in `hooks/`
- **Component-Based**: Shadcn/vue components
- **State Management**: Centralized Pinia stores
- **Reactive Programming**: Refs and computed properties

---

## 🔐 Security Features

- ✨ **OWASP Security Headers** (NEW)
- bcrypt password hashing
- httpOnly session cookies
- Email domain validation (MX records)
- Rate limiting (per-user and per-IP)
- Input validation (Pydantic + enum)
- ✨ Enum validation for parameters (NEW)
- HTML sanitization (nh3)
- CORS configuration
- Request ID tracing
- SQL injection prevention (ORM)

---

## 📝 Configuration Files

| File | Purpose |
|------|---------|
| `.env.example` | Backend environment variables template |
| `requirements.txt` | Python dependencies |
| `package.json` | Node.js dependencies |
| `tailwind.config.ts` | Tailwind CSS configuration |
| `vite.config.ts` | Vite build configuration |
| `components.json` | Shadcn/vue components config |

---

## 🚀 Key Improvements (Latest)

1. ✅ **Constants Extraction** - `constants.py` for all config values
2. ✅ **Security Headers** - OWASP-compliant middleware
3. ✅ **Enum Validation** - Type-safe URLscan visibility parameter
4. ✅ **Enhanced Documentation** - This detailed structure guide

---

**Last Updated**: December 15, 2025  
**Version**: 1.0.0
