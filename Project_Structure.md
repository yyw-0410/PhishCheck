# PhishCheck - Detailed Project Structure

**Type**: Full-Stack Phishing Detection Platform  
**Backend**: FastAPI (Python 3.11+)  
**Frontend**: Vue 3 + TypeScript + Tailwind CSS

---

## Complete Directory Structure

This tree focuses on source and documentation paths. Generated folders (node_modules, dist, venv, __pycache__) are omitted.

```
PhishCheck/
|-- backend/                          # Python FastAPI backend
|   |-- app/
|   |   |-- api/
|   |   |   |-- routers/
|   |   |   |   |-- __init__.py
|   |   |   |   |-- dependencies.py   # Auth context, rate limit checks
|   |   |   |   |-- email.py          # POST /api/v1/analysis/email
|   |   |   |   |-- link.py           # POST /api/v1/analysis/link
|   |   |   |   |-- file.py           # POST /api/v1/analysis/file
|   |   |   |   |-- ai_agent.py       # POST /api/v1/ai (AI chat)
|   |   |   |   |-- auth.py           # Auth endpoints (login, register, OAuth)
|   |   |   |   |-- health.py         # GET /api/v1/health (health check)
|   |   |   |   |-- utils.py          # Utility helpers
|   |   |   |-- __init__.py
|   |   |   |-- routes.py             # Router aggregation
|   |   |-- core/
|   |   |   |-- __init__.py
|   |   |   |-- config.py             # Environment settings (Settings class)
|   |   |   |-- constants.py          # Centralized constants
|   |   |   |-- database.py           # SQLite initialization
|   |   |   |-- logging.py            # Structured logging
|   |   |   |-- rate_limit.py         # SlowAPI rate limiter
|   |   |   |-- security_headers.py   # OWASP security headers middleware
|   |   |-- services/
|   |   |   |-- __init__.py
|   |   |   |-- analysis_pipeline.py  # Email analysis orchestration
|   |   |   |-- auth_service.py       # Auth + session + rate limits
|   |   |   |-- email_parser.py       # EML file parsing
|   |   |   |-- email_service.py      # Email verification (Resend API)
|   |   |   |-- oauth_service.py      # OAuth flow (Google, Microsoft)
|   |   |   |-- qr_scanner.py         # QR code detection in images
|   |   |   |-- rag_service.py        # AI chat with RAG (Gemini)
|   |   |   |-- threat_intel.py       # Threat intel orchestration
|   |   |   |-- providers/            # External API clients
|   |   |       |-- __init__.py
|   |   |       |-- base.py           # Base provider class
|   |   |       |-- virustotal.py     # VirusTotal API
|   |   |       |-- urlscan.py        # URLscan.io API
|   |   |       |-- sublime.py        # Sublime Security MDM API
|   |   |       |-- ipqs.py           # IP Quality Score API
|   |   |       |-- hybrid_analysis.py # Hybrid Analysis sandbox
|   |   |-- models/
|   |   |   |-- __init__.py
|   |   |   |-- user.py               # User, Session, OAuthState, GuestRateLimit models
|   |   |-- schemas/
|   |   |   |-- __init__.py
|   |   |   |-- analysis.py           # CombinedAnalysisResult
|   |   |   |-- attachment_analysis.py # Attachment schemas
|   |   |   |-- auth.py               # UserLogin, UserRegister, AuthResponse
|   |   |   |-- chat.py               # ChatRequest, ChatResponse
|   |   |   |-- email.py              # ParsedEmail, EmailHeader, EmailBody
|   |   |   |-- link_analysis.py      # LinkAnalysisResult
|   |   |   |-- mdm.py                # Sublime MDM schemas
|   |   |   |-- threat_intel.py       # ThreatIntelReport, VT/URLscan schemas
|   |   |-- utils/
|   |   |   |-- __init__.py
|   |   |   |-- crypto.py             # Token encryption/decryption
|   |   |   |-- datetime.py           # Timezone utilities
|   |   |-- knowledge/
|   |   |   |-- email_analysis.md     # Email analysis guide
|   |   |   |-- file_analysis.md      # File analysis guide
|   |   |   |-- link_analysis.md      # Link analysis guide
|   |   |   |-- privacy_summary.md    # Privacy policy summary
|   |   |   |-- terms_summary.md      # Terms of service summary
|   |   |   |-- user_guide.md         # User guide
|   |   |-- __init__.py
|   |   |-- main.py                   # FastAPI application factory
|   |-- tests/                        # Backend tests (pytest)
|   |   |-- __init__.py
|   |   |-- test_app.py
|   |   |-- test_auth_service.py
|   |   |-- test_email_parser.py
|   |   |-- test_sublime_client.py
|   |   |-- test_sublime_mdm.py
|   |-- scripts/                      # Utility scripts
|   |   |-- cleanup.py                # Cleanup script (also runs at midnight)
|   |   |-- run_sublime.py            # Test Sublime API
|   |   |-- filter_sublime_hits.py    # Parse Sublime responses
|   |   |-- api_test.py               # API testing
|   |-- .env.example                  # Environment variables template
|   |-- requirements.txt              # Python dependencies
|   |-- phishcheck.db                 # SQLite database
|   |-- phishcheck.erd                # Database ERD
|   |-- main.py                       # Compatibility import for uvicorn
|-- frontend/                         # Vue 3 + TypeScript frontend
|   |-- src/
|   |   |-- views/                    # Page components
|   |   |   |-- AnalysisView.vue
|   |   |   |-- LinkAnalysisView.vue
|   |   |   |-- FileAnalysisView.vue
|   |   |   |-- ChatView.vue
|   |   |   |-- LoginView.vue
|   |   |   |-- SignupView.vue
|   |   |   |-- AccountView.vue
|   |   |   |-- EmailVerificationView.vue
|   |   |   |-- OAuthCallback.vue
|   |   |   |-- NotificationsView.vue
|   |   |   |-- BillingView.vue
|   |   |   |-- FeedbackView.vue
|   |   |   |-- SupportView.vue
|   |   |   |-- PrivacyPolicyView.vue
|   |   |   |-- TermsOfServiceView.vue
|   |   |   |-- NotFound.vue
|   |   |-- components/               # Reusable components
|   |   |   |-- auth/
|   |   |   |   |-- LoginForm.vue
|   |   |   |   |-- SignupForm.vue
|   |   |   |   |-- VerificationBanner.vue
|   |   |   |-- chat/
|   |   |   |   |-- AIChatWidget.vue
|   |   |   |-- layout/
|   |   |   |   |-- AppSidebar.vue
|   |   |   |   |-- FloatingActions.vue
|   |   |   |   |-- NavMain.vue
|   |   |   |   |-- NavProjects.vue
|   |   |   |   |-- NavSecondary.vue
|   |   |   |   |-- NavUser.vue
|   |   |   |   |-- TopBar.vue
|   |   |   |-- icons/
|   |   |   |   |-- IconGoogle.vue
|   |   |   |   |-- IconMicrosoft.vue
|   |   |   |-- ui/                   # Shadcn/vue components
|   |   |       |-- JsonTreeNode.vue
|   |   |       |-- avatar/
|   |   |       |-- badge/
|   |   |       |-- breadcrumb/
|   |   |       |-- button/
|   |   |       |-- card/
|   |   |       |-- collapsible/
|   |   |       |-- dialog/
|   |   |       |-- dropdown-menu/
|   |   |       |-- field/
|   |   |       |-- input/
|   |   |       |-- label/
|   |   |       |-- resizable/
|   |   |       |-- scroll-to-top/
|   |   |       |-- separator/
|   |   |       |-- sheet/
|   |   |       |-- sidebar/
|   |   |       |-- skeleton/
|   |   |       |-- switch/
|   |   |       |-- tooltip/
|   |   |-- stores/                   # Pinia state management
|   |   |   |-- analysis.ts
|   |   |   |-- auth.ts
|   |   |   |-- chat.ts
|   |   |   |-- api.ts
|   |   |   |-- sidebar.ts
|   |   |-- hooks/                    # Vue composables
|   |   |   |-- useAnalysisState.ts
|   |   |   |-- useThreatIntel.ts
|   |   |   |-- useParsedEmail.ts
|   |   |   |-- useSublimeInsights.ts
|   |   |   |-- useViewport.ts
|   |   |-- services/                 # API layer
|   |   |   |-- api.ts
|   |   |-- types/                    # TypeScript types
|   |   |   |-- analysis.ts
|   |   |-- utils/                    # Utility functions
|   |   |   |-- screenshotUtils.ts
|   |   |-- lib/                      # Library helpers
|   |   |   |-- utils.ts
|   |   |-- assets/                   # Static assets
|   |   |   |-- base.css
|   |   |   |-- main.css
|   |   |   |-- Logo.svg
|   |   |-- router/
|   |   |   |-- index.ts              # Routes + guards
|   |   |-- App.vue
|   |   |-- main.ts
|   |-- public/                       # Public assets
|   |   |-- FullLogo_Transparent_NoBuffer.ico
|   |-- e2e/                          # E2E tests (Playwright)
|   |   |-- vue.spec.ts
|   |-- components.json               # Shadcn config
|   |-- env.d.ts                      # Environment types
|   |-- index.html                    # HTML entry
|   |-- package.json                  # Node dependencies
|   |-- package-lock.json             # Locked dependencies
|   |-- tailwind.config.ts            # Tailwind configuration
|   |-- tsconfig.json                 # TypeScript config
|   |-- tsconfig.app.json             # App TypeScript config
|   |-- vite.config.ts                # Vite configuration
|   |-- vitest.config.ts              # Vitest config (unit tests)
|-- docs/
|   |-- uml/
|   |   |-- use-case.puml             # UML use case diagram (PlantUML)
|-- Project_Structure.md              # This file
|-- README.md                         # Project README
|-- schema.sql                        # Database schema SQL
|-- start.bat                         # Quick start script
```

---

## Key Files Explained

### Backend Core Files

| File | Purpose |
|------|---------|
| `app/main.py` | FastAPI app factory, middleware, scheduled tasks (APScheduler) |
| `main.py` | Compatibility import for `uvicorn` (re-exports `app`) |
| `core/config.py` | Loads environment variables, validates settings |
| `core/constants.py` | Centralized constants (file sizes, limits, timeouts) |
| `core/security_headers.py` | OWASP security headers middleware |
| `core/database.py` | SQLite initialization, table creation |
| `core/logging.py` | Structured logging (JSON in prod, colored in dev) |
| `core/rate_limit.py` | SlowAPI configuration for rate limiting |

### Backend Services

| Service | Purpose |
|---------|---------|
| `analysis_pipeline.py` | Orchestrates email analysis (parsing + Sublime + threat intel) |
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
| `file.py` | `POST /api/v1/analysis/file` | Analyze file or hash |
| `ai_agent.py` | `POST /api/v1/ai` | AI chat assistant |
| `auth.py` | `/api/auth/*` | Authentication, OAuth, email verification |
| `health.py` | `GET /api/v1/health` | Health check endpoint |
| `utils.py` | - | Helper functions |
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
| `AccountView.vue` | User account settings |
| `EmailVerificationView.vue` | Email verification page |
| `auth/LoginForm.vue` | Email/password login form |
| `auth/SignupForm.vue` | Registration form with validation |
| `auth/VerificationBanner.vue` | Email verification reminder banner |
| `chat/AIChatWidget.vue` | AI chat widget component |
| `layout/AppSidebar.vue` | Main sidebar navigation |
| `layout/FloatingActions.vue` | Floating action buttons |
| `layout/TopBar.vue` | Top navigation bar |

### Frontend Stores (Pinia)

| Store | Purpose |
|-------|---------|
| `analysis.ts` | Analysis results, loading state, file data |
| `auth.ts` | User session, login/logout, profile |
| `chat.ts` | AI chat messages, streaming responses |
| `api.ts` | API client configuration |
| `sidebar.ts` | Sidebar open/close state |

---

## API Endpoints

### Analysis APIs

```
POST   /api/v1/analysis/email         - Analyze .eml file
POST   /api/v1/analysis/link          - Analyze URL
POST   /api/v1/analysis/file          - Analyze file or hash
GET    /api/v1/analysis/urlscan/{id}  - Refresh URLscan result
POST   /api/v1/analysis/virustotal/url - Scan URL with VirusTotal
```

### Authentication APIs

```
POST   /api/auth/register             - Email/password registration
POST   /api/auth/login                - Email/password login
POST   /api/auth/logout               - Logout (delete session)
GET    /api/auth/me                   - Get current user
GET    /api/auth/me/analysis-limit    - Get remaining analysis limits
POST   /api/auth/validate             - Validate session token
GET    /api/auth/verify-email         - Verify email with token
POST   /api/auth/resend-verification  - Resend verification email
POST   /api/auth/disconnect-oauth     - Disconnect OAuth

# OAuth
GET    /api/auth/google/login         - Initiate Google OAuth
GET    /api/auth/google/callback      - Google OAuth callback
GET    /api/auth/microsoft/login      - Initiate Microsoft OAuth
GET    /api/auth/microsoft/callback   - Microsoft OAuth callback
```

### AI APIs

```
POST   /api/v1/ai                     - Chat with AI assistant
GET    /api/v1/ai/suggestions         - Get chat suggestions
GET    /api/v1/ai/analysis-questions  - Get analysis-specific suggestions
POST   /api/v1/ai/recommendation      - Get AI recommendation from analysis
```

---

## Technology Stack

### Backend
- **Framework**: FastAPI 0.115+
- **Python**: 3.11+
- **Database**: SQLite (ORM: SQLAlchemy)
- **Authentication**: bcrypt, OAuth 2.0
- **Email**: Resend API
- **AI**: Google Gemini
- **Rate Limiting**: SlowAPI
- **Scheduler**: APScheduler (background tasks)
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
- **Hybrid Analysis** - Sandbox file analysis
- **Google Gemini** - AI chat assistant
- **Resend** - Email verification service

---

## Database Schema

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
| `user_id` | INTEGER | Foreign key -> users.id |
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

**Guest Limits** (Lower to encourage signup):
- EML: 2/day
- Link: 5/day
- File: 3/day
- **AI chat**: Requires login (no guest access)

---

### Database Relationships

```
users (1) -- (N) sessions
```

**Foreign Keys**:
- `sessions.user_id` -> `users.id` (CASCADE DELETE)

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

## UML Use Case Diagram

The use case diagram is available in PlantUML format: `docs/uml/use-case.puml`.

---

## Design Patterns

### Backend
- **Layered Architecture**: API -> Services -> Models
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

## Security Features

- OWASP security headers
- bcrypt password hashing
- httpOnly session cookies
- Email domain validation (MX records)
- Rate limiting (per-user and per-IP)
- Input validation (Pydantic + enum)
- HTML sanitization (nh3)
- CORS configuration
- Request ID tracing
- SQL injection prevention (ORM)

---

## Configuration Files

| File | Purpose |
|------|---------|
| `backend/.env.example` | Backend environment variables template |
| `backend/requirements.txt` | Python dependencies |
| `frontend/package.json` | Node.js dependencies |
| `frontend/tailwind.config.ts` | Tailwind CSS configuration |
| `frontend/vite.config.ts` | Vite build configuration |
| `frontend/components.json` | Shadcn/vue components config |

---

## Key Improvements (Latest)

1. Constants extraction (`core/constants.py`) for shared limits and sizes
2. Security headers middleware (OWASP defaults)
3. Enum validation for URLscan visibility parameter
4. Enhanced documentation (this structure guide)
5. Automatic cleanup - scheduled midnight cleanup (APScheduler)
   - Guest rate limits: deleted daily (records older than 1 day)
   - Unverified accounts: deleted after 7 days

---

**Last Updated**: December 18, 2025  
**Version**: 1.0.0
