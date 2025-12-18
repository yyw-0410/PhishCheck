# PhishCheck

**Email & URL Phishing Analysis Platform**

A full-stack phishing detection platform that analyzes emails and URLs using multiple threat intelligence providers.

## Features

- 📧 **Email Analysis**: Upload .eml files for comprehensive phishing detection
- 🔗 **Link Analysis**: Scan URLs with VirusTotal, URLscan.io, and Sublime ML
- 📁 **File Analysis**: Check file hashes against threat databases
- 🤖 **AI Assistant**: Get AI-powered recommendations and explanations
- 🔐 **Authentication**: User accounts with OAuth (Google/Microsoft)
- 📊 **Rate Limiting**: Guest and user-based daily limits

## Tech Stack

| Layer | Technology |
|-------|------------|
| Backend | FastAPI (Python 3.11+) |
| Frontend | Vue 3 + TypeScript + Vite |
| Database | SQLite |
| Styling | Tailwind CSS + Shadcn/vue |
| AI | Google Gemini API |

## Quick Start

### Prerequisites
- Python 3.11+
- Node.js 18+
- API keys (see `.env.example`)

### Installation

```bash
# Clone repository
git clone https://github.com/yourusername/PhishCheck.git
cd PhishCheck

# Backend setup
cd backend
pip install -r requirements.txt

# Create your .env file with your own API keys
# See .env.example for required variables
touch .env  # or manually create the file
# Then edit .env and add your API keys

uvicorn app.main:app --reload

# Frontend setup (new terminal)
cd frontend
npm install
npm run dev
```

> **⚠️ SECURITY WARNING:**  
> - **Create your own `.env` file** with your actual API keys
> - **NEVER commit `.env`** to Git - it contains sensitive credentials
> - Only `.env.example` (with placeholder values) should be in version control
> - Keep your API keys secure and private

### Running Both
```bash
# From root directory
./start.bat  # Windows
```

## API Documentation
📚 **http://localhost:8000/api/docs** - Modern interactive API documentation

## External Integrations

| Service | Purpose |
|---------|---------|
| Sublime Security | Email analysis + ML link detection |
| VirusTotal | URL/domain/file reputation |
| URLscan.io | URL scanning + screenshots |
| IPQS | IP reputation |
| Hybrid Analysis | Sandbox file analysis |
| Google Gemini | AI chat assistant |
| Resend | Email verification delivery |

## Third-Party Acknowledgments

### Backend Libraries
PhishCheck is built using the following open-source Python libraries:
- **FastAPI** - Modern web framework (MIT License)
- **SQLAlchemy** - SQL toolkit and ORM (MIT License)
- **bcrypt** - Password hashing (Apache 2.0 License)
- **httpx** - HTTP client library (BSD License)
- **Pydantic** - Data validation (MIT License)
- **nh3** - HTML sanitization (MIT License)
- **SlowAPI** - Rate limiting (MIT License)
- **APScheduler** - Background task scheduling (MIT License)
- **Pillow** - Image processing (HPND License)
- **pyzbar** - QR code detection (MIT License)

### Frontend Libraries
Frontend built with modern JavaScript/TypeScript libraries:
- **Vue.js 3** - Progressive JavaScript framework (MIT License)
- **TypeScript** - Typed superset of JavaScript (Apache 2.0 License)
- **Tailwind CSS** - Utility-first CSS framework (MIT License)
- **Shadcn/vue** - Re-usable component library (MIT License)
- **Pinia** - State management (MIT License)
- **Vue Router** - Official routing library (MIT License)

### External Services
Integrated with the following security and infrastructure services:
- **Sublime Security MDM** - Advanced email threat detection
- **VirusTotal** - Multi-engine malware scanning service
- **URLscan.io** - Automated website scanner
- **IP Quality Score (IPQS)** - Fraud prevention and threat detection
- **Google Gemini AI** - Advanced language model for AI assistance
- **Resend** - Transactional email delivery platform

*All services used comply with their respective terms of service and are used within free tier limits where applicable.*

## Project Structure

See [Project_Structure.md](Project_Structure.md) for detailed organization.

```
PhishCheck/
├── backend/          # FastAPI Python API
│   ├── app/
│   │   ├── api/      # API routers
│   │   ├── core/     # Config, database, logging
│   │   ├── services/ # Business logic
│   │   └── schemas/  # Pydantic models
│   └── tests/
│
└── frontend/         # Vue 3 SPA
    └── src/
        ├── views/    # Page components
        ├── stores/   # Pinia state
        └── hooks/    # Composables
```

## Testing

### Backend Tests (23 tests ✅)

```bash
cd backend

# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov-report=html

# Run specific test file
pytest tests/test_auth_service.py -v
```

**Test Coverage**:
- ✅ API endpoints (health check, auth)
- ✅ Authentication service (password hashing, sessions, email validation, OAuth)
- ✅ Email parser (multipart emails, HTML sanitization)
- ✅ Sublime API integration
- ✅ Schema validation

### Frontend Tests (Infrastructure configured)

```bash
cd frontend

# Test infrastructure configured (minimal test implementation)
npm run test:unit  # Vitest
npm run test:e2e   # Playwright

# Run linter
npm run lint
```

**Note**: Frontend test infrastructure (Vitest, Playwright) is configured for future development. Primary testing focus has been on backend logic given the prototype nature of this project.

## Future Enhancements

Potential improvements and features for future development:

- Browser fingerprinting for enhanced guest rate limiting
- Email inbox integration with auto-scanning (Gmail/Outlook plugin)
- Push notifications for real-time threat alerts
- Analysis history storage and retrieval
- Batch analysis for multiple files/URLs
- PDF report generation and export
- Email sandbox preview for safe HTML rendering
- Team collaboration and shared workspaces
- API webhooks for external integrations
- ~~Scheduled automated scanning~~ ✅ (Implemented: midnight cleanup)
- Subscription billing system (if monetizing)

## License

MIT License - see [LICENSE](LICENSE) for details.

---

*Final Year Project - December 2025*