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

## License

MIT License - see [LICENSE](LICENSE) for details.

---

*Final Year Project - December 2025*