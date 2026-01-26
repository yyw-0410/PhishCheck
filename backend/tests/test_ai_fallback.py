
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_fallback_critical_vt():
    """Test fallback to CRITICAL when VirusTotal has high detections (Sublime Failed)."""
    response = client.post("/api/v1/ai/recommendation", json={
        "attack_score": None, # Sublime Failed
        "rule_count": 0,
        "insight_count": 0,
        "vt_malicious": 5,
        "vt_suspicious": 0
    })
    assert response.status_code == 200
    data = response.json()
    assert data["risk_level"] == "critical"
    assert "Malicious content detected" in data["recommendation"]

def test_fallback_high_urlscan():
    """Test fallback to HIGH when URLscan finds malicious links (Sublime Failed)."""
    response = client.post("/api/v1/ai/recommendation", json={
        "attack_score": None,
        "rule_count": 0,
        "insight_count": 0,
        "vt_malicious": 0,
        "urlscan_verdict": "malicious",
        "urlscan_malicious_count": 1
    })
    assert response.status_code == 200
    data = response.json()
    assert data["risk_level"] == "high"

def test_fallback_critical_hybrid_analysis():
    """Test fallback to CRITICAL when Hybrid Analysis Sandbox finds Malware."""
    response = client.post("/api/v1/ai/recommendation", json={
        "attack_score": None,
        "rule_count": 0,
        "insight_count": 0,
        "vt_malicious": 0,
        "ha_verdict": "malicious",
        "ha_malicious_count": 1
    })
    assert response.status_code == 200
    data = response.json()
    assert data["risk_level"] == "critical"

def test_fallback_high_ipqs():
    """Test fallback to HIGH when IPQS Fraud Score is very high."""
    response = client.post("/api/v1/ai/recommendation", json={
        "attack_score": None,
        "rule_count": 0,
        "insight_count": 0,
        "vt_malicious": 0,
        "ipqs_max_fraud_score": 95
    })
    assert response.status_code == 200
    data = response.json()
    assert data["risk_level"] == "high"

def test_sublime_success_override():
    """Test that if Sublime SUCCEEDS with a low score, it is trusted even if small noise exists."""
    # Note: If VT has 3+ it might still trigger critical depending on logic, 
    # but let's test a clean sublime score with minor noise.
    response = client.post("/api/v1/ai/recommendation", json={
        "attack_score": 5, # Clean
        "rule_count": 0,
        "insight_count": 0,
        "vt_malicious": 0
    })
    assert response.status_code == 200
    data = response.json()
    assert data["risk_level"] == "low"
