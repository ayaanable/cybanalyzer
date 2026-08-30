from app.services.store import load_demo
from app.analysis.engine import analyze
from app.schemas.environment import Environment

def test_discovers_ranked_paths():
    result = analyze(load_demo(), "internet", "db01")
    assert len(result["paths"]) >= 2
    assert result["paths"] == sorted(result["paths"], key=lambda p: p["risk_score"], reverse=True)
    assert result["paths"][0]["risk_score"] >= 75

def test_removing_required_vulnerability_eliminates_web_paths():
    environment = load_demo()
    data = environment.model_dump()
    data["vulnerabilities"] = [v for v in data["vulnerabilities"] if v["id"] != "v1"]
    result = analyze(Environment.model_validate(data), "internet", "db01")
    assert result["paths"] == []
