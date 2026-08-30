from pathlib import Path
from app.schemas.environment import Environment

DEMO_PATH = Path(__file__).parents[3] / "demo" / "enterprise_environment.json"
_environments: dict[str, Environment] = {}

def load_demo() -> Environment: return Environment.model_validate_json(DEMO_PATH.read_text())
def initialise() -> None: _environments.setdefault("demo", load_demo())
def list_environments() -> list[Environment]: return list(_environments.values())
def get_environment(environment_id: str) -> Environment | None: return _environments.get(environment_id)
def save_environment(environment: Environment) -> Environment:
    _environments[environment.id] = environment
    return environment
def delete_environment(environment_id: str) -> bool: return _environments.pop(environment_id, None) is not None
