from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="BURTGEL_")

    api_host: str = "0.0.0.0"
    api_port: int = 8001
    db_path: Path = BASE_DIR / "data" / "burtgel.db"
    secret_key: str = "change-me-before-production"


settings = Settings()
