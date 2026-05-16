from pydantic_settings import BaseSettings
from pydantic import SecretStr

class Settings(BaseSettings):
    # Налаштування проєкту
    PROJECT_NAME: str = "OSINT Threat Analyzer"
    VERSION: str = "1.0.0"
    
    # Бази даних та брокери (Розділ 2.2)
    # Використовуємо asyncpg для високонавантаженого асинхронного доступу
    POSTGRES_URL: str = "postgresql+asyncpg://osint_user:secure_password@localhost:5432/osint_db"
    REDIS_URL: str = "redis://localhost:6379/0"
    
    # API Ключі (захищені типи)
    GEMINI_API_KEY: SecretStr
    SHODAN_API_KEY: SecretStr
    CENSYS_API_ID: str | None = None
    CENSYS_API_SECRET: SecretStr | None = None

    # Налаштування FAISS
    FAISS_INDEX_PATH: str = "./faiss_index"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

# Глобальний об'єкт налаштувань
settings = Settings()