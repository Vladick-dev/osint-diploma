import asyncio
from core.database import engine, Base

# КРИТИЧНО ВАЖЛИВО: Імпортуємо всі моделі, щоб SQLAlchemy побачила їх структуру
from models.db_models import Organization, ScanTask, DigitalAsset, Vulnerability, RiskAssessment

async def setup_database():
    print("[*] Підключення до PostgreSQL...")
    async with engine.begin() as conn:
        # Створюємо всі таблиці за нашими схемами
        await conn.run_sync(Base.metadata.create_all)
    print("[+] Усі таблиці (ScanTask, DigitalAsset, RiskAssessment тощо) успішно створені!")

if __name__ == "__main__":
    asyncio.run(setup_database())
