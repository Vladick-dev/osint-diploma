from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from core.config import settings

# Створення асинхронного рушія бази даних
# pool_size та max_overflow налаштовані для високонавантаженого корпоративного середовища
engine = create_async_engine(
    settings.POSTGRES_URL,
    echo=False,
    future=True,
    pool_size=20,
    max_overflow=10
)

# Фабрика асинхронних сесій
AsyncSessionLocal = async_sessionmaker(
    bind=engine, 
    class_=AsyncSession, 
    expire_on_commit=False
)

# Базовий клас для створення моделей (таблиць) SQLAlchemy
Base = declarative_base()

async def get_db():
    """
    Dependency Injection для FastAPI.
    Забезпечує транзакційну цілісність: відкриває сесію на час запиту і закриває після.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()