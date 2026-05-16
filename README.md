# osint-diploma
Розробка автоматизованого OSINT-застосунку  для аналізу векторів загроз для компаній
## Запуск проекту

### 1. Запуск інфраструктури
Перед запуском сервісів підніміть необхідне оточення (бази даних, брокери повідомлень тощо) через Docker:
```bash
docker-compose up -d
```

### 2. Запуск серверної частини (Backend)

**Термінал 1: Запуск API Gateway (FastAPI)**
```bash
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

**Термінал 2: Запуск оркестратора завдань (Celery Worker)**

*Для Linux/Mac:*
```bash
celery -A core.celery_app worker --loglevel=info
```

*Для Windows (вимагає додаткового прапорця `--pool=solo`):*
```bash
celery -A core.celery_app worker --loglevel=info --pool=solo
```

### 3. Запуск клієнтської частини (GUI)

**Термінал 3: Встановлення залежностей інтерфейсу та запуск клієнта**
```bash
pip install PyQt6 requests
python client.py
```

## Структура проекту

```text
osint-diploma/
├── main.py                 # Точка входу FastAPI (API Gateway)
├── gui.py                  # GUI для зручної взаємодії з API
├── core/
│   ├── config.py           # Налаштування середовища
│   ├── database.py         # Підключення до PostgreSQL
│   ├── faiss_store.py      # Підключення та логіка векторної бази FAISS
│   └── celery_app.py       # Ініціалізація Celery (Redis)
├── models/
│   ├── schemas.py          # Pydantic моделі (валідація)
│   └── db_models.py        # SQLAlchemy моделі (таблиці MISP, JSONB)
├── agents/
│   ├── llm_setup.py        # Інтеграція Gemini 3.1 Flash
│   └── langgraph_flow.py   # Багатоагентна система (Scout, Enricher, Evaluator)
├── ml/
│   ├── models.py           # GBDT та DBSCAN (scikit-learn)
│   ├── analysis.py         # Оцінка кіберризиків та ризиків конфіденційності, виявлення Shadow IT
│   └── risk_calc.py        # Математична модель оцінки ризиків (CRQ)
├── services/
│   ├── osint_gather.py     # Пасивний збір (Shodan, Censys, GitHub)
│   ├── normalization.py    # Парсинг, SHA-256 дедуплікація, LSH
│   └── tasks.py            # Збір, нормалізація, запис у БД та виклик агентів
└── utils/
    └── algorithms.py       # Token Bucket, Exponential Backoff
```

