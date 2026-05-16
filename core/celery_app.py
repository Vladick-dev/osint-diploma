from celery import Celery
from core.config import settings

# Ініціалізація Celery з In-Memory брокером Redis (Розділ 2.2)
celery_app = Celery(
    "osint_worker",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    # Автоматичний пошук завдань у вказаних модулях
    include=['services.tasks'] 
)

# Оптимізація конфігурації Celery для OSINT-завдань
celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='Europe/Kyiv',
    enable_utc=True,
    
    # Налаштування стійкості (Circuit Breaker / Exponential Backoff)
    task_acks_late=True,               # Завдання вважається виконаним тільки після успішного завершення
    task_reject_on_worker_lost=True,   # Повернення завдання в чергу, якщо worker впав
    worker_prefetch_multiplier=1,      # Справедливий розподіл завдань (по 1 на worker)
    
    # Обмеження часу виконання (наприклад, 1 година на повний цикл розвідки)
    task_time_limit=3600,
    task_soft_time_limit=3500
)

if __name__ == '__main__':
    celery_app.start()