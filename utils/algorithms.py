import time
import random
import asyncio

async def exponential_backoff(attempt: int, base_delay: float = 1.0):
    """
    Адаптивна затримка для уникнення блокувань (Rate Limiting).
    Розділ 2.3: wait_time = base_delay * 2^attempt + jitter
    """
    jitter = random.uniform(0.1, 0.5)
    wait_time = (base_delay * (2 ** attempt)) + jitter
    await asyncio.sleep(wait_time)
    return wait_time

class TokenBucket:
    """Алгоритм маркерного кошика (Token Bucket) для Rate Limiting"""
    def __init__(self, capacity: int, fill_rate: float):
        self.capacity = capacity
        self.tokens = capacity
        self.fill_rate = fill_rate
        self.last_update = time.time()

    def consume(self, tokens: int = 1) -> bool:
        now = time.time()
        self.tokens += (now - self.last_update) * self.fill_rate
        self.tokens = min(self.capacity, self.tokens)
        self.last_update = now
        
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False