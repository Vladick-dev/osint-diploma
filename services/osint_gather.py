import asyncio
import aiohttp
import random
import time
import socket
from typing import List, Dict, Any
from core.config import settings

class TokenBucket:
    """Алгоритм маркерного кошика (Token Bucket) для запобігання блокуванню за IP"""
    def __init__(self, capacity: int, fill_rate: float):
        self.capacity = capacity
        self.tokens = capacity
        self.fill_rate = fill_rate
        self.last_update = time.monotonic()

    def consume(self, tokens: int = 1) -> bool:
        now = time.monotonic()
        self.tokens += (now - self.last_update) * self.fill_rate
        self.tokens = min(self.capacity, self.tokens)
        self.last_update = now
        
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False

async def adaptive_fetch(url: str, headers: dict, bucket: TokenBucket, max_retries: int = 3) -> dict | None:
    """Асинхронний запит з адаптивною затримкою та обробкою таймаутів"""
    base_delay = 1.0
    # Збільшуємо таймаут до 30 секунд для повільних OSINT-сервісів
    timeout = aiohttp.ClientTimeout(total=30)
    
    async with aiohttp.ClientSession(timeout=timeout) as session:
        for attempt in range(max_retries):
            while not bucket.consume(1):
                await asyncio.sleep(0.1)
                
            try:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        if 'application/json' in response.headers.get('Content-Type', ''):
                            return await response.json()
                        return {"text_data": await response.text()}
                    
                    elif response.status in (429, 502, 503, 504): # Обробка перевантажень сервера
                        jitter = random.uniform(0.1, 0.5)
                        wait_time = (base_delay * (2 ** attempt)) + jitter
                        print(f"[*] Сервер перевантажений (статус {response.status}). Очікування {wait_time:.1f}с...")
                        await asyncio.sleep(wait_time)
                    else:
                        response.raise_for_status()
                        
            except (aiohttp.ClientError, asyncio.TimeoutError, TimeoutError) as e:
                print(f"[!] Помилка з'єднання ({e}). Спроба {attempt + 1} з {max_retries}...")
                await asyncio.sleep(base_delay * (2 ** attempt))
                
        return None

class OSINTCollector:
    def __init__(self):
        self.shodan_key = settings.SHODAN_API_KEY.get_secret_value()
        self.shodan_bucket = TokenBucket(capacity=5, fill_rate=1.0)
        self.crtsh_bucket = TokenBucket(capacity=3, fill_rate=0.5)

    async def gather_subdomains(self, domain: str) -> List[str]:
        """Пасивний DNS-аналіз з автоматичним резервуванням джерел (Failover)"""
        print(f"[*] Збір субдоменів для {domain} через crt.sh...")
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json"
        }
        
        subdomains = {domain} # Завжди додаємо головний домен
        
        # СПРОБА 1: crt.sh
        url_crt = f"https://crt.sh/?q=%.{domain}&output=json"
        data = await adaptive_fetch(url_crt, headers, self.crtsh_bucket)
        
        if data and isinstance(data, list):
            for entry in data:
                name = entry.get('name_value', '').lower()
                if name and not name.startswith('*'):
                    for sub in name.split('\n'):
                        subdomains.add(sub.strip())
        else:
            # СПРОБА 2: Якщо crt.sh лежить (502), використовуємо HackerTarget
            print(f"[-] crt.sh не відповів. Перемикання на резервне джерело HackerTarget...")
            url_ht = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            
            # HackerTarget повертає звичайний текст (CSV), а не JSON
            ht_data = await adaptive_fetch(url_ht, headers, self.crtsh_bucket)
            
            if ht_data and isinstance(ht_data, dict) and "text_data" in ht_data:
                lines = ht_data["text_data"].split('\n')
                for line in lines:
                    if ',' in line:
                        sub = line.split(',')[0].strip().lower()
                        if sub.endswith(domain):
                            subdomains.add(sub)

        print(f"[*] Знайдено {len(subdomains)} унікальних доменів/субдоменів.")
        return list(subdomains)

    async def gather_host_info(self, ip_or_domain: str) -> Dict[str, Any]:
        """Збір даних через безкоштовний сервіс InternetDB"""
        try:
            loop = asyncio.get_event_loop()
            ip_address = await loop.run_in_executor(None, socket.gethostbyname, ip_or_domain)
        except socket.gaierror:
            return {}

        url = f"https://internetdb.shodan.io/{ip_address}"
        data = await adaptive_fetch(url, {}, self.shodan_bucket)
        
        # Якщо портів немає, просто повертаємо чистий IP для графа
        if not data or "error" in data:
            return {
                "ip": ip_address,
                "ports":[],
                "hostnames": [ip_or_domain],
                "vulns":[],
                "raw_data": {}
            }
            
        return {
            "ip": data.get("ip", ip_address),
            "ports": data.get("ports",[]),
            "hostnames": data.get("hostnames", [ip_or_domain]),
            "vulns": data.get("vulns",[]),
            "raw_data": data
        }

    async def run_full_recon(self, target_domain: str) -> Dict[str, Any]:
        # ... (залишається без змін) ...
        subdomains = await self.gather_subdomains(target_domain)
        tasks =[self.gather_host_info(sub) for sub in subdomains[:10]]
        hosts_data = await asyncio.gather(*tasks)
        
        return {
            "target": target_domain,
            "subdomains_found": len(subdomains),
            "hosts": [h for h in hosts_data if h]
        }
