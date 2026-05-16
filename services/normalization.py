import re
import hashlib
from typing import List, Dict, Any
from datasketch import MinHash, MinHashLSH

class DataNormalizer:
    """Алгоритми нормалізації та дедуплікації (Розділ 2.3)"""
    
    @staticmethod
    def extract_atomic_entities(text: str) -> Dict[str, List[str]]:
        """Синтаксичний парсинг за допомогою регулярних виразів"""
        ipv4_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        hash_md5_pattern = r'\b[a-fA-F0-9]{32}\b'
        hash_sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
        
        return {
            "ipv4": list(set(re.findall(ipv4_pattern, text))),
            "md5": list(set(re.findall(hash_md5_pattern, text))),
            "sha256": list(set(re.findall(hash_sha256_pattern, text)))
        }

    @staticmethod
    def crypto_deduplicate(asset: Dict[str, Any]) -> str:
        """Криптографічна дедуплікація (SHA-256)"""
        ip = asset.get('ip', 'no_ip')
        ports = ",".join(map(str, sorted(asset.get('ports',[]))))
        
        # Хешуємо ТІЛЬКИ за IP та портами, щоб ідеально згрупувати інфраструктуру
        raw_string = f"{ip}_{ports}"
        return hashlib.sha256(raw_string.encode('utf-8')).hexdigest()
class FuzzyHasher:
    """Алгоритм локально-чутливого хешування (LSH) для текстових звітів"""
    def __init__(self, threshold: float = 0.8):
        # threshold 0.8 означає, що документи ідентичні на 80%
        self.lsh = MinHashLSH(threshold=threshold, num_perm=128)
        self.minhashes = {}

    def _get_minhash(self, text: str) -> MinHash:
        m = MinHash(num_perm=128)
        # Розбиваємо текст на шингли (слова)
        for word in text.lower().split():
            m.update(word.encode('utf8'))
        return m

    def add_document(self, doc_id: str, text: str):
        m = self._get_minhash(text)
        self.lsh.insert(doc_id, m)
        self.minhashes[doc_id] = m

    def find_duplicates(self, text: str) -> List[str]:
        """Повертає список ID звітів, які є неповними дублікатами (Fuzzy Match)"""
        m = self._get_minhash(text)
        return self.lsh.query(m)

class KnowledgeGraphBuilder:
    """Формування єдиного графа знань (Вузли та Ребра)"""
    def __init__(self):
        self.nodes = {}
        self.edges =[]

    def add_asset(self, ip: str, domain: str, vulns: List[str]):
        # Вузли
        if ip not in self.nodes:
            self.nodes[ip] = {"type": "IP-адреса", "id": ip}
        if domain not in self.nodes:
            self.nodes[domain] = {"type": "Домен", "id": domain}
            
        # Ребра (семантичні зв'язки)
        self.edges.append({"source": domain, "target": ip, "relation": "resolves_to"})
        
        for vuln in vulns:
            if vuln not in self.nodes:
                self.nodes[vuln] = {"type": "Вразливість", "id": vuln}
            self.edges.append({"source": ip, "target": vuln, "relation": "has_vulnerability"})
            
    def get_graph(self) -> Dict[str, Any]:
        return {"nodes": list(self.nodes.values()), "edges": self.edges}
