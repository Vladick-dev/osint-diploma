import os
from langchain_community.vectorstores import FAISS
from langchain_google_genai import GoogleGenerativeAIEmbeddings
from core.config import settings

class FAISSManager:
    def __init__(self):
        # Ініціалізація моделі ембеддінгів від Google
        self.embeddings = GoogleGenerativeAIEmbeddings(
            model="models/embedding-001",
            google_api_key=settings.GEMINI_API_KEY.get_secret_value()
        )
        self.index_path = settings.FAISS_INDEX_PATH
        self.vector_store = None

    def load_or_create_index(self):
        """Завантажує існуючий індекс FAISS або створює новий, якщо його немає"""
        if os.path.exists(self.index_path):
            self.vector_store = FAISS.load_local(
                self.index_path, 
                self.embeddings,
                allow_dangerous_deserialization=True # Дозволено для локальних довірених файлів
            )
            print("[*] Локальний індекс FAISS успішно завантажено.")
        else:
            # Створення порожнього індексу з фіктивним документом для ініціалізації
            print("[*] Індекс FAISS не знайдено. Створення нового...")
            self.vector_store = FAISS.from_texts(
                texts=["Ініціалізація бази знань CTI"], 
                embedding=self.embeddings,
                metadatas=[{"source": "system", "id": "init"}]
            )
            self.save_index()

    def add_cti_reports(self, reports: list[dict]):
        """
        Додає нові звіти CTI до векторної бази.
        Кожен вектор містить метадані з ID для зв'язку з PostgreSQL (Data Lineage).
        """
        if not self.vector_store:
            self.load_or_create_index()
            
        texts = [report['content'] for report in reports]
        # Обов'язкове мета-поле з унікальним ідентифікатором (Розділ 2.2)
        metadatas = [{"source": report['url'], "db_id": report['postgres_id']} for report in reports]
        
        self.vector_store.add_texts(texts=texts, metadatas=metadatas)
        self.save_index()

    def save_index(self):
        """Зберігає векторну базу на диск"""
        if self.vector_store:
            self.vector_store.save_local(self.index_path)

# Глобальний екземпляр для використання в застосунку
faiss_db = FAISSManager()