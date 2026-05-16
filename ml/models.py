from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_google_genai import HarmCategory, HarmBlockThreshold
from core.config import settings

def get_gemini_llm(temperature: float = 0.1, max_tokens: int = 8192) -> ChatGoogleGenerativeAI:
    """
    Ініціалізація когнітивного ядра системи — моделі Gemini 3.1.
    
    Згідно з Розділом 2.2, ця модель використовується для:
    1. Оркестрації багатоагентної системи (ReAct парадигма).
    2. Аналізу надвеликих масивів сирих логів та CTI-звітів без втрати контексту.
    3. Генерації фінальних звітів з дотриманням Data Lineage.
    
    :param temperature: Температура генерації (0.1 для максимальної детермінованості та точності аналітики)
    :param max_tokens: Максимальний розмір вихідного звіту
    """
    
    # Налаштування фільтрів безпеки (Safety Settings).
    # КРИТИЧНО ВАЖЛИВО ДЛЯ OSINT: Знижуємо поріг блокування для категорії DANGEROUS_CONTENT,
    # інакше модель буде відмовлятися аналізувати CVE, експлойти та дампи баз даних,
    # розцінюючи кібербезпековий аналіз як "шкідливі поради".
    safety_settings = {
        HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_ONLY_HIGH,
        HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
        HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
        HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
    }

    # Ініціалізація моделі через LangChain
    # Примітка: Вказуємо умовну назву gemini-3.1-pro (або актуальну версію API Google на 2026 рік)
    llm = ChatGoogleGenerativeAI(
        model="gemini-3.1-pro", # Відповідно до тексту дипломної роботи
        google_api_key=settings.GEMINI_API_KEY.get_secret_value(),
        temperature=temperature,
        max_output_tokens=max_tokens,
        safety_settings=safety_settings,
        # Увімкнення максимального контекстного вікна (якщо підтримується параметром)
        request_options={"timeout": 120} # Збільшений таймаут для обробки терабайтів даних
    )
    
    return llm


def get_multimodal_llm() -> ChatGoogleGenerativeAI:
    """
    Ініціалізація Gemini 3.1 для візуального аналізу (нативна мультимодальність).
    
    Як зазначено в роботі: "Сучасні зловмисники публікують докази успішних зломів 
    у вигляді графічних скріншотів панелей керування... Gemini 3.1 здатна 
    безпосередньо аналізувати візуальну інформацію".
    """
    # Для мультимодальних задач (зображення + текст) використовуємо ту саму модель,
    # але можемо задати іншу температуру для кращого розпізнавання
    return get_gemini_llm(temperature=0.2)


def get_evaluator_prompt_template() -> str:
    """
    Базовий системний промпт для агента-оцінювача, що гарантує відсутність галюцинацій
    та дотримання принципу Data Lineage.
    """
    return """
    Ти — автономний ШІ-агент з кібербезпеки (Threat Intelligence Analyst).
    Твоє завдання — проаналізувати зібрані OSINT-артефакти та оцінити вектори загроз для компанії.
    
    ПРАВИЛА (КРИТИЧНО):
    1. Використовуй парадигму логічного виведення (Reasoning). Крок за кроком пояснюй свої висновки.
    2. Data Lineage: Кожне твердження про вразливість ПОВИННО містити посилання на джерело (наприклад,[Shodan, IP: 1.1.1.1] або [CVE-2024-XXXX]).
    3. Якщо інформації недостатньо для висновку, чітко заяви про це. НЕ ГЕНЕРУЙ вигаданих (галюцинованих) вразливостей.
    4. Класифікуй ризик згідно з матрицею: Прийнятний (Acceptable), Допустимий (Tolerable), Неприпустимий (Intolerable).
    """