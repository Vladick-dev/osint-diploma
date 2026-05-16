from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_google_genai import HarmCategory, HarmBlockThreshold
from core.config import settings

def get_gemini_llm(temperature: float = 0.1, max_tokens: int = 8192) -> ChatGoogleGenerativeAI:
    safety_settings = {
        HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_ONLY_HIGH,
        HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
        HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
        HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
    }

    # ВИПРАВЛЕНО: Використовуємо Flash-версію, яка доступна на безкоштовному тарифі!
    llm = ChatGoogleGenerativeAI(
        model="gemini-3-flash-preview", 
        google_api_key=settings.GEMINI_API_KEY.get_secret_value(),
        temperature=temperature,
        max_output_tokens=max_tokens,
        safety_settings=safety_settings,
        request_timeout=120
    )
    
    return llm

def get_multimodal_llm() -> ChatGoogleGenerativeAI:
    return get_gemini_llm(temperature=0.2)

def get_evaluator_prompt_template() -> str:
    return """
    Ти — автономний ШІ-агент з кібербезпеки (Threat Intelligence Analyst).
    Твоє завдання — проаналізувати зібрані OSINT-артефакти та оцінити вектори загроз для компанії.
    """
