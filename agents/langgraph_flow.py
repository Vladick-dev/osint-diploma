from langgraph.graph import StateGraph, END
from typing import Dict, TypedDict, Any
from agents.llm_setup import get_gemini_llm  # Імпортуємо нашу правильно налаштовану модель

# Ініціалізація моделі (ключ та Safety Settings підтягнуться автоматично з llm_setup.py)
llm = get_gemini_llm()

class AgentState(TypedDict):
    target: str
    raw_data: list
    enriched_data: dict  # Граф знань (вузли та ребра)
    risk_report: str

def agent_scout(state: AgentState):
    """Агент-розвідник: пошук прихованих субдоменів (пасивна розвідка)"""
    # Оскільки ми вже зібрали дані у tasks.py, тут можна додати логіку фільтрації
    print(f"[*] Агент-розвідник отримав {len(state['raw_data'])} активів.")
    return state

def agent_enricher(state: AgentState):
    """Агент збагачення: збір HTTP-банерів та мапування CVE"""
    print("[*] Агент збагачення аналізує граф знань...")
    return state

def agent_evaluator(state: AgentState):
    """Агент оцінки: фінальний синтез та RAG інтеграція"""
    print("[*] Агент оцінки генерує фінальний звіт через Gemini...")
    
    prompt = f"""
    Оціни кібер-ризики для організації {state['target']}.
    Використовуй наступний граф знань (активи та вразливості):
    {state['enriched_data']}
    
    Дій за парадигмою ReAct. Зроби детальний висновок.
    """
    
    # Виклик Gemini
    response = llm.invoke(prompt)
    
    # --- ВИПРАВЛЕННЯ ФОРМАТУ ДАНИХ ---
    # Перевіряємо, чи повернула нова модель список замість тексту
    content = response.content
    if isinstance(content, list):
        # Дістаємо текст з усіх блоків і з'єднуємо їх
        text_parts =[]
        for item in content:
            if isinstance(item, dict) and "text" in item:
                text_parts.append(item["text"])
            elif isinstance(item, str):
                text_parts.append(item)
        final_report = "\n".join(text_parts)
    else:
        # Якщо це звичайний рядок
        final_report = str(content)
        
    state["risk_report"] = final_report
    return state

# Побудова динамічного графа станів (LangGraph)
workflow = StateGraph(AgentState)
workflow.add_node("scout", agent_scout)
workflow.add_node("enricher", agent_enricher)
workflow.add_node("evaluator", agent_evaluator)

# Налаштування потоку (AUTOINT конвеєр)
workflow.set_entry_point("scout")
workflow.add_edge("scout", "enricher")
workflow.add_edge("enricher", "evaluator")
workflow.add_edge("evaluator", END)

app_graph = workflow.compile()
