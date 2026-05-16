import asyncio
import uuid
from datetime import datetime
from celery import shared_task
from sqlalchemy import select

from core.database import AsyncSessionLocal
from models.db_models import Organization, ScanTask, DigitalAsset, Vulnerability, RiskAssessment
from services.osint_gather import OSINTCollector
from services.normalization import DataNormalizer, KnowledgeGraphBuilder
from ml.analysis import RiskEvaluator  # Математична модель з попередніх кроків
from agents.langgraph_flow import app_graph  # Ваш багатоагентний граф

async def async_osint_pipeline(target_domain: str, task_id_str: str):
    """Асинхронний конвеєр (AUTOINT) з повним збереженням у БД"""
    
    # 1. Збір даних (Scout)
    collector = OSINTCollector()
    raw_data = await collector.run_full_recon(target_domain)
    
    # 2. Нормалізація та Дедуплікація
    normalizer = DataNormalizer()
    unique_assets = {}
    
    for host in raw_data.get("hosts",[]):
        asset_hash = normalizer.crypto_deduplicate(host)
        if asset_hash not in unique_assets:
            unique_assets[asset_hash] = host
            
    # 3. Побудова графа знань
    kg_builder = KnowledgeGraphBuilder()
    for asset in unique_assets.values():
        ip = asset.get("ip")
        vulns = asset.get("vulns",[])
        if ip:
            # ПОВЕРНУЛИ ЯК БУЛО: прив'язуємо IP до головного домену
            kg_builder.add_asset(ip, target_domain, vulns)
            
    # 4. Передача нормалізованих даних до ШІ-агентів (Gemini 3.1)
    agent_state = {
        "target": target_domain,
        "raw_data": list(unique_assets.values()),
        "enriched_data": kg_builder.get_graph(),
        "risk_report": ""
    }
    
    # Запуск LangGraph оркестратора (генерація звіту)
    final_state = app_graph.invoke(agent_state)
    llm_report = final_state.get("risk_report", "Звіт не згенеровано.")

    # Ініціалізація математичної моделі для оцінки ризиків
    risk_evaluator = RiskEvaluator()
    
    # 5. ЗБЕРЕЖЕННЯ РЕЗУЛЬТАТІВ У POSTGRESQL
    async with AsyncSessionLocal() as db:
        try:
            # 5.1. Знайти або створити Організацію
            result = await db.execute(select(Organization).where(Organization.root_domain == target_domain))
            org = result.scalars().first()
            
            if not org:
                org = Organization(name=target_domain, root_domain=target_domain)
                db.add(org)
                await db.commit()
                await db.refresh(org)

            # 5.2. Знайти завдання сканування (створене в API Gateway) або створити нове
            try:
                task_uuid = uuid.UUID(task_id_str)
            except ValueError:
                task_uuid = uuid.uuid4()

            result = await db.execute(select(ScanTask).where(ScanTask.id == task_uuid))
            scan_task = result.scalars().first()

            if not scan_task:
                scan_task = ScanTask(id=task_uuid, org_id=org.id, status="running")
                db.add(scan_task)
            else:
                scan_task.status = "running"
            
            await db.commit()

            # 5.3. Збереження активів (DigitalAsset) та вразливостей (Vulnerability)
            for asset_hash, asset_data in unique_assets.items():
                ip = asset_data.get("ip")
                if not ip:
                    continue

                # Логіка виявлення тіньового ІТ (спрощена для прикладу)
                # У реальності тут підключається DBSCAN з risk_evaluator
                hostnames = asset_data.get("hostnames",[])
                is_shadow = any("dev" in h or "test" in h or "staging" in h for h in hostnames)

                new_asset = DigitalAsset(
                    org_id=org.id,
                    task_id=scan_task.id,
                    asset_type="ip",
                    value=ip,
                    is_shadow_it=is_shadow,
                    raw_data=asset_data  # Зберігається як JSONB
                )
                db.add(new_asset)
                await db.flush()  # Отримуємо ID нового активу без повного коміту

                # Збереження знайдених CVE
                vulns = asset_data.get("vulns", [])
                formatted_vulns_for_ml =[]
                
                for cve in vulns:
                    new_vuln = Vulnerability(
                        asset_id=new_asset.id,
                        cve_id=cve,
                        cvss_score=7.5, # Базова оцінка (в реальності підтягується з NVD API)
                        description=f"Знайдено вразливість {cve}"
                    )
                    db.add(new_vuln)
                    
                    # Форматуємо дані для математичної моделі
                    formatted_vulns_for_ml.append({
                        'likelihood': 0.8,
                        'threat_event_frequency': 1.2
                    })

                # 5.4. Розрахунок ризику (CRQ) та збереження
                # Використовуємо формулу з Розділу 2.3 вашої роботи
                risk_score = risk_evaluator.calculate_cyber_risk(
                    vulnerabilities=formatted_vulns_for_ml,
                    I_i=100.0,  # Базова оцінка впливу (Loss Magnitude)
                    W_i=new_asset.criticality_weight,
                    F_ml=1.1    # Коригувальний фактор машинного навчання
                )

                # Визначення категорії за Таблицею 2.5
                if risk_score < 540:
                    category = "Прийнятний (Acceptable)"
                elif risk_score <= 1215:
                    category = "Допустимий (Tolerable)"
                else:
                    category = "Неприпустимий (Intolerable)"

                # Запис фінальної оцінки та звіту від Gemini 3.1
                risk_assessment = RiskAssessment(
                    asset_id=new_asset.id,
                    task_id=scan_task.id,
                    risk_score=risk_score,
                    risk_category=category,
                    # ВИПРАВЛЕНО: Тепер ми ЗАВЖДИ зберігаємо звіт від ШІ, незалежно від балів!
                    llm_report=llm_report 
                )
                db.add(risk_assessment)

            # Фіналізуємо завдання сканування
            scan_task.status = "completed"
            scan_task.completed_at = datetime.utcnow()
            await db.commit()

        except Exception as e:
            await db.rollback()
            print(f"[!] Помилка бази даних: {e}")
            raise e

    return llm_report

@shared_task(bind=True, name="run_osint_scan")
def run_osint_scan_task(self, target_domain: str, ip_range: str = None):
    """
    Точка входу для Celery Worker.
    Оскільки Celery синхронний, ми створюємо event loop для запуску асинхронного конвеєра.
    """
    # Оновлюємо статус завдання в Celery
    self.update_state(state='PROGRESS', meta={'step': 'Gathering OSINT data'})
    
    # Запуск асинхронного пайплайну
    loop = asyncio.get_event_loop()
    report = loop.run_until_complete(async_osint_pipeline(target_domain, self.request.id))
    
    return {"status": "completed", "report": report}
