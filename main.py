from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import joinedload

import core.celery_app 
from services.tasks import run_osint_scan_task
from core.database import get_db
from models.db_models import ScanTask, RiskAssessment, DigitalAsset, Vulnerability, Organization 

app = FastAPI(
    title="OSINT Threat Analyzer API",
    version="1.0.0"
)

class ScanRequest(BaseModel):
    target_domain: str
    ip_range_cidr: Optional[str] = None
    
class ScanResponse(BaseModel):
    task_id: str
    status: str

@app.post("/api/v1/scan", response_model=ScanResponse)
async def initiate_scan(request: ScanRequest):
    # Запускаємо сканування у фоні
    task = run_osint_scan_task.delay(request.target_domain, request.ip_range_cidr)
    return ScanResponse(task_id=task.id, status="Processing initiated via Celery")

@app.get("/api/v1/report/{task_id}")
async def get_scan_report(task_id: str, db: AsyncSession = Depends(get_db)):
    """Дістає готовий звіт та структуру графа знань з PostgreSQL"""
    result = await db.execute(select(ScanTask).where(ScanTask.id == task_id))
    task = result.scalars().first()
    
    if not task:
        raise HTTPException(status_code=404, detail="Завдання не знайдено")
        
    if task.status != "completed":
        return {"status": task.status, "message": "Сканування ще триває..."}

    # 1. Дістаємо звіти ШІ
    risk_result = await db.execute(select(RiskAssessment).where(RiskAssessment.task_id == task_id))
    assessments = risk_result.scalars().all()
    
    reports =[{"risk_score": a.risk_score, "risk_category": a.risk_category, "llm_report": a.llm_report} for a in assessments]
        
    # 2. БУДУЄМО ГРАФ ЗНАНЬ ДЛЯ GUI
    assets_result = await db.execute(select(DigitalAsset).where(DigitalAsset.task_id == task_id))
    assets = assets_result.scalars().all()
    
    graph_data = {"nodes": [], "edges":[]}
    added_nodes = set()
    
    for asset in assets:
        if asset.value not in added_nodes:
            graph_data["nodes"].append({"id": asset.value, "type": "Asset"})
            added_nodes.add(asset.value)
            
        # Шукаємо вразливості для цього активу
        vulns_result = await db.execute(select(Vulnerability).where(Vulnerability.asset_id == asset.id))
        vulns = vulns_result.scalars().all()
        
        for vuln in vulns:
            if vuln.cve_id not in added_nodes:
                graph_data["nodes"].append({"id": vuln.cve_id, "type": "Vulnerability"})
                added_nodes.add(vuln.cve_id)
            # Створюємо зв'язок (ребро) між IP та CVE
            graph_data["edges"].append({"source": asset.value, "target": vuln.cve_id})

    return {
        "status": task.status,
        "completed_at": task.completed_at,
        "assessments": reports,
        "graph_data": graph_data # Передаємо граф на фронтенд!
    }
@app.get("/api/v1/history")
async def get_scan_history(db: AsyncSession = Depends(get_db)):
    """Повертає список усіх минулих сканувань (Безпечний асинхронний запит)"""
    
    # 1. Дістаємо всі завдання разом з організаціями (joinedload вирішує проблему MissingGreenlet)
    result = await db.execute(
        select(ScanTask)
        .options(joinedload(ScanTask.organization))
        .order_by(ScanTask.started_at.desc())
    )
    tasks = result.scalars().all()
    
    history =[]
    for t in tasks:
        history.append({
            "task_id": str(t.id),
            "target": t.organization.root_domain if t.organization else "Невідомо",
            "status": t.status,
            "started_at": t.started_at.strftime("%Y-%m-%d %H:%M:%S") if t.started_at else ""
        })
        
    return {"history": history}
