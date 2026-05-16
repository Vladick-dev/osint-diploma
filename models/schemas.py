from pydantic import BaseModel, Field, IPvAnyNetwork, ConfigDict
from typing import List, Optional, Dict, Any
from datetime import datetime
from uuid import UUID

# --- Вхідні запити (Requests) ---

class ScanInitiationRequest(BaseModel):
    """Валідація запиту на старт OSINT сканування"""
    org_name: str = Field(..., description="Назва організації")
    target_domain: str = Field(..., description="Кореневий домен організації (напр. example.com)")
    # IPvAnyNetwork автоматично валідує CIDR формат (напр. 192.168.1.0/24)
    ip_range_cidr: Optional[IPvAnyNetwork] = Field(None, description="Діапазон IP у форматі CIDR")

# --- Вихідні відповіді (Responses) ---

class ScanTaskResponse(BaseModel):
    """Відповідь API Gateway після ініціалізації завдання"""
    task_id: UUID
    org_id: UUID
    status: str
    message: str = "Завдання успішно додано до швидкісної In-Memory черги (Celery)"

class VulnerabilitySchema(BaseModel):
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    description: Optional[str] = None
    
    model_config = ConfigDict(from_attributes=True)

class AssetResponseSchema(BaseModel):
    """Схема цифрового активу для видачі клієнту"""
    id: UUID
    asset_type: str
    value: str
    is_shadow_it: bool
    criticality_weight: float
    vulnerabilities: List[VulnerabilitySchema] =[]
    
    model_config = ConfigDict(from_attributes=True)

class RiskAssessmentResponse(BaseModel):
    """Схема фінального звіту про ризики"""
    asset_id: UUID
    risk_score: float
    risk_category: str
    llm_report: Optional[str] = None
    calculated_at: datetime
    
    model_config = ConfigDict(from_attributes=True)

class FullReportResponse(BaseModel):
    """Комплексний звіт по організації"""
    org_name: str
    target_domain: str
    scan_task_id: UUID
    assets_analyzed: int
    shadow_it_found: int
    critical_risks: List[RiskAssessmentResponse]