import uuid
from datetime import datetime
from sqlalchemy import String, Float, Boolean, ForeignKey, DateTime, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from core.database import Base

class Organization(Base):
    """Таблиця цільових організацій (зберігає ідентифікатори та кореневі домени)"""
    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    root_domain: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    tasks = relationship("ScanTask", back_populates="organization", cascade="all, delete-orphan")
    assets = relationship("DigitalAsset", back_populates="organization", cascade="all, delete-orphan")

class ScanTask(Base):
    """Таблиця завдань сканування (фіксує метадані кожного циклу розвідки)"""
    __tablename__ = "scan_tasks"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="pending") # pending, running, completed, failed
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    completed_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    organization = relationship("Organization", back_populates="tasks")
    assets = relationship("DigitalAsset", back_populates="task")

class DigitalAsset(Base):
    """
    Технологічне ядро бази: акумулює записи про субдомени, порти та хмарні сховища.
    Використовує JSONB для гнучкого збереження сирих даних (MISP формат).
    """
    __tablename__ = "digital_assets"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    task_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scan_tasks.id"), nullable=False)
    
    asset_type: Mapped[str] = mapped_column(String(100), nullable=False) # subdomain, ip, s3_bucket, github_repo
    value: Mapped[str] = mapped_column(String(255), nullable=False)
    
    # Прапорець приналежності до тіньового ІТ (Shadow IT)
    is_shadow_it: Mapped[bool] = mapped_column(Boolean, default=False)
    
    # Розрахунковий ваговий коефіцієнт критичності (W_i з формули)
    criticality_weight: Mapped[float] = mapped_column(Float, default=1.0)
    
    # Неструктуровані дані від зовнішніх API (Shodan, Censys)
    raw_data: Mapped[dict] = mapped_column(JSONB, nullable=True)

    organization = relationship("Organization", back_populates="assets")
    task = relationship("ScanTask", back_populates="assets")
    vulnerabilities = relationship("Vulnerability", back_populates="asset", cascade="all, delete-orphan")
    risk_assessment = relationship("RiskAssessment", back_populates="asset", uselist=False, cascade="all, delete-orphan")

class Vulnerability(Base):
    """Таблиця вразливостей (зберігає CVSS-бали та сирі докази)"""
    __tablename__ = "vulnerabilities"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("digital_assets.id"), nullable=False)
    
    cve_id: Mapped[str] = mapped_column(String(50), nullable=True)
    cvss_score: Mapped[float] = mapped_column(Float, nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    
    # Сирі докази (evidence) у форматі JSON
    evidence: Mapped[dict] = mapped_column(JSONB, nullable=True)

    asset = relationship("DigitalAsset", back_populates="vulnerabilities")

class RiskAssessment(Base):
    """Таблиця математичних оцінок ризику (реєструє фінальні ймовірнісні показники)"""
    __tablename__ = "risk_assessments"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("digital_assets.id"), nullable=False, unique=True)
    task_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scan_tasks.id"), nullable=False)
    
    # Фінальний бал ризику (CRQ)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    
    # Категорія згідно з Таблицею 2.5 (Acceptable, Tolerable, Intolerable)
    risk_category: Mapped[str] = mapped_column(String(50), nullable=False)
    
    # Звіт, згенерований LLM (Gemini 3.1)
    llm_report: Mapped[str] = mapped_column(Text, nullable=True)
    
    calculated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    asset = relationship("DigitalAsset", back_populates="risk_assessment")