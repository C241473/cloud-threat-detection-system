from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import Threat
from backend.schemas import ThreatResponse, ThreatStatusUpdate

router = APIRouter(prefix="/api/threats", tags=["Threat Detection"])

@router.get("", response_model=List[ThreatResponse])
def get_threats(
    severity: Optional[str] = Query(None),
    threat_status: Optional[str] = Query(None, alias="status"),
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db)
):
    """List detected security threats with severity & status filters."""
    query = db.query(Threat)
    
    if severity and severity != "ALL":
        query = query.filter(Threat.severity == severity.upper())
    if threat_status and threat_status != "ALL":
        query = query.filter(Threat.status == threat_status.upper())

    threats = query.order_by(Threat.detected_at.desc()).limit(limit).all()
    return threats

@router.patch("/{threat_id}/status", response_model=ThreatResponse)
def update_threat_status(threat_id: int, status_update: ThreatStatusUpdate, db: Session = Depends(get_db)):
    """Update threat status (ACTIVE, INVESTIGATING, RESOLVED, DISMISSED)."""
    threat = db.query(Threat).filter(Threat.id == threat_id).first()
    if not threat:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Threat record not found")

    threat.status = status_update.status.upper()
    db.commit()
    db.refresh(threat)
    return threat
