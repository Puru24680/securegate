"""
SecureGate Immutable Audit Logging Engine
Records append-only records of all security-sensitive actions, authentication events,
policy changes, and governance decisions.
"""
import json
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from flask import request

logger = logging.getLogger(__name__)


def log_audit_event(
    organization_id: int,
    action: str,
    resource_type: str,
    resource_id: Optional[str] = None,
    user_id: Optional[int] = None,
    user_email: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None
):
    """
    Append an immutable audit entry to the audit log table.
    """
    from ..models.database import db, AuditLog

    # Auto-extract request IP and User Agent if available and not explicitly provided
    if request:
        try:
            if not ip_address:
                ip_address = request.headers.get("X-Forwarded-For", request.remote_addr or "")
                if "," in ip_address:
                    ip_address = ip_address.split(",")[0].strip()
            if not user_agent:
                user_agent = request.headers.get("User-Agent", "")[:250]
        except Exception:
            pass

    try:
        details_json = json.dumps(details or {}, default=str)
        audit_entry = AuditLog(
            organization_id=organization_id,
            user_id=user_id,
            user_email=user_email or (f"user#{user_id}" if user_id else "system"),
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id is not None else None,
            details=details_json,
            ip_address=ip_address or "",
            user_agent=user_agent or "",
            created_at=datetime.now(timezone.utc)
        )
        db.session.add(audit_entry)
        db.session.commit()
    except Exception as e:
        logger.warning(f"Failed to record audit log: {e}")
        try:
            db.session.rollback()
        except Exception:
            pass


class AuditLogger:
    @staticmethod
    def log(
        org_id: int,
        action: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        user_id: Optional[int] = None,
        user_email: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ):
        return log_audit_event(
            organization_id=org_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            user_id=user_id,
            user_email=user_email,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent
        )
