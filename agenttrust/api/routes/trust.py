"""Trust scoring API."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from agenttrust.api.deps import get_db
from agenttrust.auth.dependencies import require_permission
from agenttrust.auth.service import PERM_TRUST_CALCULATE, PERM_TRUST_READ
from agenttrust.db.repositories import list_trust_profiles as list_trust_profiles_db
from agenttrust.db.repositories import recalculate_all_profiles_db
from agenttrust.trust import TrustProfile

router = APIRouter()


@router.get("/profiles", dependencies=[Depends(require_permission(PERM_TRUST_READ))])
def trust_profiles(db: Annotated[Session, Depends(get_db)]) -> list[dict]:
    rows = list_trust_profiles_db(db)
    return [r.model_dump(mode="json") for r in rows]


@router.post("/calculate", dependencies=[Depends(require_permission(PERM_TRUST_CALCULATE))])
def calculate(db: Annotated[Session, Depends(get_db)]) -> dict[str, dict]:
    updated: dict[str, TrustProfile] = recalculate_all_profiles_db(db)
    return {aid: prof.model_dump(mode="json") for aid, prof in sorted(updated.items())}
