"""Policy evaluation API."""

from __future__ import annotations

from pydantic import BaseModel, Field

from fastapi import APIRouter, Depends

from recklock.auth.dependencies import require_permission
from recklock.auth.service import PERM_POLICIES_EVALUATE
from recklock.policy import ActionRequest, Policy, PolicyDecision, evaluate_action

router = APIRouter()


class PolicyEvaluateBody(BaseModel):
    request: ActionRequest
    policies: list[Policy] = Field(default_factory=list)


@router.post("/evaluate", dependencies=[Depends(require_permission(PERM_POLICIES_EVALUATE))])
def evaluate(body: PolicyEvaluateBody) -> PolicyDecision:
    return evaluate_action(body.request, body.policies)
