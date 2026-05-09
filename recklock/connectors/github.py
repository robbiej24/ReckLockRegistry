"""GitHub connector — validation & guarded execution (Phase 3D)."""

from __future__ import annotations

from typing import Any, ClassVar

from recklock.connectors.base import (
    BaseConnector,
    ConnectorRequest,
    ConnectorResponse,
    real_connectors_enabled,
)


class GitHubConnector(BaseConnector):
    connector_id: ClassVar[str] = "github"
    name: ClassVar[str] = "GitHub"
    supported_capabilities: ClassVar[list[str]] = [
        "create_issue",
        "comment_on_issue",
        "create_pull_request",
    ]
    required_permission_scopes: ClassVar[list[str]] = ["workspace.write", "integrations.github", "*"]

    def validate_config(self, config: dict[str, Any]) -> None:
        action = config.get("_validated_action")
        if not action:
            raise ValueError("missing connector action for validation")
        if action == "create_issue":
            repo = config.get("repository")
            title = config.get("title")
            if not repo or not isinstance(repo, str):
                raise ValueError("create_issue requires string 'repository'")
            if not title or not isinstance(title, str):
                raise ValueError("create_issue requires string 'title'")
        elif action == "comment_on_issue":
            repo = config.get("repository")
            issue_number = config.get("issue_number")
            body = config.get("body")
            if not repo or not isinstance(repo, str):
                raise ValueError("comment_on_issue requires string 'repository'")
            if issue_number is None:
                raise ValueError("comment_on_issue requires issue_number")
            if not body or not isinstance(body, str):
                raise ValueError("comment_on_issue requires string 'body'")
        elif action == "create_pull_request":
            repo = config.get("repository")
            if not repo or not isinstance(repo, str):
                raise ValueError("create_pull_request requires string 'repository' (placeholder validation)")
        else:
            raise ValueError("Unknown action for validation")

    def dry_run(self, request: ConnectorRequest) -> ConnectorResponse:
        cfg = dict(request.config)
        cfg["_validated_action"] = request.action
        self.validate_config(cfg)
        return ConnectorResponse(
            connector_id=self.connector_id,
            action=request.action,
            dry_run=True,
            success=True,
            message=f"Dry-run validation passed for GitHub action {request.action!r}",
            metadata={"repository": request.config.get("repository")},
        )

    def execute(self, request: ConnectorRequest) -> ConnectorResponse:
        if not real_connectors_enabled():
            return ConnectorResponse(
                connector_id=self.connector_id,
                action=request.action,
                dry_run=False,
                success=False,
                message="Real GitHub execution disabled (set RECKLOCK_ENABLE_REAL_CONNECTORS=true to enable).",
            )
        cfg = dict(request.config)
        cfg["_validated_action"] = request.action
        self.validate_config(cfg)
        return ConnectorResponse(
            connector_id=self.connector_id,
            action=request.action,
            dry_run=False,
            success=False,
            message="GitHub API execution is not wired in this build (placeholder only).",
            external_reference=None,
            metadata={"simulated": True},
        )
