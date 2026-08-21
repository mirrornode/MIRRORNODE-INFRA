from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class AdminAction(str, Enum):
    PROPOSE_FILE = "PROPOSE_FILE"
    PROPOSE_WORKFLOW = "PROPOSE_WORKFLOW"
    OPEN_PR = "OPEN_PR"
    REQUEST_REVIEW = "REQUEST_REVIEW"
    MERGE_PR = "MERGE_PR"
    UPDATE_RULESET = "UPDATE_RULESET"
    EXPAND_PERMISSION = "EXPAND_PERMISSION"


@dataclass(frozen=True)
class AdminProposal:
    repository: str
    action: AdminAction
    rationale: str
    payload: dict[str, Any]
    requires_operator_approval: bool


class RepoAdmin:
    """Proposal engine for repository administration.

    v0.1 deliberately contains no GitHub write transport. It can construct
    bounded proposals but cannot execute them. A future adapter must enforce
    the policy manifest and explicit Operator approval before any mutation.
    """

    ALWAYS_OPERATOR_GATED = {
        AdminAction.MERGE_PR,
        AdminAction.UPDATE_RULESET,
        AdminAction.EXPAND_PERMISSION,
    }

    def propose(self, repository: str, action: AdminAction, rationale: str, **payload: Any) -> AdminProposal:
        return AdminProposal(
            repository=repository,
            action=action,
            rationale=rationale,
            payload=payload,
            requires_operator_approval=action in self.ALWAYS_OPERATOR_GATED,
        )

    def execute(self, proposal: AdminProposal) -> None:
        raise PermissionError(
            "Repo Steward v0.1 is proposal-only for mutations; execution transport is intentionally absent."
        )
