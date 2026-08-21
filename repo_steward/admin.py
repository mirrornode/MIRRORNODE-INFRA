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


APPROVED_ADVISORY_LANES = ("OPENAI_ASSISTANT", "PERPLEXITY", "CLAUDE")


@dataclass(frozen=True)
class AdminProposal:
    repository: str
    action: AdminAction
    rationale: str
    payload: dict[str, Any]
    requires_operator_approval: bool
    requires_advisory_attestation: bool
    approved_advisory_lanes: tuple[str, ...]


class RepoAdmin:
    """Proposal engine for repository administration.

    v0.1 deliberately contains no GitHub write transport. It can construct
    bounded proposals but cannot execute them. Any future mutation transport
    must require dual control: explicit human Operator authorization plus at
    least one independent attestation from an approved advisory lane.

    Advisory lanes can inspect, prepare, recommend, or review. They cannot
    independently authorize or execute repository administration.
    """

    def propose(self, repository: str, action: AdminAction, rationale: str, **payload: Any) -> AdminProposal:
        return AdminProposal(
            repository=repository,
            action=action,
            rationale=rationale,
            payload=payload,
            requires_operator_approval=True,
            requires_advisory_attestation=True,
            approved_advisory_lanes=APPROVED_ADVISORY_LANES,
        )

    def execute(self, proposal: AdminProposal) -> None:
        raise PermissionError(
            "Repo Steward v0.1 is proposal-only; all repository writes are closed and execution transport is absent."
        )
