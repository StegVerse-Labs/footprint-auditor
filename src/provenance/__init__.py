"""Historical provenance and ecosystem integrity auditing."""

from .historical import (
    AuditBoundary,
    AuditEvent,
    AuditLedger,
    AuditStatus,
    ExposureInterval,
    classify_event,
)
from .commit_authority import (
    AuthorityRecord,
    CommitAuthorityResolution,
    normalize_audit_log_authority_record,
    resolve_commit_authority,
)
from .inventory import (
    RepositorySnapshot,
    build_inventory_snapshot,
    inventory_digest,
    verify_inventory_snapshot,
)
from .report import (
    AuditFindingSummary,
    build_audit_report,
    normalize_finding,
    render_markdown,
    verify_report,
)
from .ecosystem_dependencies import (
    DependencyFinding,
    DependencyStatus,
    scan_dependency_file,
    summarize as summarize_ecosystem_dependencies,
)

__all__ = [
    "AuditBoundary",
    "AuditEvent",
    "AuditLedger",
    "AuditStatus",
    "ExposureInterval",
    "classify_event",
    "AuthorityRecord",
    "CommitAuthorityResolution",
    "normalize_audit_log_authority_record",
    "resolve_commit_authority",
    "RepositorySnapshot",
    "build_inventory_snapshot",
    "inventory_digest",
    "verify_inventory_snapshot",
    "AuditFindingSummary",
    "build_audit_report",
    "normalize_finding",
    "render_markdown",
    "verify_report",
    "DependencyFinding",
    "DependencyStatus",
    "scan_dependency_file",
    "summarize_ecosystem_dependencies",
]
