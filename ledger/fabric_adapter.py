"""Optional Hyperledger Fabric ledger backend; forbidden while ADR 0003 stands."""

from __future__ import annotations


def append_entry(payload: bytes) -> str:
    """Append one audit entry to Fabric. Deliberately unimplemented; see ADR 0003."""
    raise NotImplementedError(
        "Hyperledger Fabric is out of scope; see docs/adr/0003-transparency-log-over-fabric.md"
    )
