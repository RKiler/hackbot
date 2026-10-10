"""Optional recon lookup for a Target Package; never a scope decision."""

from __future__ import annotations

from .recon import ReconRepository, ReconTarget
from .target_package import TargetPackage


def resolve_recon_target(package: TargetPackage, repository: ReconRepository) -> ReconTarget | None:
    """Use an explicitly supplied read-only adapter; recon presence grants no authority."""
    return repository.resolve_target(package.primary_domain)
