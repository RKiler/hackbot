"""Evaluator-only fixture coverage for the low-resource acceptance suite."""

from __future__ import annotations

from dataclasses import dataclass

from .benchmark_catalog import BenchmarkCatalog
from .benchmark_models import BenchmarkCategory, BenchmarkFixtureKind


REQUIRED_SPECIALISTS = (
    "AUTHORIZATION", "API_GRAPHQL", "DOM_XSS", "POSTMESSAGE", "EXPOSURE",
)
PairKey = tuple[BenchmarkFixtureKind, int, str]


@dataclass(frozen=True, slots=True)
class SpecialistPairCoverage:
    specialist: str
    vulnerable_cases: tuple[str, ...]
    secure_cases: tuple[str, ...]
    paired_fixture_kinds: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "specialist": self.specialist,
            "vulnerable_cases": list(self.vulnerable_cases),
            "secure_cases": list(self.secure_cases),
            "paired_fixture_kinds": list(self.paired_fixture_kinds),
            "covered": bool(self.paired_fixture_kinds),
        }


@dataclass(frozen=True, slots=True)
class LowResourceFixtureCoverage:
    suite: str
    specialist_pairs: tuple[SpecialistPairCoverage, ...]
    noisy_secure_cases: tuple[str, ...]
    mixed_cases: tuple[str, ...]

    @property
    def complete(self) -> bool:
        return (all(item.paired_fixture_kinds for item in self.specialist_pairs)
                and bool(self.noisy_secure_cases) and bool(self.mixed_cases))

    def to_dict(self) -> dict[str, object]:
        return {
            "suite": self.suite,
            "fixture_coverage_complete": self.complete,
            "specialist_pairs": [item.to_dict() for item in self.specialist_pairs],
            "noisy_secure_cases": list(self.noisy_secure_cases),
            "mixed_cases": list(self.mixed_cases),
            "scope": "FIXTURE_INVENTORY_ONLY",
        }


def assess_low_resource_fixture_coverage(
        catalog: BenchmarkCatalog, suite: str) -> LowResourceFixtureCoverage:
    """A pair requires one positive and one secure case of the same fixture kind.

    This is an evaluator-side inventory check, not evidence that any case ran,
    any Finding was confirmed, or the full acceptance gate passed.
    """
    positives: dict[tuple[str, PairKey], list[str]] = {}
    secure: dict[PairKey, list[str]] = {}
    noisy: list[str] = []
    mixed: list[str] = []
    for case_id in catalog.suite(suite):
        visible = catalog.visible(case_id)
        key = (visible.fixture_kind, visible.version, visible.visible_hash)
        if catalog.audit_visible_inputs(case_id):
            raise ValueError("Benchmark answer key leaked into visible fixture")
        truth = catalog.ground_truth(case_id)
        if (truth.case_id, truth.version) != (visible.case_id, visible.version):
            raise ValueError("Benchmark answer key does not match visible case")
        if truth.roots:
            if truth.expected_specialist in REQUIRED_SPECIALISTS:
                positives.setdefault((truth.expected_specialist, key), []).append(case_id)
            if len({root.category for root in truth.roots}) > 1:
                mixed.append(case_id)
        else:
            secure.setdefault(key, []).append(case_id)
            if truth.category is BenchmarkCategory.NOISY_FALSE_POSITIVE_CASE:
                noisy.append(case_id)
    pairs = []
    for specialist in REQUIRED_SPECIALISTS:
        positive_cases = sorted({case_id for (name, _kind), ids in positives.items()
                                 if name == specialist for case_id in ids})
        kinds = sorted({key[0].value for name, key in positives
                        if name == specialist and secure.get(key)})
        secure_cases = sorted({case_id for name, key in positives
                               if name == specialist and secure.get(key)
                               for case_id in secure[key]})
        pairs.append(SpecialistPairCoverage(
            specialist, tuple(positive_cases), tuple(secure_cases), tuple(kinds)))
    return LowResourceFixtureCoverage(suite, tuple(pairs), tuple(sorted(noisy)),
                                      tuple(sorted(mixed)))
