#!/usr/bin/env python3
"""Embed a complete plot-that bundle record into any ReproFig carrier.

The figure carries the exact plotted and derived CSV tables. Large original
inputs remain beside it in ``data/src`` and are represented by relative paths
and SHA256 fingerprints, so the artifact never exposes an absolute machine path.
"""

from __future__ import annotations

import csv
import hashlib
import importlib.metadata
import json
import platform
from pathlib import Path
from typing import Any


PLOT_THAT_RECORD_VERSION = "2"
STATISTICS_STATUSES = frozenset({"complete", "not_applicable"})
DIRECT_FIGURE_FORMATS = frozenset({
    "svg", "pdf", "png", "jpeg", "tiff", "webp", "avif", "heif",
})


class ReproFigBundleError(RuntimeError):
    """A plot-that bundle cannot be represented faithfully as ReproFig."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _reprofig():
    try:
        import reprofig
    except ImportError as exc:
        raise ReproFigBundleError(
            "ReproFig 0.3.0 or newer is required for plot-that artifacts; "
            "install it with `python -m pip install --upgrade \"reprofig>=0.3.0\"`"
        ) from exc
    if not hasattr(reprofig, "save_figure") or len(reprofig.formats()) < 16:
        raise ReproFigBundleError(
            "plot-that needs ReproFig 0.3.0 or newer with proof support; "
            "upgrade it with `python -m pip install --upgrade \"reprofig>=0.3.0\"`"
        )
    return reprofig


def _package_version(distribution: str) -> str | None:
    try:
        return importlib.metadata.version(distribution)
    except importlib.metadata.PackageNotFoundError:
        return None


def supported_artifact_suffixes() -> frozenset[str]:
    reprofig = _reprofig()
    return frozenset(
        suffix.lower()
        for carrier in reprofig.formats()
        for suffix in carrier["extensions"]
    )


# Bundle layout. A plot-that bundle is flat: every file sits directly in the
# bundle folder, copied sources carry a ``src_`` prefix and derived tables a
# ``der_`` prefix. Bundles written before 2026-08-28 nest the same files under
# code/, data/src/, data/der/ and fig/. Both layouts are read; only flat is
# written.
RESERVED_FLAT_NAMES = frozenset(
    {"readme.md", "sources.csv", "sources.md", "figure_data.csv", "statistics.csv"}
)


def is_legacy_bundle(bundle: Path) -> bool:
    """True when the bundle still keeps its provenance under data/."""
    return (bundle / "data" / "sources.csv").is_file() and not (
        bundle / "sources.csv"
    ).is_file()


def bundle_source_index(bundle: Path) -> Path:
    if is_legacy_bundle(bundle):
        return bundle / "data" / "sources.csv"
    return bundle / "sources.csv"


def bundle_table(bundle: Path) -> Path:
    if is_legacy_bundle(bundle):
        return bundle / "data" / "der" / "figure_data.csv"
    return bundle / "figure_data.csv"


def bundle_statistics(bundle: Path) -> Path:
    if is_legacy_bundle(bundle):
        return bundle / "data" / "der" / "statistics.csv"
    return bundle / "statistics.csv"


def bundle_derived_tables(bundle: Path) -> list[Path]:
    if is_legacy_bundle(bundle):
        return sorted((bundle / "data" / "der").glob("*.csv"))
    return sorted(
        path
        for path in bundle.glob("*.csv")
        if path.name.startswith("der_")
        or path.name in {"figure_data.csv", "statistics.csv"}
    )


def bundle_figure_folder(bundle: Path) -> Path:
    return bundle / "fig" if is_legacy_bundle(bundle) else bundle


def is_figure_candidate(path: Path) -> bool:
    """In a flat bundle, provenance files and prefixed copies are never masters."""
    name = path.name.lower()
    return not (
        name.startswith(("src_", "der_", "plot."))
        or name in RESERVED_FLAT_NAMES
        or "preview" in name
    )


def relative_label(bundle: Path, path: Path) -> str:
    try:
        return path.relative_to(bundle).as_posix()
    except ValueError:
        return path.name


def _bundle_for_artifact(artifact_path: Path) -> Path:
    target = artifact_path.expanduser().resolve()
    if target.suffix.lower() not in supported_artifact_suffixes():
        raise ReproFigBundleError(
            f"plot-that output is not a supported ReproFig carrier: {target}"
        )
    if target.parent.name.lower() == "fig":
        return target.parent.parent
    bundle = target.parent
    if not (bundle / "sources.csv").is_file():
        raise ReproFigBundleError(
            f"plot-that artifact must sit in a bundle folder holding sources.csv: {target}"
        )
    return bundle


def _inside_bundle(bundle: Path, value: str | Path, label: str) -> Path:
    candidate = Path(value)
    if candidate.is_absolute():
        path = candidate.resolve()
    else:
        path = (bundle / candidate).resolve()
    try:
        path.relative_to(bundle)
    except ValueError as exc:
        raise ReproFigBundleError(f"{label} must stay inside the bundle: {path}") from exc
    return path


def _required_file(path: Path, label: str) -> Path:
    if not path.is_file():
        raise ReproFigBundleError(f"missing {label}: {path}")
    return path


def _resolve_producer(bundle: Path, value: str | Path | None) -> Path:
    if value is not None:
        return _required_file(_inside_bundle(bundle, value, "producer"), "producer")
    if is_legacy_bundle(bundle):
        code = bundle / "code"
        candidates = [
            path
            for path in sorted(code.iterdir())
            if path.is_file() and not path.name.startswith(".")
        ] if code.is_dir() else []
        where = "code/"
    else:
        candidates = [path for path in sorted(bundle.glob("plot.*")) if path.is_file()]
        where = "the bundle folder"
    if len(candidates) != 1:
        raise ReproFigBundleError(
            f"pass producer=... because {where} does not contain exactly one "
            "standalone producer"
        )
    return candidates[0].resolve()


def _source_rows(bundle: Path, source_index: Path):
    reprofig = _reprofig()
    label = relative_label(bundle, source_index)
    with source_index.open(newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        fields = set(reader.fieldnames or [])
        required = {"copied_path", "sha256"}
        missing = sorted(required - fields)
        if missing:
            raise ReproFigBundleError(
                f"{label} is missing required columns: " + ", ".join(missing)
            )
        rows = list(reader)
    if not rows:
        raise ReproFigBundleError(f"{label} has no traced source rows")

    references = []
    for row_number, row in enumerate(rows, start=2):
        copied = (row.get("copied_path") or "").strip()
        expected = (row.get("sha256") or "").strip().lower()
        if not copied or not expected:
            raise ReproFigBundleError(
                f"{label} row {row_number} needs copied_path and sha256"
            )
        source_path = _required_file(
            _inside_bundle(bundle, copied, f"source row {row_number}"),
            f"copied source from row {row_number}",
        )
        actual = sha256(source_path)
        if actual != expected:
            raise ReproFigBundleError(
                f"copied source hash mismatch at row {row_number}: {source_path}"
            )
        declared_size = (row.get("byte_size") or "").strip()
        if declared_size:
            try:
                size = int(declared_size)
            except ValueError as exc:
                raise ReproFigBundleError(
                    f"invalid byte_size at {label} row {row_number}"
                ) from exc
            if size != source_path.stat().st_size:
                raise ReproFigBundleError(
                    f"copied source size mismatch at row {row_number}: {source_path}"
                )
        original = (row.get("original_path") or "").replace("\\", "/")
        metadata = {}
        if original:
            metadata["original_name"] = original.rsplit("/", 1)[-1]
        references.append(reprofig.SourceReference(
            role="input",
            relative_path=source_path.relative_to(bundle).as_posix(),
            uri=(
                (row.get("public_uri") or "").strip()
                or (row.get("uri") or "").strip()
                or None
            ),
            sha256=actual,
            size_bytes=source_path.stat().st_size,
            modified_at=(row.get("modification_time") or "").strip() or None,
            source_id=(row.get("file_name") or "").strip() or source_path.name,
            metadata=metadata,
        ))
    return references


def _file_reference(bundle: Path, path: Path, role: str):
    reprofig = _reprofig()
    return reprofig.SourceReference(
        role=role,
        relative_path=path.relative_to(bundle).as_posix(),
        sha256=sha256(path),
        size_bytes=path.stat().st_size,
    )


def _statistics(bundle: Path, requested: str | None) -> tuple[list[dict[str, str]], str]:
    path = bundle_statistics(bundle)
    rows: list[dict[str, str]] = []
    if path.is_file():
        with path.open(newline="", encoding="utf-8-sig") as stream:
            rows = [
                {key: value for key, value in row.items() if key and value not in (None, "")}
                for row in csv.DictReader(stream)
            ]
    inferred = "complete" if rows else "not_applicable"
    status = requested or inferred
    if status not in STATISTICS_STATUSES:
        raise ReproFigBundleError(
            f"statistics_status must be one of {sorted(STATISTICS_STATUSES)}"
        )
    if status == "complete" and not rows:
        raise ReproFigBundleError(
            f"statistics_status is complete but {relative_label(bundle, path)} "
            "has no result rows"
        )
    if status == "not_applicable" and rows:
        raise ReproFigBundleError(
            "statistics.csv contains results but statistics_status is not_applicable"
        )
    return rows, status


def _json_cell(row: dict[str, str], name: str, *, row_number: int) -> dict[str, Any]:
    raw = (row.get(name) or "").strip()
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ReproFigBundleError(
            f"statistics.csv row {row_number} has invalid {name} JSON"
        ) from exc
    if not isinstance(value, dict):
        raise ReproFigBundleError(
            f"statistics.csv row {row_number} {name} must be a JSON object"
        )
    return value


def _typed_statistical_specifications(
    statistics: list[dict[str, str]],
) -> list[Any]:
    """Read optional independent-test declarations without burdening basic bundles."""

    reprofig = _reprofig()
    specifications = []
    for row_number, row in enumerate(statistics, start=2):
        algorithm_id = (row.get("algorithm_id") or "").strip()
        if not algorithm_id:
            continue
        inputs = _json_cell(row, "inputs_json", row_number=row_number)
        expected = _json_cell(row, "expected_json", row_number=row_number)
        if not inputs or not expected:
            raise ReproFigBundleError(
                f"statistics.csv row {row_number} with algorithm_id needs "
                "inputs_json and expected_json"
            )
        specifications.append(reprofig.StatisticalSpecification(
            statistic_id=(row.get("statistic_id") or row.get("test_id") or None),
            algorithm_id=algorithm_id,
            inputs=inputs,
            parameters=_json_cell(row, "parameters_json", row_number=row_number),
            expected=expected,
            display=_json_cell(row, "display_json", row_number=row_number),
            tolerances=_json_cell(row, "tolerances_json", row_number=row_number),
        ))
    return specifications


def _environment(producer: Path) -> dict[str, str]:
    values = {
        "python": platform.python_version(),
        "reprofig": _package_version("reprofig") or "unknown",
    }
    if producer.suffix.lower() in {".py", ".ipynb"}:
        for distribution in ("matplotlib", "numpy", "pandas", "seaborn"):
            version = _package_version(distribution)
            if version:
                values[distribution] = version
    return values


def _run_command(relative: str, producer: Path) -> str:
    commands = {
        ".py": "python",
        ".r": "Rscript",
        ".jl": "julia",
        ".m": "matlab -batch run",
        ".js": "node",
        ".ts": "npx tsx",
    }
    command = commands.get(producer.suffix.lower(), "run")
    return f"{command} {relative}"


def _producer_source(path: Path) -> str:
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ReproFigBundleError(f"producer must be readable UTF-8 text: {path}") from exc
    from reprofig.validation import privacy_leaks

    leaks = privacy_leaks(source)
    if leaks:
        codes = ", ".join(sorted({code for code, _excerpt in leaks}))
        raise ReproFigBundleError(
            f"producer contains private or machine-specific material ({codes}); "
            "use bundle-relative inputs and environment variables instead"
        )
    return source


def record_for_bundle(
    artifact_path: str | Path,
    *,
    claim: str | None = None,
    grammar: str | None = None,
    producer: str | Path | None = None,
    statistics_status: str | None = None,
    proof: bool = False,
):
    """Build a master ReproFig record from the fixed plot-that bundle layout."""

    reprofig = _reprofig()
    target = Path(artifact_path).expanduser().resolve()
    bundle = _bundle_for_artifact(target)
    table = _required_file(
        bundle_table(bundle), "exact plotted table"
    )
    source_index = _required_file(bundle_source_index(bundle), "source index")
    readme = _required_file(bundle / "README.md", "bundle README")
    producer_path = _resolve_producer(bundle, producer)
    producer_relative = producer_path.relative_to(bundle).as_posix()
    producer_source = _producer_source(producer_path)

    input_sources = _source_rows(bundle, source_index)
    sources = [
        *input_sources,
        _file_reference(bundle, source_index, "source_index"),
        _file_reference(bundle, producer_path, "producer"),
        _file_reference(bundle, readme, "documentation"),
    ]

    figure_table = reprofig.table_from_data(
        table.read_bytes(), name="figure_data", purpose="plot_and_statistics"
    )
    tables = [figure_table]
    for derived in bundle_derived_tables(bundle):
        if derived.resolve() == table:
            continue
        tables.append(reprofig.table_from_data(
            derived.read_bytes(),
            name=derived.stem,
            purpose="statistics" if derived.name == "statistics.csv" else "analysis",
        ))

    statistics, final_statistics_status = _statistics(bundle, statistics_status)
    skill_file = Path(__file__).resolve().parents[1] / "SKILL.md"
    helper_file = Path(__file__).resolve()
    reproduction = {
        "bundle_layout": f"plot-that/{PLOT_THAT_RECORD_VERSION}",
        "producer": producer_relative,
        "producer_sha256": sha256(producer_path),
        "producer_language": producer_path.suffix.lower().lstrip(".") or "unknown",
        "producer_source": producer_source,
        "run_command": _run_command(producer_relative, producer_path),
        "working_directory": ".",
        "exact_table": relative_label(bundle, table),
        "exact_table_sha256": sha256(table),
        "source_index": relative_label(bundle, source_index),
        "source_index_sha256": sha256(source_index),
        "readme": "README.md",
        "readme_sha256": sha256(readme),
        "skill_sha256": sha256(skill_file),
        "helper_sha256": sha256(helper_file),
        "environment": _environment(producer_path),
    }
    if producer_path.suffix.lower() == ".py":
        reproduction["script"] = producer_source
    analysis = {
        key: value
        for key, value in {"claim": claim, "grammar": grammar}.items()
        if value
    }
    record = reprofig.build_record(
        title=claim or target.stem.replace("-", " "),
        original_stem=target.stem,
        producer={
            "package": "plot-that",
            "package_version": PLOT_THAT_RECORD_VERSION,
            "function": producer_relative,
            "language": producer_path.suffix.lower().lstrip(".") or "unknown",
        },
        analysis=analysis,
        data_tables=tables,
        statistics=statistics or None,
        sources=sources,
        reproduction=reproduction,
        data_status="complete",
        statistics_status=final_statistics_status,
        extensions={"plot_that": {"bundle": bundle.name}},
    )
    specifications = _typed_statistical_specifications(statistics) if proof else []
    if proof:
        record.extensions["proof"] = {
            "statistical_specifications": [item.to_dict() for item in specifications]
        }
        evidence_ids = [f"table:{table.sha256}" for table in record.data_tables]
        if statistics:
            evidence_ids.append("statistics:reported")
        claims = (
            [reprofig.ScientificClaim(
                text=claim,
                evidence_ids=evidence_ids,
                statistic_ids=[str(item.statistic_id) for item in specifications],
            )]
            if claim
            else []
        )
        record = reprofig.attach_evidence_graph(record, claims=claims)
    if target.is_file():
        try:
            existing = reprofig.extract_record(target)
        except (OSError, ValueError):
            existing = None
        if existing is not None:
            record.figure_id = existing.figure_id
            record.created_at = existing.created_at
            for key in ("render_manifest", "visual_reference"):
                if key in existing.extensions:
                    record.extensions[key] = existing.extensions[key]
            existing_proof = existing.extensions.get("proof")
            if proof and isinstance(existing_proof, dict):
                for key in ("transformations", "statistical_specifications"):
                    if not record.extensions.get("proof", {}).get(key) and existing_proof.get(key):
                        record.extensions.setdefault("proof", {})[key] = existing_proof[key]
            if proof:
                record = reprofig.attach_evidence_graph(record, claims=claims)
    return record


def save_matplotlib_figure(
    figure: Any,
    artifact_path: str | Path,
    *,
    record: Any | None = None,
    claim: str | None = None,
    grammar: str | None = None,
    producer: str | Path | None = None,
    statistics_status: str | None = None,
    dpi: float | None = None,
    render_preset: str | None = None,
    width: float | None = None,
    height: float | None = None,
    format_options: dict[str, Any] | None = None,
    allow_reencode: bool = False,
    savefig_kwargs: dict[str, Any] | None = None,
    proof: bool = False,
    proof_policy: dict[str, Any] | None = None,
):
    """Atomically render a visual carrier with its bundle-derived record."""

    reprofig = _reprofig()
    target = Path(artifact_path).expanduser().resolve()
    carrier = next(
        (
            item["format"]
            for item in reprofig.formats()
            if target.suffix.lower() in item["extensions"]
        ),
        None,
    )
    if carrier not in DIRECT_FIGURE_FORMATS:
        raise ReproFigBundleError(
            f"{target.suffix or target.name} is an enclosing carrier, not a directly "
            "rendered figure; create it first and register it with register.py add"
        )
    if record is None:
        record = record_for_bundle(
            target,
            claim=claim,
            grammar=grammar,
            producer=producer,
            statistics_status=statistics_status,
            proof=bool(proof or proof_policy),
        )
    proof_kwargs = (
        {"proof": proof, "proof_policy": proof_policy}
        if proof or proof_policy
        else {}
    )
    return reprofig.save_figure(
        figure,
        target,
        record=record,
        figure_profile="master",
        dpi=dpi,
        render_preset=render_preset,
        width=width,
        height=height,
        format_options=format_options,
        allow_reencode=allow_reencode,
        savefig_kwargs=savefig_kwargs,
        **proof_kwargs,
    )


def save_matplotlib_svg(
    figure: Any,
    svg_path: str | Path,
    **kwargs: Any,
):
    """Backward-compatible SVG-only name for existing plot producers."""

    target = Path(svg_path)
    if target.suffix.lower() != ".svg":
        raise ReproFigBundleError(f"save_matplotlib_svg requires an SVG path: {target}")
    return save_matplotlib_figure(figure, target, **kwargs)


def embed_bundle_record(
    artifact_path: str | Path,
    *,
    claim: str,
    grammar: str,
    producer: str | Path,
    statistics_status: str,
    proof: bool = False,
    proof_policy: dict[str, Any] | None = None,
):
    """Refresh an existing carrier from the final bundle and validate it."""

    reprofig = _reprofig()
    target = _required_file(
        Path(artifact_path).expanduser().resolve(), "figure artifact"
    )
    record = record_for_bundle(
        target,
        claim=claim,
        grammar=grammar,
        producer=producer,
        statistics_status=statistics_status,
        proof=bool(proof or proof_policy),
    )
    try:
        existing = reprofig.extract_record(target)
    except (OSError, ValueError):
        existing = None
    # A producer such as PyFLASH may already have embedded a richer complete
    # record with semantic render bindings, independent statistical
    # specifications, transformations, signatures, or attestations. The
    # registry is an index over that artifact; it must not replace stronger
    # evidence merely because plot-that would spell the producer metadata
    # differently. Matching the bundle's exact plotted-table digest establishes
    # that the existing record describes this bundle.
    expected_table_hashes = {table.sha256 for table in record.data_tables}
    existing_table_hashes = (
        {table.sha256 for table in existing.data_tables} if existing is not None else set()
    )
    existing_is_authoritative = bool(
        existing is not None
        and existing.data_status == "complete"
        and expected_table_hashes.intersection(existing_table_hashes)
        and (
            statistics_status != "complete"
            or existing.statistics_status == "complete"
        )
        and existing.producer
        and existing.reproduction
    )
    if existing_is_authoritative:
        # Keep the stronger evidence, but never keep its reproduction block: that
        # block digests README, source index, producer and exact table, all of
        # which can change between registrations. Carrying it forward makes the
        # record disagree with the bundle and `verify` report drift for good.
        carried = existing.to_dict()
        stale_reproduction = carried.get("reproduction") or {}
        fresh_reproduction = record.to_dict().get("reproduction") or {}
        carried["reproduction"] = fresh_reproduction
        record = reprofig.FigureRecord.from_dict(carried)
        if stale_reproduction != fresh_reproduction:
            reprofig.embed_file(
                target,
                record,
                output_path=target,
                allow_reencode=target.suffix.lower() in {".avif", ".heif", ".heic"},
            )
    elif existing is None or existing.fingerprint() != record.fingerprint():
        reprofig.embed_file(
            target,
            record,
            output_path=target,
            allow_reencode=target.suffix.lower() in {".avif", ".heif", ".heic"},
        )
    report = reprofig.validate_artifact(
        target,
        expected_profile="master",
        require_complete=True,
        public_safety=False,
    )
    if not report.valid:
        messages = "; ".join(
            issue.message for issue in report.issues if issue.severity == "error"
        )
        raise ReproFigBundleError(f"embedded ReproFig record failed validation: {messages}")
    if proof or proof_policy:
        record, proof_report = reprofig.apply_artifact_policy(
            target, proof_policy, record=record
        )
        try:
            setattr(record, "_plot_that_proof_report", proof_report)
        except Exception:
            pass
    return record


def mirror_bundle_record(
    master_path: str | Path,
    artifact_paths: list[str | Path],
    *,
    proof_policy: dict[str, Any] | None = None,
) -> list[Path]:
    """Copy one validated master record into sibling carrier representations."""

    reprofig = _reprofig()
    master = _required_file(
        Path(master_path).expanduser().resolve(), "registered master artifact"
    )
    bundle = _bundle_for_artifact(master)
    master_report = reprofig.validate_artifact(
        master,
        expected_profile="master",
        require_complete=True,
        public_safety=False,
    )
    if not master_report.valid:
        messages = "; ".join(
            issue.message
            for issue in master_report.issues
            if issue.severity == "error"
        )
        raise ReproFigBundleError(f"master ReproFig record failed validation: {messages}")
    record = reprofig.extract_record(master)
    outputs: list[Path] = []
    for value in artifact_paths:
        target = _required_file(
            Path(value).expanduser().resolve(), "sibling figure artifact"
        )
        if target == master:
            continue
        if _bundle_for_artifact(target) != bundle:
            raise ReproFigBundleError(
                f"sibling artifact must stay in the master's bundle: {target}"
            )
        sibling_record = reprofig.FigureRecord.from_dict(record.to_dict())
        if "render_manifest" in sibling_record.extensions:
            sibling_record = reprofig.refresh_visual_reference(target, sibling_record)
            proof = sibling_record.extensions.get("proof")
            if isinstance(proof, dict):
                proof["signatures"] = []
        try:
            existing = reprofig.extract_record(target)
        except (OSError, ValueError):
            existing = None
        if existing is None or existing.fingerprint() != sibling_record.fingerprint():
            reprofig.embed_file(
                target,
                sibling_record,
                output_path=target,
                allow_reencode=target.suffix.lower() in {".avif", ".heif", ".heic"},
            )
        if proof_policy:
            sibling_policy = dict(proof_policy)
            sibling_policy.pop("encrypt_sections", None)
            sibling_policy.pop("encrypted_sections", None)
            reprofig.apply_artifact_policy(target, sibling_policy, record=sibling_record)
        report = reprofig.validate_artifact(
            target,
            expected_profile="master",
            require_complete=True,
            public_safety=False,
        )
        if not report.valid:
            messages = "; ".join(
                issue.message for issue in report.issues if issue.severity == "error"
            )
            raise ReproFigBundleError(
                f"mirrored ReproFig record failed validation for {target.name}: {messages}"
            )
        outputs.append(target)
    return outputs


def audit_bundle_artifact(
    artifact_path: str | Path,
    *,
    producer: str | Path | None = None,
) -> list[str]:
    """Return drift between an artifact's record and the current bundle files."""

    reprofig = _reprofig()
    target = Path(artifact_path).expanduser().resolve()
    bundle = _bundle_for_artifact(target)
    problems: list[str] = []
    report = reprofig.validate_artifact(
        target,
        expected_profile="master",
        require_complete=True,
        public_safety=False,
    )
    problems.extend(
        f"ReproFig {issue.code}: {issue.message}"
        for issue in report.issues
        if issue.severity == "error"
    )
    if problems:
        return problems
    record = reprofig.extract_record(target)
    if record.schema != reprofig.SCHEMA_ID:
        problems.append(f"embedded schema is {record.schema}, expected {reprofig.SCHEMA_ID}")
    table_path = bundle_table(bundle)
    expected_table = reprofig.table_from_data(
        table_path.read_bytes(), name="figure_data", purpose="plot_and_statistics"
    )
    embedded = next((table for table in record.data_tables if table.name == "figure_data"), None)
    if embedded is None:
        problems.append("embedded figure_data table is missing")
    elif embedded.sha256 != expected_table.sha256:
        problems.append(
            f"embedded figure_data differs from {relative_label(bundle, table_path)}"
        )

    expected_hashes = {
        "exact_table_sha256": sha256(table_path),
        "source_index_sha256": sha256(bundle_source_index(bundle)),
        "readme_sha256": sha256(bundle / "README.md"),
    }
    producer_path = _resolve_producer(bundle, producer)
    expected_hashes["producer_sha256"] = sha256(producer_path)
    for key, expected in expected_hashes.items():
        if record.reproduction.get(key) != expected:
            problems.append(f"embedded {key} differs from the current bundle")
    try:
        _source_rows(bundle, bundle_source_index(bundle))
    except ReproFigBundleError as exc:
        problems.append(str(exc))
    return problems


def audit_bundle_svg(
    svg_path: str | Path,
    *,
    producer: str | Path | None = None,
) -> list[str]:
    """Backward-compatible SVG-only name for existing callers."""

    target = Path(svg_path)
    if target.suffix.lower() != ".svg":
        raise ReproFigBundleError(f"audit_bundle_svg requires an SVG path: {target}")
    return audit_bundle_artifact(target, producer=producer)
