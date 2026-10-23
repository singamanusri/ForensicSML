"""Flask application: Stage 1 (evidence management). Routes stay thin;
logic lives in utils/ and models/."""
import csv
import json
import runpy
import uuid
from datetime import datetime
from pathlib import Path

import pandas as pd
from flask import (Flask, Response, abort, flash, redirect, render_template,
                   request, send_file, url_for)

from utils.hashing import sha256_file
from utils.validation import (OPTIONAL_COLUMNS, REQUIRED_COLUMNS, TEMPLATE_CSV,
                              validate_dataframe)
from models.statistics import analyze_evidence

BASE_DIR = Path(__file__).resolve().parent
INSTANCE = BASE_DIR / "instance"
EVIDENCE_DIR = INSTANCE / "evidence"
VALIDATION_DIR = INSTANCE / "validation"
REGISTRY = INSTANCE / "evidence_registry.csv"
SAMPLE = BASE_DIR / "data" / "sample_evidence.csv"
FIELDS = ["evidence_id", "original_filename", "stored_name", "upload_time", "sha256",
          "size_bytes", "rows_total", "rows_valid", "rows_invalid", "has_labels", "is_sample"]
MAX_UPLOAD_BYTES = 5 * 1024 * 1024
MAX_ROWS = 100_000
PAGE_SIZE = 25

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES
app.config["SECRET_KEY"] = uuid.uuid4().hex  # local-only; regenerated each start


# ---------------------------------------------------------------- registry
def _ensure_dirs():
    for d in (EVIDENCE_DIR, VALIDATION_DIR):
        d.mkdir(parents=True, exist_ok=True)


def load_registry():
    if not REGISTRY.exists():
        return []
    with open(REGISTRY, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def get_record(evidence_id):
    return next((r for r in load_registry() if r["evidence_id"] == evidence_id), None)


def _append_registry(row):
    new = not REGISTRY.exists()
    with open(REGISTRY, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        if new:
            w.writeheader()
        w.writerow(row)


def read_raw_csv(path):
    """Read as text exactly as stored (no type guessing)."""
    return pd.read_csv(path, dtype=str, keep_default_na=False, encoding="utf-8-sig", nrows=MAX_ROWS + 1)


def ingest(src_path, original_name, is_sample=False):
    """Hash, validate and register a file already saved in EVIDENCE_DIR.
    Returns (record or None, report)."""
    try:
        raw = read_raw_csv(src_path)
    except (pd.errors.EmptyDataError, pd.errors.ParserError, UnicodeDecodeError) as exc:
        return None, {"errors": [f"Could not read file as CSV: {exc}"], "warnings": [], "issues": []}
    if len(raw) > MAX_ROWS:
        return None, {"errors": [f"File has more than {MAX_ROWS:,} rows."], "warnings": [], "issues": []}
    _, report = validate_dataframe(raw)
    if report["errors"]:
        return None, report
    ev_id = "sample" if is_sample else "EV-" + uuid.uuid4().hex[:8].upper()
    record = {
        "evidence_id": ev_id, "original_filename": original_name,
        "stored_name": Path(src_path).name,
        "upload_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "sha256": sha256_file(src_path), "size_bytes": Path(src_path).stat().st_size,
        "rows_total": report["rows_total"], "rows_valid": report["rows_valid"],
        "rows_invalid": report["rows_invalid"], "has_labels": report["has_labels"],
        "is_sample": is_sample,
    }
    (VALIDATION_DIR / f"{ev_id}.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    _append_registry(record)
    return record, report


def bootstrap():
    _ensure_dirs()
    if not SAMPLE.exists():
        runpy.run_path(str(BASE_DIR / "data" / "generate_sample_data.py"), run_name="__main__")
    if not any(r["evidence_id"] == "sample" for r in load_registry()):
        dest = EVIDENCE_DIR / "sample.csv"
        dest.write_bytes(SAMPLE.read_bytes())
        ingest(dest, "sample_evidence.csv (synthetic)", is_sample=True)


# ------------------------------------------------------------------ routes
@app.route("/")
def dashboard():
    reg = load_registry()
    stats = {
        "files": len(reg),
        "records": sum(int(r["rows_valid"]) for r in reg),
        "labelled": sum(r["has_labels"] == "True" for r in reg),
        "latest": reg[-1] if reg else None,
    }

    analysis = {}
    sample_path = EVIDENCE_DIR / "sample.csv"
    if sample_path.exists():
        try:
            analysis = analyze_evidence(sample_path)
        except Exception as exc:
            app.logger.exception("Statistical analysis failed: %s", exc)

    return render_template(
        "dashboard.html",
        stats=stats,
        registry=reg[::-1][:5],
        analysis=analysis,
    )


@app.route("/evidence")
def evidence():
    return render_template("evidence.html", registry=load_registry()[::-1],
                           required=REQUIRED_COLUMNS, optional=OPTIONAL_COLUMNS,
                           max_mb=MAX_UPLOAD_BYTES // (1024 * 1024))


@app.route("/evidence/upload", methods=["POST"])
def upload():
    f = request.files.get("file")
    if not f or not f.filename:
        flash("Please choose a CSV file first.", "warning")
        return redirect(url_for("evidence"))
    if not f.filename.lower().endswith(".csv"):
        flash("Only .csv files are accepted.", "danger")
        return redirect(url_for("evidence"))
    _ensure_dirs()
    stored = EVIDENCE_DIR / f"{uuid.uuid4().hex}.csv"  # never trust the client filename for storage
    f.save(stored)
    original = Path(f.filename).name[:120]
    record, report = ingest(stored, original)
    if record is None:
        stored.unlink(missing_ok=True)
        flash("Upload rejected: " + " ".join(report["errors"]), "danger")
        return redirect(url_for("evidence"))
    flash(f"Evidence registered as {record['evidence_id']}: {record['rows_valid']} valid and "
          f"{record['rows_invalid']} invalid row(s).", "success" if not record["rows_invalid"] else "warning")
    return redirect(url_for("evidence_detail", evidence_id=record["evidence_id"]))


@app.route("/evidence/<evidence_id>")
def evidence_detail(evidence_id):
    rec = get_record(evidence_id)
    if not rec:
        abort(404)
    path = EVIDENCE_DIR / rec["stored_name"]
    if not path.exists():
        flash("The stored evidence file is missing from disk.", "danger")
        return redirect(url_for("evidence"))
    raw = read_raw_csv(path)
    page = max(1, request.args.get("page", 1, type=int))
    pages = max(1, -(-len(raw) // PAGE_SIZE))
    page = min(page, pages)
    chunk = raw.iloc[(page - 1) * PAGE_SIZE: page * PAGE_SIZE]
    report = json.loads((VALIDATION_DIR / f"{evidence_id}.json").read_text(encoding="utf-8"))
    return render_template("evidence_detail.html", rec=rec, report=report, columns=list(raw.columns),
                           rows=chunk.values.tolist(), first_row=(page - 1) * PAGE_SIZE + 2,
                           page=page, pages=pages)


@app.route("/evidence/<evidence_id>/verify", methods=["POST"])
def verify(evidence_id):
    rec = get_record(evidence_id)
    if not rec:
        abort(404)
    current = sha256_file(EVIDENCE_DIR / rec["stored_name"])
    if current == rec["sha256"]:
        flash("Integrity check PASSED: the file hash matches the hash recorded at upload.", "success")
    else:
        flash("Integrity check FAILED: the file has changed since it was recorded.", "danger")
    return redirect(url_for("evidence_detail", evidence_id=evidence_id))


@app.route("/download/template")
def download_template():
    return Response(TEMPLATE_CSV, mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=evidence_template.csv"})


@app.route("/download/sample")
def download_sample():
    return send_file(SAMPLE, as_attachment=True, download_name="sample_evidence_synthetic.csv")


@app.errorhandler(413)
def too_large(_):
    flash(f"File too large (limit {MAX_UPLOAD_BYTES // (1024 * 1024)} MB).", "danger")
    return redirect(url_for("evidence"))


@app.errorhandler(404)
def not_found(_):
    return render_template("404.html"), 404


bootstrap()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
