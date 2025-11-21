from fastapi import FastAPI, Body
from pydantic import BaseModel
from typing import List, Optional, Dict
import re
import json

app = FastAPI(title="MM-IM Remediator – S/4HANA Table Replacement")

# ------------------------------------------------------------
# TABLE MAP
# ------------------------------------------------------------
CORE_DOC_MAP = {
    "MKPF": {"new": "MATDOC"},
    "MSEG": {"new": "MATDOC"},
}

HYBRID_MAP = {
    "MARC": {"new": "NSDM_V_MARC"},
    "MARD": {"new": "NSDM_V_MARD"},
    "MCHB": {"new": "NSDM_V_MCHB"},
    "MKOL": {"new": "NSDM_V_MKOL"},
    "MSLB": {"new": "NSDM_V_MSLB"},
    "MSKA": {"new": "NSDM_V_MSKA"},
    "MSPR": {"new": "NSDM_V_MSPR"},
    "MSKU": {"new": "NSDM_V_MSKU"},
}

AGGR_MAP = {
    "MSSA": {"new": "NSDM_V_MSSA"},
    "MSSL": {"new": "NSDM_V_MSSL"},
    "MSSQ": {"new": "NSDM_V_MSSQ"},
    "MSTB": {"new": "NSDM_V_MSTB"},
    "MSTE": {"new": "NSDM_V_MSTE"},
    "MSTQ": {"new": "NSDM_V_MSTQ"},
}

DIMP_MAP = {
    "MCSD": {"new": "NSDM_V_MCSD"},
    "MCSS": {"new": "NSDM_V_MCSS"},
    "MSCD": {"new": "NSDM_V_MSCD"},
    "MSFS": {"new": "NSDM_V_MSFS"},
}

HISTORY_MAP = {
    "MARCH": {"new": "NSDM_V_MARCH"},
    "MARDH": {"new": "NSDM_V_MARDH"},
}

TABLE_MAP = {
    **CORE_DOC_MAP,
    **HYBRID_MAP,
    **AGGR_MAP,
    **DIMP_MAP,
    **HISTORY_MAP,
}

# ------------------------------------------------------------
# REGEX
# ------------------------------------------------------------
TABLE_NAMES = sorted(TABLE_MAP.keys(), key=len, reverse=True)

TABLE_RE = re.compile(
    rf"\b(?P<table>{'|'.join(TABLE_NAMES)})\b",
    re.IGNORECASE
)

# ------------------------------------------------------------
# MODELS
# ------------------------------------------------------------
class Finding(BaseModel):
    prog_name: Optional[str] = None
    incl_name: Optional[str] = None
    types: Optional[str] = None
    blockname: Optional[str] = None
    starting_line: Optional[int] = None
    ending_line: Optional[int] = None
    issues_type: Optional[str] = None
    severity: Optional[str] = None
    message: Optional[str] = None
    suggestion: Optional[str] = None
    snippet: Optional[str] = None

class Unit(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = None
    code: Optional[str] = ""
    findings: Optional[List[Finding]] = None

# ------------------------------------------------------------
# HELPERS
# ------------------------------------------------------------
def get_line(text: str, off: int) -> int:
    return text.count("\n", 0, off) + 1

def extract_line(text: str, pos: int) -> str:
    s = text.rfind("\n", 0, pos) + 1
    e = text.find("\n", pos)
    if e == -1:
        e = len(text)
    return text[s:e].strip()

# ------------------------------------------------------------
# CORE LOGIC
# ------------------------------------------------------------
def scan_unit(unit: Unit) -> Unit:
    src = unit.code or ""
    findings: List[Finding] = []

    for m in TABLE_RE.finditer(src):
        table = m.group("table").upper()
        new_table = TABLE_MAP.get(table, {}).get("new")
        if not new_table:
            continue

        # Skip write statements
        line_text = extract_line(src, m.start()).upper()

        if (
            line_text.startswith("UPDATE " + table)
            or line_text.startswith("MODIFY " + table)
            or line_text.startswith("DELETE FROM " + table)
        ):
            continue

        findings.append(Finding(
            prog_name=unit.pgm_name,
            incl_name=unit.inc_name,
            types=unit.type,
            blockname=unit.name,
            starting_line=get_line(src, m.start()),
            ending_line=get_line(src, m.start()),
            issues_type="MM_ObsoleteTable",
            severity="error",
            message=f"Obsolete table '{table}' used. Replace with '{new_table}'.",
            suggestion=f"Replace '{table}' with '{new_table}'.",
            snippet=extract_line(src, m.start())
        ))

    unit.findings = findings
    return unit

# ------------------------------------------------------------
# ENDPOINTS  (REFERENCE STYLE)
# ------------------------------------------------------------
@app.post("/remediate-array", response_model=List[Unit])
async def remediate_array(units: List[Unit] = Body(...)):
    results: List[Unit] = []
    for u in units:
        res = scan_unit(u)
        if res.findings:
            results.append(res)
    return results

@app.post("/remediate", response_model=Unit)
async def remediate_single(unit: Unit = Body(...)):
    return scan_unit(unit)

@app.get("/health")
async def health():
    return {"ok": True, "rule": "MM-IM"}
