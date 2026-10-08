import shutil
import tempfile
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from ai.analyzer import analyze_finding, generate_fix
from scanner.scanner import scan_directory
from utils.archive import extract_zip_safely


app = FastAPI(title="Sentinel", version="0.2.0")


app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class FixRequest(BaseModel):
    finding: dict


@app.get("/")
def root():
    return {
        "name": "Sentinel",
        "message": "AI Security Engineer API",
        "status": "running",
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/scan")
def scan(file: UploadFile = File(...)):

    if not file.filename.endswith(".zip"):
        raise HTTPException(
            status_code=400,
            detail="Only .zip files are supported for repository scanning.",
        )

    temp_dir = tempfile.mkdtemp()
    zip_path = Path(temp_dir) / file.filename

    try:
        # Save uploaded ZIP to temporary file
        with open(zip_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # Extract ZIP safely with Zip Slip protection
        extract_dir = Path(temp_dir) / "extracted"
        extract_dir.mkdir(parents=True, exist_ok=True)
        extract_zip_safely(zip_path, extract_dir)

        # Run AST security scanner
        findings = scan_directory(str(extract_dir))

        # Perform AI analysis on findings
        analyzed_findings = [
            analyze_finding(finding)
            for finding in findings
        ]

        return {
            "directory": file.filename,
            "findings_count": len(analyzed_findings),
            "findings": analyzed_findings,
        }

    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=str(val_err))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    finally:
        # Ensure temporary files are completely cleaned up
        shutil.rmtree(temp_dir, ignore_errors=True)


@app.post("/generate-fix")
def fix(request: FixRequest):
    try:
        fixed_code = generate_fix(request.finding)

        return {
            "fixed_code": fixed_code,
        }

    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
