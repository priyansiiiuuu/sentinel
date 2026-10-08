from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from scanner.scanner import scan_directory
from ai.analyzer import analyze_finding, generate_fix


app = FastAPI(title="Sentinel", version="0.2.0")


app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    directory: str


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
def scan(request: ScanRequest):
    try:
        findings = scan_directory(request.directory)

        analyzed_findings = [
            analyze_finding(finding)
            for finding in findings
        ]

        return {
            "directory": request.directory,
            "findings_count": len(analyzed_findings),
            "findings": analyzed_findings,
        }

    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/generate-fix")
def fix(request: FixRequest):
    try:
        fixed_code = generate_fix(request.finding)

        return {
            "fixed_code": fixed_code,
        }

    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
