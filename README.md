# Sentinel

## AI Security Engineer for Python Codebases

Sentinel is a local AI assisted security review platform that combines Python AST based static analysis with a local large language model to identify common application security vulnerabilities, explain their impact, and generate remediation suggestions.

## Features

- AST based Python security scanning
- Hardcoded secret detection
- Command injection detection
- Dynamic code execution detection
- Severity classification
- Source code context for findings
- AI powered vulnerability explanation
- AI generated remediation suggestions
- Local LLM inference using Ollama
- React security dashboard
- FastAPI backend

## Tech Stack

**Backend:** Python, FastAPI, Python AST, Uvicorn

**AI:** Ollama, Llama 3.2 3B

**Frontend:** React, Vite, JavaScript, CSS

## Architecture

```text
Python Repository
       │
       ▼
AST Security Scanner
       │
       ▼
Vulnerability Findings
       │
       ├── Severity
       ├── Source Location
       └── Code Snippet
              │
              ▼
        Local LLM Analysis
         Ollama / Llama 3.2
              │
              ▼
       Security Explanation
              │
              ▼
       Remediation Suggestion
              │
              ▼
        React Dashboard
