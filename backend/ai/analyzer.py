import json
import urllib.request


OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
MODEL = "llama3.2:3b"


def ask_ollama(prompt: str) -> str:
    payload = json.dumps({
        "model": MODEL,
        "prompt": prompt,
        "stream": False,
    }).encode("utf-8")

    request = urllib.request.Request(
        OLLAMA_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urllib.request.urlopen(request, timeout=180) as response:
        data = json.loads(response.read().decode("utf-8"))

    return data["response"].strip()


def analyze_finding(finding: dict) -> dict:
    prompt = f"""
You are a senior application security engineer.

Analyze this security finding.

Type: {finding["type"]}
Severity: {finding["severity"]}
File: {finding["file"]}
Line: {finding["line"]}
Message: {finding["message"]}

Code:
{finding.get("code_snippet", "No code snippet available.")}

Return exactly these sections:

**Explanation:**
Explain the vulnerability.

**Impact:**
Explain what an attacker could potentially do.

**Recommendation:**
Explain how the developer should fix it.

Be concise and technically accurate.
Do not invent facts about the application.
"""

    analysis = ask_ollama(prompt)

    return {
        **finding,
        "ai_analysis": analysis,
    }


def generate_fix(finding: dict) -> str:
    prompt = f"""
You are a senior secure software engineer.

Fix this security vulnerability.

Vulnerability:
{finding["type"]}

Severity:
{finding["severity"]}

File:
{finding["file"]}

Line:
{finding["line"]}

Message:
{finding["message"]}

Vulnerable code:
{finding.get("code_snippet", "No code snippet available.")}

Return ONLY the corrected code snippet.

Rules:
1. Preserve the original intent of the code.
2. Remove or mitigate the security vulnerability.
3. Do not add explanations.
4. Do not use markdown code fences.
5. Do not invent unrelated application code.
"""

    return ask_ollama(prompt)
