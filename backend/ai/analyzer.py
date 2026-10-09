import json
import os
import socket
import urllib.request

try:
    from google import genai
    HAS_GENAI_SDK = True
except ImportError:
    HAS_GENAI_SDK = False


GEMINI_MODEL = "gemini-3.8-flash"
OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
OLLAMA_MODEL = "llama3.2:3b"


def ask_gemini(prompt: str, api_key: str) -> str:
    """
    Queries Google Gemini API using official google-genai Python SDK.
    """
    if HAS_GENAI_SDK:
        try:
            client = genai.Client(api_key=api_key)
            response = client.models.generate_content(
                model=GEMINI_MODEL,
                contents=prompt,
            )
            if response and response.text:
                return response.text.strip()
            return "AI Analysis Error: Empty response returned by Gemini API."
        except Exception as err:
            return f"AI Analysis Error (Gemini API request failed: {err})"

    # Fallback to direct HTTP request if SDK is not present
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent?key={api_key}"
    payload = json.dumps({
        "contents": [
            {
                "parts": [
                    {"text": prompt}
                ]
            }
        ]
    }).encode("utf-8")

    request = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            data = json.loads(response.read().decode("utf-8"))
            return data["candidates"][0]["content"]["parts"][0]["text"].strip()
    except Exception as err:
        return f"AI Analysis Error (Gemini API HTTP request failed: {err})"


def is_ollama_online(host: str = "127.0.0.1", port: int = 11434, timeout: float = 0.2) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def ask_ollama(prompt: str) -> str:
    if not is_ollama_online():
        return "AI Analysis Unavailable: Local Ollama service is offline."

    payload = json.dumps({
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
    }).encode("utf-8")

    request = urllib.request.Request(
        OLLAMA_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            data = json.loads(response.read().decode("utf-8"))
        return data["response"].strip()
    except Exception as err:
        return f"AI Analysis Unavailable: Ollama request failed ({err})."


def ask_llm(prompt: str) -> str:
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()

    if api_key:
        return ask_gemini(prompt, api_key)

    if is_ollama_online():
        return ask_ollama(prompt)

    return (
        "AI Analysis Unavailable: Please set GEMINI_API_KEY environment variable "
        "or start local Ollama service."
    )


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

    analysis = ask_llm(prompt)

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

    return ask_llm(prompt)
