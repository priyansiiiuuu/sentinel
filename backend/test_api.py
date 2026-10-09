import io
import json
import os
import sys
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from fastapi import UploadFile

from ai.analyzer import analyze_finding, ask_gemini, ask_llm, generate_fix
from main import fix, scan
from utils.archive import extract_zip_safely


def create_test_zip():
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        vulnerable_code = """import os
password = "super_secret_password"
user_input = input("Enter command: ")
os.system(user_input)
result = eval(user_input)
"""
        zf.writestr("vulnerable.py", vulnerable_code)
        zf.writestr("sub/clean.py", "print('hello world')")

    zip_buffer.seek(0)
    return zip_buffer


def test_zip_slip_protection():
    print("--- Testing Zip Slip Protection ---", flush=True)
    temp_dir = tempfile.mkdtemp()
    zip_path = Path(temp_dir) / "malicious.zip"

    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("../../evil.txt", "malicious content")

    try:
        extract_zip_safely(zip_path, Path(temp_dir) / "extracted")
        assert False, "Zip slip not caught"
    except ValueError as e:
        print(f"  SUCCESS: Caught Zip Slip correctly -> {e}", flush=True)


def test_gemini_provider_with_mock_key():
    print("\n--- Testing Gemini API Provider (SDK & HTTP Mock) ---", flush=True)

    # 1. Test SDK mock
    mock_genai_client = MagicMock()
    mock_sdk_response = MagicMock()
    mock_sdk_response.text = (
        "**Explanation:** Mocked Gemini SDK vulnerability explanation.\n\n"
        "**Impact:** High impact.\n\n"
        "**Recommendation:** Use secure environment variable."
    )
    mock_genai_client.models.generate_content.return_value = mock_sdk_response

    with patch.dict(os.environ, {"GEMINI_API_KEY": "test_fake_gemini_api_key_123"}):
        with patch("google.genai.Client", return_value=mock_genai_client):
            response = ask_llm("Analyze this security finding...")
            assert "Mocked Gemini SDK" in response, f"Unexpected response: {response}"
            print("  SUCCESS: ask_llm successfully routed via official google-genai SDK!", flush=True)

    # 2. Test HTTP fallback mock
    fake_http_response = {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {
                            "text": "**Explanation:** Mocked Gemini HTTP vulnerability explanation."
                        }
                    ]
                }
            }
        ]
    }
    mock_response_obj = MagicMock()
    mock_response_obj.read.return_value = json.dumps(fake_http_response).encode("utf-8")
    mock_response_obj.__enter__.return_value = mock_response_obj

    with patch.dict(os.environ, {"GEMINI_API_KEY": "test_fake_gemini_api_key_123"}):
        with patch("google.genai.Client", side_effect=ImportError("SDK not installed")):
            with patch("urllib.request.urlopen", return_value=mock_response_obj) as mock_url:
                response = ask_llm("Analyze this security finding...")
                assert "Mocked Gemini HTTP" in response, f"Unexpected response: {response}"
                assert mock_url.called, "urllib.request.urlopen was not called"
                print("  SUCCESS: ask_llm successfully routed via HTTP fallback!", flush=True)


def test_gemini_503_fallback_scenarios():
    print("\n--- Testing Gemini 503 Fallback Scenarios ---", flush=True)

    # Scenario 1: Primary model succeeds
    mock_client1 = MagicMock()
    resp1 = MagicMock()
    resp1.text = "Primary Model Output"
    mock_client1.models.generate_content.return_value = resp1

    with patch.dict(os.environ, {"GEMINI_API_KEY": "fake_key"}):
        with patch("google.genai.Client", return_value=mock_client1):
            res = ask_llm("test prompt")
            assert res == "Primary Model Output"
            mock_client1.models.generate_content.assert_called_once_with(
                model="gemini-3.8-flash", contents="test prompt"
            )
            print("  SUCCESS: Primary model gemini-3.8-flash succeeded directly!", flush=True)

    # Scenario 2: Primary returns 503 and fallback succeeds (gemini-3.7-flash)
    mock_client2 = MagicMock()

    def side_effect_503(model, contents):
        if model == "gemini-3.8-flash":
            raise Exception("503 Service Unavailable: This model is currently experiencing high demand.")
        elif model == "gemini-3.7-flash":
            resp2 = MagicMock()
            resp2.text = "Fallback Model Output"
            return resp2
        raise ValueError(f"Unexpected model: {model}")

    mock_client2.models.generate_content.side_effect = side_effect_503

    with patch.dict(os.environ, {"GEMINI_API_KEY": "fake_key"}):
        with patch("google.genai.Client", return_value=mock_client2):
            res = ask_llm("test prompt")
            assert res == "Fallback Model Output"
            assert mock_client2.models.generate_content.call_count == 2
            print("  SUCCESS: Primary 503 fallback to gemini-3.7-flash succeeded!", flush=True)

    # Scenario 3: Both models fail with 503
    mock_client3 = MagicMock()
    mock_client3.models.generate_content.side_effect = Exception("503 Service Unavailable: High Demand")

    with patch.dict(os.environ, {"GEMINI_API_KEY": "fake_key"}):
        with patch("google.genai.Client", return_value=mock_client3):
            res = ask_llm("test prompt")
            assert "Gemini API 503 fallback failed" in res
            assert mock_client3.models.generate_content.call_count == 2
            print("  SUCCESS: Both models failed with 503, error reported cleanly!", flush=True)

    # Scenario 4: Non-503 error (401 Invalid Key) does not trigger fallback
    mock_client4 = MagicMock()
    mock_client4.models.generate_content.side_effect = Exception("401 API_KEY_INVALID: Invalid API Key")

    with patch.dict(os.environ, {"GEMINI_API_KEY": "invalid_key"}):
        with patch("google.genai.Client", return_value=mock_client4):
            res = ask_llm("test prompt")
            assert "Gemini API request failed" in res
            # Must ONLY call primary model once
            assert mock_client4.models.generate_content.call_count == 1
            print("  SUCCESS: 401 error did not trigger fallback!", flush=True)


def test_fallback_when_no_api_key():
    print("\n--- Testing Provider Fallback (No Gemini API Key) ---", flush=True)
    with patch.dict(os.environ, {"GEMINI_API_KEY": ""}):
        with patch("ai.analyzer.is_ollama_online", return_value=False):
            response = ask_llm("Analyze this finding...")
            assert "AI Analysis Unavailable" in response, f"Expected offline message, got: {response}"
            print("  SUCCESS: Fallback returns offline message cleanly when no keys/Ollama available!", flush=True)


def test_scan_function():
    print("\n--- Testing /scan Functionality with UploadFile ---", flush=True)
    zip_data = create_test_zip()
    upload_file = UploadFile(filename="test_repo.zip", file=zip_data)

    data = scan(upload_file)

    print("  Response Dictionary:", flush=True)
    print(f"    directory: {data.get('directory')}", flush=True)
    print(f"    findings_count: {data.get('findings_count')}", flush=True)

    findings = data.get("findings", [])
    assert len(findings) == 3, f"Expected 3 findings, got {len(findings)}"

    for f in findings:
        print(f"    Finding: {f['type']} | Severity: {f['severity']} | File: {f['file']} | Line: {f['line']}", flush=True)
        assert not f['file'].startswith("/tmp"), f"File path should be relative, got: {f['file']}"
        assert not f['file'].startswith("\\"), f"File path should not start with slash: {f['file']}"
        assert "ai_analysis" in f, "AI analysis field missing"

    print("  SUCCESS: /scan test passed completely!", flush=True)


def test_generate_fix_endpoint():
    print("\n--- Testing /generate-fix Endpoint ---", flush=True)
    finding = {
        "type": "Hardcoded Secret",
        "severity": "HIGH",
        "file": "vulnerable.py",
        "line": 2,
        "message": "Possible hardcoded secret stored in variable 'password'.",
        "code_snippet": "password = 'super_secret_password'",
    }

    mock_genai_client = MagicMock()
    mock_sdk_response = MagicMock()
    mock_sdk_response.text = "password = os.environ.get('PASSWORD')"
    mock_genai_client.models.generate_content.return_value = mock_sdk_response

    with patch.dict(os.environ, {"GEMINI_API_KEY": "fake_key"}):
        with patch("google.genai.Client", return_value=mock_genai_client):
            from pydantic import BaseModel
            class FixRequest(BaseModel):
                finding: dict

            req = FixRequest(finding=finding)
            res = fix(req)
            assert "fixed_code" in res, "fixed_code missing in response"
            assert "os.environ" in res["fixed_code"], f"Unexpected fix code: {res}"
            print("  SUCCESS: /generate-fix endpoint returned secure code fix via SDK!", flush=True)


if __name__ == "__main__":
    test_zip_slip_protection()
    test_gemini_provider_with_mock_key()
    test_gemini_503_fallback_scenarios()
    test_fallback_when_no_api_key()
    test_scan_function()
    test_generate_fix_endpoint()
    print("\n==========================================")
    print("ALL BACKEND TESTS PASSED SUCCESSFULLY! 🚀")
    print("==========================================")
    sys.exit(0)
