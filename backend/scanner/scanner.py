import ast
from pathlib import Path


def get_snippet(source: str, line_number: int, radius: int = 2) -> str:
    lines = source.splitlines()

    start = max(0, line_number - radius - 1)
    end = min(len(lines), line_number + radius)

    snippet_lines = []

    for index in range(start, end):
        snippet_lines.append(
            f"{index + 1}: {lines[index]}"
        )

    return "\n".join(snippet_lines)


def scan_file(file_path: str) -> list[dict]:
    findings = []

    path = Path(file_path)

    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except (SyntaxError, UnicodeDecodeError):
        return findings

    for node in ast.walk(tree):

        # Detect possible hardcoded secrets
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    name = target.id.lower()

                    if any(word in name for word in [
                        "password",
                        "secret",
                        "api_key",
                        "apikey",
                        "token",
                    ]):
                        if isinstance(node.value, ast.Constant):
                            if isinstance(node.value.value, str) and node.value.value:
                                findings.append({
                                    "type": "Hardcoded Secret",
                                    "severity": "HIGH",
                                    "file": str(path),
                                    "line": node.lineno,
                                    "message": (
                                        f"Possible hardcoded secret stored in "
                                        f"variable '{target.id}'."
                                    ),
                                    "code_snippet": get_snippet(
                                        source, node.lineno
                                    ),
                                })

        # Detect shell command execution
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if node.func.attr in ["system", "popen"]:
                    findings.append({
                        "type": "Command Injection Risk",
                        "severity": "HIGH",
                        "file": str(path),
                        "line": node.lineno,
                        "message": (
                            f"Use of os.{node.func.attr}() may allow "
                            "command injection if user input reaches it."
                        ),
                        "code_snippet": get_snippet(
                            source, node.lineno
                        ),
                    })

            elif isinstance(node.func, ast.Name):
                if node.func.id == "eval":
                    findings.append({
                        "type": "Code Injection Risk",
                        "severity": "CRITICAL",
                        "file": str(path),
                        "line": node.lineno,
                        "message": (
                            "eval() executes dynamically supplied Python code "
                            "and can lead to arbitrary code execution."
                        ),
                        "code_snippet": get_snippet(
                            source, node.lineno
                        ),
                    })

    return findings


def scan_directory(directory: str) -> list[dict]:
    all_findings = []

    root = Path(directory).resolve()

    for file_path in root.rglob("*.py"):
        if ".venv" in file_path.parts or "__pycache__" in file_path.parts:
            continue

        findings = scan_file(str(file_path))
        for finding in findings:
            try:
                rel_path = str(Path(finding["file"]).resolve().relative_to(root))
                finding["file"] = rel_path
            except ValueError:
                pass
        all_findings.extend(findings)

    return all_findings

