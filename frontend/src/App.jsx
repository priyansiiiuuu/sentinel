import { useState } from "react";
import "./App.css";

const API_URL = "http://127.0.0.1:8000";

function formatAnalysis(text) {
  const cleaned = text
    .replace(/```python/g, "")
    .replace(/```/g, "")
    .trim();

  const sections = cleaned.split(
    /\*\*(Explanation|Impact|Recommendation):?\*\*/i
  );

  const result = [];

  if (sections[0]?.trim()) {
    result.push({
      title: "Security Analysis",
      content: sections[0].trim(),
    });
  }

  for (let i = 1; i < sections.length; i += 2) {
    result.push({
      title: sections[i].trim(),
      content: sections[i + 1]?.trim() || "",
    });
  }

  return result;
}

function App() {
  const [directory, setDirectory] = useState("");
  const [findings, setFindings] = useState([]);
  const [selected, setSelected] = useState(null);
  const [loading, setLoading] = useState(false);
  const [fixLoading, setFixLoading] = useState(false);
  const [fixedCode, setFixedCode] = useState("");
  const [error, setError] = useState("");

  const scanRepository = async () => {
    if (!directory.trim()) {
      setError("Enter a repository path first.");
      return;
    }

    setLoading(true);
    setError("");
    setFindings([]);
    setSelected(null);
    setFixedCode("");

    try {
      const response = await fetch(`${API_URL}/scan`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          directory: directory.trim(),
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "Scan failed.");
      }

      setFindings(data.findings || []);

      if (data.findings?.length > 0) {
        setSelected(data.findings[0]);
      }
    } catch (err) {
      setError(err.message || "Unable to connect to Sentinel.");
    } finally {
      setLoading(false);
    }
  };

  const generateFix = async () => {
    if (!selected) return;

    setFixLoading(true);
    setError("");
    setFixedCode("");

    try {
      const response = await fetch(`${API_URL}/generate-fix`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          finding: selected,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "Failed to generate fix.");
      }

      setFixedCode(data.fixed_code || "");
    } catch (err) {
      setError(err.message || "Unable to generate fix.");
    } finally {
      setFixLoading(false);
    }
  };

  const criticalCount = findings.filter(
    (finding) => finding.severity === "CRITICAL"
  ).length;

  const highCount = findings.filter(
    (finding) => finding.severity === "HIGH"
  ).length;

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <div className="brand-mark">S</div>

          <div>
            <h1>Sentinel</h1>
            <span>AI Security Engineer</span>
          </div>
        </div>

        <div className="status">
          <span className="status-dot" />
          Local analysis active
        </div>
      </header>

      <main className="container">
        <section className="hero">
          <div>
            <p className="eyebrow">SECURITY CODE REVIEW</p>

            <h2>Find vulnerabilities before attackers do.</h2>

            <p className="hero-text">
              Scan a Python repository with AST based analysis and AI powered
              security reasoning.
            </p>
          </div>
        </section>

        <section className="scan-card">
          <div className="input-header">
            <div>
              <h3>Scan Repository</h3>
              <p>Enter the local path to a Python project.</p>
            </div>
          </div>

          <div className="scan-form">
            <input
              type="text"
              value={directory}
              onChange={(event) => setDirectory(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") {
                  scanRepository();
                }
              }}
              placeholder="/Users/you/Projects/my-app"
            />

            <button onClick={scanRepository} disabled={loading}>
              {loading ? "Scanning..." : "Scan Repository"}
            </button>
          </div>

          {error && <div className="error">{error}</div>}
        </section>

        {findings.length > 0 && (
          <>
            <section className="summary">
              <div className="summary-title">
                <p className="eyebrow">SCAN RESULTS</p>

                <h2>{findings.length} vulnerabilities found</h2>
              </div>

              <div className="stats">
                <div className="stat critical">
                  <strong>{criticalCount}</strong>
                  <span>Critical</span>
                </div>

                <div className="stat high">
                  <strong>{highCount}</strong>
                  <span>High</span>
                </div>

                <div className="stat">
                  <strong>{findings.length}</strong>
                  <span>Total</span>
                </div>
              </div>
            </section>

            <section className="results">
              <div className="finding-list">
                {findings.map((finding, index) => (
                  <button
                    key={`${finding.file}-${finding.line}-${index}`}
                    className={`finding ${
                      selected === finding ? "selected" : ""
                    }`}
                    onClick={() => {
                      setSelected(finding);
                      setFixedCode("");
                    }}
                  >
                    <div
                      className={`severity ${finding.severity.toLowerCase()}`}
                    >
                      {finding.severity}
                    </div>

                    <div className="finding-info">
                      <strong>{finding.type}</strong>

                      <span>
                        {finding.file.split("/").pop()} : line{" "}
                        {finding.line}
                      </span>
                    </div>

                    <span className="arrow">→</span>
                  </button>
                ))}
              </div>

              {selected && (
                <div className="detail-card">
                  <div className="detail-heading">
                    <div>
                      <div
                        className={`severity ${selected.severity.toLowerCase()}`}
                      >
                        {selected.severity}
                      </div>

                      <h2>{selected.type}</h2>

                      <p>
                        {selected.file} · line {selected.line}
                      </p>
                    </div>
                  </div>

                  <div className="code-section">
                    <div className="section-label">SOURCE CODE</div>

                    <pre>
                      <code>{selected.code_snippet}</code>
                    </pre>
                  </div>

                  <div className="ai-section">
                    <div className="ai-label">
                      <span>✦</span>
                      AI SECURITY ANALYSIS
                    </div>

                    <div className="analysis">
                      {formatAnalysis(selected.ai_analysis).map(
                        (section, index) => (
                          <div className="analysis-section" key={index}>
                            <h4>{section.title}</h4>
                            <p>{section.content}</p>
                          </div>
                        )
                      )}
                    </div>
                  </div>

                  <div
                    style={{
                      marginTop: "28px",
                      paddingTop: "24px",
                      borderTop: "1px solid rgba(255,255,255,0.08)",
                    }}
                  >
                    <div
                      className="ai-label"
                      style={{ marginBottom: "16px" }}
                    >
                      <span>✦</span>
                      AI GENERATED FIX
                    </div>

                    <button
                      onClick={generateFix}
                      disabled={fixLoading}
                      style={{
                        width: "100%",
                        padding: "14px 18px",
                        border: "none",
                        borderRadius: "10px",
                        background: "#f1f5f9",
                        color: "#080b12",
                        fontWeight: "700",
                        fontSize: "14px",
                        cursor: fixLoading ? "wait" : "pointer",
                        opacity: fixLoading ? 0.7 : 1,
                      }}
                    >
                      {fixLoading
                        ? "Generating secure fix..."
                        : "Generate Secure Fix"}
                    </button>

                    {fixedCode && (
                      <div style={{ marginTop: "18px" }}>
                        <div className="section-label">SUGGESTED CODE</div>

                        <pre
                          style={{
                            marginTop: "10px",
                            whiteSpace: "pre-wrap",
                            overflowX: "auto",
                          }}
                        >
                          <code>{fixedCode}</code>
                        </pre>

                        <p
                          style={{
                            marginTop: "12px",
                            fontSize: "12px",
                            lineHeight: "1.6",
                            color: "#7f8ba3",
                          }}
                        >
                          Review this AI generated suggestion before applying
                          it to production code.
                        </p>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </section>
          </>
        )}

        {!loading && findings.length === 0 && !error && (
          <section className="empty-state">
            <div className="shield">⌁</div>

            <h3>Ready to secure your code</h3>

            <p>
              Enter a Python repository path above and Sentinel will analyze
              it for security vulnerabilities.
            </p>
          </section>
        )}
      </main>
    </div>
  );
}

export default App;
