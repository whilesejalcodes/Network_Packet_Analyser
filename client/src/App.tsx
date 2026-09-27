import { useRef, useState, type ChangeEvent, type DragEvent, type FormEvent } from "react";

type AnalysisResult = {
  fileName: string;
  fileSizeBytes: number;
  totalPackets: number;
  totalBytes: number;
  tcpPackets: number;
  udpPackets: number;
  forwarded: number;
  dropped: number;
  applications: Array<{ name: string; count: number; percent: number }>;
  detectedDomains: Array<{ domain: string; application: string; status: string }>;
  blockedTraffic: Array<{ type: string; value: string; status: string }>;
  engineOutput: string;
  outputPcapRecords: number;
  outputPcapBytes: number;
  downloadUrl: string;
  downloadExpiresInSeconds: number;
  notes: string[];
};

type ApiError = {
  error?: string;
  engineOutput?: string;
};

const MAX_FILE_SIZE = 25 * 1024 * 1024;

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(value >= 10 ? 0 : 1)} ${units[unit]}`;
}

function splitRules(value: string): string[] {
  return value.split(/[\n,]/).map((part) => part.trim()).filter(Boolean);
}

function App() {
  const inputRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [blockIps, setBlockIps] = useState("");
  const [blockApps, setBlockApps] = useState("");
  const [blockDomains, setBlockDomains] = useState("");
  const [dragging, setDragging] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [engineErrorOutput, setEngineErrorOutput] = useState("");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [downloading, setDownloading] = useState(false);

  function acceptFile(nextFile?: File) {
    setError("");
    setEngineErrorOutput("");
    setResult(null);
    if (!nextFile) return;
    if (!nextFile.name.toLowerCase().endsWith(".pcap")) {
      setFile(null);
      setError("Choose a classic .pcap file. PCAPNG and other formats are not accepted.");
      return;
    }
    if (nextFile.size > MAX_FILE_SIZE) {
      setFile(null);
      setError("This file is over the 25 MiB upload limit.");
      return;
    }
    setFile(nextFile);
  }

  function onFileChange(event: ChangeEvent<HTMLInputElement>) {
    acceptFile(event.target.files?.[0]);
  }

  function onDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    setDragging(false);
    acceptFile(event.dataTransfer.files?.[0]);
  }

  async function analyze(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!file) {
      setError("Select a .pcap capture before starting analysis.");
      return;
    }

    setLoading(true);
    setError("");
    setEngineErrorOutput("");
    setResult(null);
    const form = new FormData();
    form.append("file", file);
    for (const value of splitRules(blockIps)) form.append("blockIps", value);
    for (const value of splitRules(blockApps)) form.append("blockApps", value);
    for (const value of splitRules(blockDomains)) form.append("blockDomains", value);

    try {
      const response = await fetch("/api/analyze", { method: "POST", body: form });
      const payload = await response.json() as AnalysisResult & ApiError;
      if (!response.ok) {
        setError(payload.error || "The analyzer could not process this capture.");
        setEngineErrorOutput(payload.engineOutput || "");
        return;
      }
      setResult(payload);
    } catch {
      setError("Could not reach the analysis service. Check that the server is running and try again.");
    } finally {
      setLoading(false);
    }
  }

  async function downloadResult() {
    if (!result) return;
    setDownloading(true);
    setError("");
    try {
      const response = await fetch(result.downloadUrl);
      if (!response.ok) {
        const payload = await response.json() as ApiError;
        throw new Error(payload.error || "The filtered PCAP could not be downloaded.");
      }
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `${file?.name.replace(/\.pcap$/i, "") || "capture"}-filtered.pcap`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    } catch (downloadError) {
      setError(downloadError instanceof Error ? downloadError.message : "The filtered PCAP could not be downloaded.");
    } finally {
      setDownloading(false);
    }
  }

  const maxApplicationCount = Math.max(1, ...((result?.applications ?? []).map((item) => item.count)));

  return (
    <main className="app-shell">
      <header className="topbar">
        <a className="brand" href="/" aria-label="Network Packet Analyzer home">
          <span className="brand-mark"><NetworkIcon /></span>
          <span className="brand-copy"><strong>FIELDNOTES</strong><small>NETWORK INTELLIGENCE</small></span>
        </a>
        <div className="topbar-right">
          <span className="system-state"><i /> ENGINE READY</span>
          <span className="build-tag">DPI / 02</span>
        </div>
      </header>

      <div className="page-wrap">
        <section className="hero">
          <div className="hero-copy">
            <p className="eyebrow"><span className="eyebrow-line" /> TRAFFIC INSPECTION / LOCAL ANALYSIS</p>
            <h1>NETWORK PACKET<br /><span>ANALYZER</span></h1>
            <p className="hero-subtitle">Deep Packet Inspection Dashboard</p>
          </div>
          <div className="hero-stamp" aria-hidden="true">
            <div className="stamp-orbit orbit-one" />
            <div className="stamp-orbit orbit-two" />
            <div className="stamp-core"><NetworkIcon /></div>
            <span className="stamp-label">PCAP / DPI</span>
          </div>
        </section>

        <div className="dashboard-grid">
          <section className="control-column">
            <form onSubmit={analyze} className="panel analysis-panel">
              <div className="panel-heading">
                <div>
                  <p className="eyebrow">01 / INPUT</p>
                  <h2>Analyze Network Traffic</h2>
                </div>
                <span className="step-icon"><UploadIcon /></span>
              </div>
              <div
                className={`drop-zone ${dragging ? "is-dragging" : ""} ${file ? "has-file" : ""}`}
                onDragEnter={(event) => { event.preventDefault(); setDragging(true); }}
                onDragOver={(event) => event.preventDefault()}
                onDragLeave={(event) => {
                  if (!event.currentTarget.contains(event.relatedTarget as Node | null)) setDragging(false);
                }}
                onDrop={onDrop}
              >
                <input
                  ref={inputRef}
                  className="visually-hidden"
                  type="file"
                  accept=".pcap,application/vnd.tcpdump.pcap"
                  onChange={onFileChange}
                />
                <div className="drop-icon"><UploadIcon /></div>
                {file ? (
                  <div className="selected-file">
                    <strong title={file.name}>{file.name}</strong>
                    <span>{formatBytes(file.size)} <b>·</b> PCAP capture</span>
                  </div>
                ) : (
                  <div className="drop-copy">
                    <strong>Drop a capture file here</strong>
                    <span>Classic PCAP · Ethernet · up to 25 MiB</span>
                  </div>
                )}
                <button type="button" className="button button-secondary browse-button" onClick={() => inputRef.current?.click()}>
                  {file ? "Replace file" : "Browse files"}
                </button>
              </div>

              <div className="filter-heading">
                <div>
                  <p className="eyebrow">02 / OPTIONAL RULES</p>
                  <h3>Traffic Filtering</h3>
                </div>
                <span className="optional-label">OPTIONAL</span>
              </div>

              <div className="rule-field">
                <label htmlFor="block-ips"><span className="rule-dot dot-cyan" />Blocked IPs</label>
                <textarea id="block-ips" rows={2} placeholder={"192.168.1.50\nOne IPv4 address per line"} value={blockIps} onChange={(event) => setBlockIps(event.target.value)} />
              </div>
              <div className="rule-field">
                <label htmlFor="block-apps"><span className="rule-dot dot-violet" />Blocked Applications</label>
                <textarea id="block-apps" rows={2} placeholder={"YouTube\nUse exact engine labels, e.g. Twitter/X"} value={blockApps} onChange={(event) => setBlockApps(event.target.value)} />
              </div>
              <div className="rule-field">
                <label htmlFor="block-domains"><span className="rule-dot dot-amber" />Blocked Domains</label>
                <textarea id="block-domains" rows={2} placeholder={"facebook\nMatches a case-sensitive substring"} value={blockDomains} onChange={(event) => setBlockDomains(event.target.value)} />
              </div>
              <p className="rule-note"><InfoIcon /> App matching is exact and case-sensitive. Domain rules match literal, case-sensitive substrings.</p>

              {error && <div className="error-message" role="alert"><WarningIcon /><span>{error}</span></div>}
              <button className="button button-primary analyze-button" type="submit" disabled={loading}>
                {loading ? <><span className="spinner" /> ANALYZING CAPTURE</> : <>RUN DEEP INSPECTION <ArrowIcon /></>}
              </button>
              <p className="privacy-note"><LockIcon /> Capture files are analyzed temporarily and then removed.</p>
            </form>

            {engineErrorOutput && (
              <details className="engine-error">
                <summary>View engine output from the failed run</summary>
                <pre>{engineErrorOutput}</pre>
              </details>
            )}
          </section>

          <section className="results-column" aria-live="polite">
            {loading ? (
              <LoadingState fileName={file?.name ?? "capture"} />
            ) : result ? (
              <Results
                result={result}
                maxApplicationCount={maxApplicationCount}
                onDownload={downloadResult}
                downloading={downloading}
              />
            ) : (
              <EmptyState />
            )}
          </section>
        </div>

        <footer className="footer">
          <span>NETWORK PACKET ANALYZER <b>·</b> C++17 DPI ENGINE</span>
          <span>CLASSIC PCAP / ETHERNET</span>
        </footer>
      </div>
    </main>
  );
}

function Results({
  result,
  maxApplicationCount,
  onDownload,
  downloading,
}: {
  result: AnalysisResult;
  maxApplicationCount: number;
  onDownload: () => void;
  downloading: boolean;
}) {
  const [outputOpen, setOutputOpen] = useState(false);
  const metrics = [
    { label: "Total packets", value: result.totalPackets.toLocaleString(), tone: "cyan" },
    { label: "TCP packets", value: result.tcpPackets.toLocaleString(), tone: "blue" },
    { label: "UDP packets", value: result.udpPackets.toLocaleString(), tone: "violet" },
    { label: "Total bytes", value: formatBytes(result.totalBytes), tone: "amber" },
    { label: "Forwarded", value: result.forwarded.toLocaleString(), tone: "green" },
    { label: "Blocked", value: result.dropped.toLocaleString(), tone: "red" },
  ];

  return (
    <div className="results-stack">
      <div className="results-title-row">
        <div>
          <p className="eyebrow"><span className="eyebrow-line" /> ANALYSIS COMPLETE</p>
          <h2>Capture Report</h2>
          <p className="result-filename"><FileIcon /> {result.fileName} <span>·</span> {formatBytes(result.fileSizeBytes)}</p>
        </div>
        <button type="button" className="button button-download" onClick={onDownload} disabled={downloading}>
          {downloading ? <span className="spinner" /> : <DownloadIcon />}
          {downloading ? "Preparing" : "Download filtered PCAP"}
        </button>
      </div>

      <section className="panel summary-panel">
        <div className="section-title">
          <div><p className="eyebrow">03 / MEASURED OUTPUT</p><h3>Summary</h3></div>
          <span className="measured-tag"><i /> FROM ENGINE REPORT</span>
        </div>
        <div className="metrics-grid">
          {metrics.map((metric) => (
            <div className="metric-card" key={metric.label}>
              <span className={`metric-indicator ${metric.tone}`} />
              <span className="metric-label">{metric.label}</span>
              <strong>{metric.value}</strong>
            </div>
          ))}
        </div>
        <div className="pcap-output-line">
          <span><CheckIcon /> OUTPUT PCAP VERIFIED</span>
          <span>{result.outputPcapRecords.toLocaleString()} records <b>·</b> {formatBytes(result.outputPcapBytes)}</span>
        </div>
      </section>

      <section className="panel applications-panel">
        <div className="section-title">
          <div><p className="eyebrow">04 / CLASSIFICATION</p><h3>Application Traffic</h3></div>
          <span className="count-pill">{result.applications.length} types</span>
        </div>
        {result.applications.length ? (
          <div className="app-chart">
            {result.applications.map((application, index) => (
              <div className="app-row" key={`${application.name}-${index}`}>
                <span className="app-name">{application.name}</span>
                <div className="bar-track"><span style={{ width: `${Math.max(2, application.count / maxApplicationCount * 100)}%` }} /></div>
                <strong>{application.count}</strong>
                <small>{application.percent.toFixed(1)}%</small>
              </div>
            ))}
          </div>
        ) : (
          <p className="no-data">The engine did not report application classifications for this capture.</p>
        )}
      </section>

      <section className="panel domains-panel">
        <div className="section-title">
          <div><p className="eyebrow">05 / HOST IDENTIFICATION</p><h3>Detected Domains</h3></div>
          <span className="count-pill">{result.detectedDomains.length} found</span>
        </div>
        {result.detectedDomains.length ? (
          <div className="table-scroll">
            <table>
              <thead><tr><th>Domain</th><th>Application</th><th>Status</th></tr></thead>
              <tbody>
                {result.detectedDomains.map((domain, index) => (
                  <tr key={`${domain.domain}-${index}`}>
                    <td className="domain-cell">{domain.domain}</td>
                    <td>{domain.application}</td>
                    <td><span className={`status-label ${domain.status.startsWith("Matches") ? "status-match" : ""}`}><i />{domain.status}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="no-data">No domains or SNI names were emitted by the engine for this capture.</p>
        )}
      </section>

      <section className="panel blocked-panel">
        <div className="section-title">
          <div><p className="eyebrow">06 / ENFORCEMENT</p><h3>Blocked Traffic</h3></div>
          <span className={`drop-pill ${result.dropped ? "has-drops" : ""}`}>{result.dropped.toLocaleString()} dropped</span>
        </div>
        {result.blockedTraffic.length ? (
          <div className="table-scroll">
            <table>
              <thead><tr><th>Type</th><th>Value</th><th>Status</th></tr></thead>
              <tbody>
                {result.blockedTraffic.map((rule, index) => (
                  <tr key={`${rule.type}-${rule.value}-${index}`}>
                    <td><span className={`rule-type rule-${rule.type.toLowerCase()}`}>{rule.type}</span></td>
                    <td className="domain-cell">{rule.value}</td>
                    <td>{rule.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="no-rules"><span className="rule-dot dot-green" /><span>No blocking rules were submitted. All {result.forwarded.toLocaleString()} forwarded packets passed through.</span></div>
        )}
        <p className="section-footnote">The engine reports total drops, not per-rule match counts. Domain status above reflects rule text matching, not packet-level attribution.</p>
      </section>

      {result.notes.map((note) => <p className="result-note" key={note}><InfoIcon />{note}</p>)}

      <section className="panel output-panel">
        <button type="button" className="output-toggle" aria-expanded={outputOpen} onClick={() => setOutputOpen(!outputOpen)}>
          <span><TerminalIcon /><span><small>TRANSPARENCY / DEBUG</small><strong>Engine Output</strong></span></span>
          <ChevronIcon open={outputOpen} />
        </button>
        {outputOpen && <pre className="engine-output">{result.engineOutput || "The engine returned no text output."}</pre>}
      </section>
      <p className="download-expiry">Filtered PCAP link expires in {Math.round(result.downloadExpiresInSeconds / 60)} minutes or after the first download.</p>
    </div>
  );
}

function EmptyState() {
  return (
    <div className="empty-state">
      <div className="empty-grid" aria-hidden="true" />
      <div className="empty-content">
        <div className="empty-icon"><NetworkIcon /></div>
        <p className="eyebrow">WAITING FOR CAPTURE</p>
        <h2>Inspect the<br /><span>packet stream.</span></h2>
        <p>Choose a classic PCAP file to see the engine’s measured traffic summary, classifications, and filtered output.</p>
        <div className="empty-signals"><span><i /> 01 / UPLOAD</span><span><i /> 02 / INSPECT</span><span><i /> 03 / REPORT</span></div>
      </div>
      <div className="empty-coordinate">DPI / FIELD 01<br />ETHERNET · IPV4</div>
    </div>
  );
}

function LoadingState({ fileName }: { fileName: string }) {
  return (
    <div className="loading-state">
      <div className="scan-radar"><span /><i /><b /></div>
      <p className="eyebrow">ENGINE ACTIVE / PLEASE WAIT</p>
      <h2>Inspecting packets</h2>
      <p>{fileName}</p>
      <div className="loading-track"><span /></div>
      <small>Running the C++ DPI engine and verifying its output PCAP.</small>
    </div>
  );
}

function NetworkIcon() {
  return <svg viewBox="0 0 40 40" fill="none" aria-hidden="true"><circle cx="20" cy="20" r="3" /><circle cx="8" cy="10" r="2.5" /><circle cx="32" cy="9" r="2.5" /><circle cx="9" cy="31" r="2.5" /><circle cx="32" cy="31" r="2.5" /><path d="m10 11 8 7m4 0 8-7m-19 18 8-7m4 0 8 7M11 10h18M10 30h20M8 13v15m24-16v16" /></svg>;
}

function UploadIcon() {
  return <svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 16V4m0 0L7.5 8.5M12 4l4.5 4.5M5 14.5v4A1.5 1.5 0 0 0 6.5 20h11a1.5 1.5 0 0 0 1.5-1.5v-4" /></svg>;
}
function ArrowIcon() {
  return <svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M4 12h15m-6-6 6 6-6 6" /></svg>;
}
function InfoIcon() {
  return <svg viewBox="0 0 20 20" fill="none" aria-hidden="true"><circle cx="10" cy="10" r="7" /><path d="M10 9v4m0-6h.01" /></svg>;
}
function WarningIcon() {
  return <svg viewBox="0 0 20 20" fill="none" aria-hidden="true"><path d="m10 3 7 13H3L10 3Z" /><path d="M10 8v3m0 2h.01" /></svg>;
}
function LockIcon() {
  return <svg viewBox="0 0 20 20" fill="none" aria-hidden="true"><rect x="4" y="8" width="12" height="9" rx="1.5" /><path d="M7 8V5.5a3 3 0 0 1 6 0V8m-3 4v2" /></svg>;
}
function FileIcon() {
  return <svg viewBox="0 0 18 18" fill="none" aria-hidden="true"><path d="M4 2.5h6l4 4v9H4v-13Z" /><path d="M10 2.5v4h4m-7 3h4m-4 3h4" /></svg>;
}
function DownloadIcon() {
  return <svg viewBox="0 0 20 20" fill="none" aria-hidden="true"><path d="M10 3v9m0 0 3.5-3.5M10 12 6.5 8.5M4 13v3h12v-3" /></svg>;
}
function CheckIcon() {
  return <svg viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="m3 8 3 3 7-7" /></svg>;
}
function TerminalIcon() {
  return <svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><rect x="3" y="4" width="18" height="16" rx="2" /><path d="m7 9 3 3-3 3m6 0h4" /></svg>;
}
function ChevronIcon({ open }: { open: boolean }) {
  return <svg className={open ? "chevron is-open" : "chevron"} viewBox="0 0 20 20" fill="none" aria-hidden="true"><path d="m5 7.5 5 5 5-5" /></svg>;
}

export default App;