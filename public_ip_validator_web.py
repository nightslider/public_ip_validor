#!/usr/bin/env python3
"""Browser-based web app for public_ip_validator.py."""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

import public_ip_validator as validator


# A single-file web app keeps deployment simple: Python serves this page and the API.
HTML_PAGE = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Public IP Validator</title>
  <style>
    :root {
      --bg: #eef2ee;
      --panel: #ffffff;
      --ink: #17201a;
      --muted: #637066;
      --line: #d7ded8;
      --accent: #0f766e;
      --accent-strong: #115e59;
      --pass: #0f7b3d;
      --warn: #9a5b00;
      --fail: #b00020;
      --info: #315f86;
      --shadow: 0 18px 45px rgba(23, 32, 26, 0.12);
    }

    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      min-height: 100vh;
      color: var(--ink);
      font-family: "Aptos", "Bahnschrift", "Segoe UI", sans-serif;
      background:
        linear-gradient(135deg, rgba(15, 118, 110, 0.14), transparent 34%),
        radial-gradient(circle at top right, rgba(255, 196, 87, 0.18), transparent 30%),
        var(--bg);
    }

    main {
      width: min(1180px, calc(100% - 32px));
      margin: 0 auto;
      padding: 28px 0 36px;
    }

    .topbar {
      display: flex;
      align-items: end;
      justify-content: space-between;
      gap: 20px;
      margin-bottom: 18px;
    }

    h1 {
      margin: 0 0 6px;
      font-family: "Aptos Display", "Bahnschrift", sans-serif;
      font-size: clamp(2rem, 5vw, 4rem);
      line-height: 0.98;
      letter-spacing: 0;
    }

    .subtitle {
      margin: 0;
      max-width: 720px;
      color: var(--muted);
      font-size: 1.02rem;
    }

    .layout {
      display: grid;
      grid-template-columns: minmax(280px, 390px) 1fr;
      gap: 18px;
      align-items: start;
    }

    .panel {
      background: rgba(255, 255, 255, 0.92);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
    }

    form.panel {
      padding: 18px;
      position: sticky;
      top: 18px;
    }

    .field {
      display: grid;
      gap: 7px;
      margin-bottom: 14px;
    }

    label,
    .legend {
      color: #2e3b32;
      font-weight: 700;
      font-size: 0.92rem;
    }

    input,
    select {
      width: 100%;
      min-height: 42px;
      border: 1px solid #c3ccc4;
      border-radius: 6px;
      padding: 9px 10px;
      color: var(--ink);
      background: #fbfdfb;
      font: inherit;
    }

    input:focus,
    select:focus {
      outline: 3px solid rgba(15, 118, 110, 0.18);
      border-color: var(--accent);
    }

    .split {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
    }

    .toggle {
      display: flex;
      align-items: center;
      gap: 10px;
      margin: 8px 0 16px;
      color: #2e3b32;
      font-weight: 700;
    }

    .toggle input {
      width: 18px;
      min-height: 18px;
      accent-color: var(--accent);
    }

    button {
      width: 100%;
      min-height: 46px;
      border: 0;
      border-radius: 6px;
      background: var(--accent);
      color: white;
      font: inherit;
      font-weight: 800;
      cursor: pointer;
    }

    button:hover {
      background: var(--accent-strong);
    }

    button:disabled {
      cursor: progress;
      opacity: 0.72;
    }

    .results {
      display: grid;
      gap: 14px;
    }

    .verdict {
      padding: 18px;
      display: grid;
      grid-template-columns: auto 1fr;
      gap: 12px;
      align-items: center;
      min-height: 90px;
    }

    .verdict-icon {
      width: 54px;
      height: 54px;
      display: grid;
      place-items: center;
      border-radius: 8px;
      background: #eef7f4;
      font-size: 1.8rem;
    }

    .verdict h2 {
      margin: 0 0 4px;
      font-size: 1.15rem;
    }

    .verdict p {
      margin: 0;
      color: var(--muted);
    }

    .checks {
      overflow: hidden;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      table-layout: fixed;
    }

    th,
    td {
      padding: 12px 14px;
      border-bottom: 1px solid var(--line);
      text-align: left;
      vertical-align: top;
      overflow-wrap: anywhere;
    }

    th {
      color: #2e3b32;
      background: #f7faf7;
      font-size: 0.84rem;
      text-transform: uppercase;
    }

    th:first-child,
    td:first-child {
      width: 110px;
    }

    .status {
      font-weight: 800;
      white-space: nowrap;
    }

    .PASS .status { color: var(--pass); }
    .WARN .status { color: var(--warn); }
    .FAIL .status { color: var(--fail); }
    .ERROR .status { color: var(--fail); }
    .INFO .status { color: var(--info); }

    .summary {
      color: var(--muted);
      margin-top: 4px;
    }

    details {
      margin-top: 8px;
      color: #38433b;
    }

    details ul {
      margin: 8px 0 0;
      padding-left: 18px;
    }

    .empty {
      padding: 28px 18px;
      color: var(--muted);
    }

    @media (max-width: 860px) {
      main {
        width: min(100% - 22px, 680px);
        padding-top: 18px;
      }

      .topbar,
      .layout,
      .split {
        grid-template-columns: 1fr;
        display: grid;
      }

      form.panel {
        position: static;
      }

      table,
      thead,
      tbody,
      tr,
      th,
      td {
        display: block;
      }

      thead {
        display: none;
      }

      tr {
        border-bottom: 1px solid var(--line);
        padding: 10px 0;
      }

      td {
        border: 0;
        padding: 6px 14px;
      }

      th:first-child,
      td:first-child {
        width: auto;
      }
    }
  </style>
</head>
<body>
  <main>
    <section class="topbar">
      <div>
        <h1>Public IP Validator</h1>
        <p class="subtitle">Run the same ISP, routability, DNS, subnet, and gateway checks from a browser.</p>
      </div>
    </section>

    <section class="layout">
      <form class="panel" id="validator-form">
        <div class="field">
          <label for="ip">IP address</label>
          <input id="ip" name="ip" autocomplete="off" placeholder="Blank = auto-detect server public IP">
        </div>

        <div class="split">
          <div class="field">
            <label for="subnet-mask">Subnet mask / prefix</label>
            <input id="subnet-mask" name="subnet_mask" autocomplete="off" placeholder="255.255.255.0">
          </div>
          <div class="field">
            <label for="gateway">Default gateway</label>
            <input id="gateway" name="gateway" autocomplete="off" placeholder="8.8.8.1">
          </div>
        </div>

        <label class="toggle">
          <input type="checkbox" id="reverse-dns" name="reverse_dns">
          Check reverse DNS (PTR)
        </label>

        <div class="field">
          <label for="dns-policy">Known DNS policy</label>
          <select id="dns-policy" name="dns_policy">
            <option value="fail">Fail</option>
            <option value="warn">Warn</option>
            <option value="ignore">Ignore</option>
          </select>
        </div>

        <button id="submit-button" type="submit">Run validation</button>
      </form>

      <section class="results">
        <div class="panel verdict" id="verdict">
          <div class="verdict-icon" id="verdict-icon">ℹ</div>
          <div>
            <h2 id="verdict-title">Ready</h2>
            <p id="verdict-text">Enter an IP address, or leave it blank to detect the web server's public IP.</p>
          </div>
        </div>

        <div class="panel checks">
          <table aria-label="Validation checks">
            <thead>
              <tr>
                <th>Status</th>
                <th>Check</th>
                <th>Summary</th>
              </tr>
            </thead>
            <tbody id="checks-body">
              <tr><td colspan="3" class="empty">Results will appear here.</td></tr>
            </tbody>
          </table>
        </div>
      </section>
    </section>
  </main>

  <script>
    const form = document.querySelector("#validator-form");
    const button = document.querySelector("#submit-button");
    const checksBody = document.querySelector("#checks-body");
    const verdictIcon = document.querySelector("#verdict-icon");
    const verdictTitle = document.querySelector("#verdict-title");
    const verdictText = document.querySelector("#verdict-text");
    const symbols = { PASS: "✅", WARN: "⚠", FAIL: "⛔", ERROR: "⛔", INFO: "ℹ" };

    // Update the verdict banner without replacing the rest of the page.
    function setVerdict(status, title, message) {
      verdictIcon.textContent = symbols[status] || "ℹ";
      verdictTitle.textContent = title;
      verdictText.textContent = message;
    }

    // All server-provided values are escaped before being inserted into HTML.
    function escapeHtml(value) {
      return String(value).replace(/[&<>'"]/g, (char) => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        "'": "&#39;",
        "\"": "&quot;"
      }[char]));
    }

    // Render each validation check as a table row with optional expandable details.
    function renderChecks(checks) {
      if (!checks.length) {
        checksBody.innerHTML = '<tr><td colspan="3" class="empty">No checks returned.</td></tr>';
        return;
      }

      checksBody.innerHTML = checks.map((check) => {
        const details = check.details.length
          ? `<details><summary>Details</summary><ul>${check.details.map((line) => `<li>${escapeHtml(line)}</li>`).join("")}</ul></details>`
          : "";
        return `<tr class="${escapeHtml(check.status)}">
          <td class="status">${symbols[check.status] || "ℹ"} ${escapeHtml(check.status)}</td>
          <td>${escapeHtml(check.name)}</td>
          <td><div>${escapeHtml(check.summary || "")}</div>${details}</td>
        </tr>`;
      }).join("");
    }

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      // Disable the button while the backend performs network lookups.
      button.disabled = true;
      button.textContent = "Running...";
      setVerdict("INFO", "Working", "Network checks are running.");
      checksBody.innerHTML = '<tr><td colspan="3" class="empty">Running checks...</td></tr>';

      const payload = {
        candidate: form.ip.value.trim() || null,
        subnet_mask: form.subnet_mask.value.trim() || null,
        gateway: form.gateway.value.trim() || null,
        reverse_dns: form.reverse_dns.checked,
        dns_policy: form.dns_policy.value
      };

      try {
        // The browser UI stays thin; the Python backend owns all validation rules.
        const response = await fetch("/api/validate", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });
        const data = await response.json();
        if (!response.ok) {
          throw new Error(data.error || "Validation failed");
        }
        setVerdict(data.verdict.status, `Finished checking ${data.ip}`, data.verdict.message);
        renderChecks(data.checks);
      } catch (error) {
        setVerdict("ERROR", "Validation error", error.message);
        checksBody.innerHTML = '<tr><td colspan="3" class="empty">The validation could not be completed.</td></tr>';
      } finally {
        button.disabled = false;
        button.textContent = "Run validation";
      }
    });
  </script>
</body>
</html>
"""


def run_validation(options: dict[str, Any]) -> dict[str, Any]:
  # Normalize browser form values before passing them to the shared validator.
    candidate = (options.get("candidate") or "").strip() or None
    subnet_mask = (options.get("subnet_mask") or "").strip() or None
    gateway = (options.get("gateway") or "").strip() or None
    reverse_dns = bool(options.get("reverse_dns"))
    dns_policy = options.get("dns_policy") or "fail"
    result = validator.validate_public_ip(
        candidate=candidate,
        subnet_mask=subnet_mask,
        gateway=gateway,
        reverse_dns=reverse_dns,
        dns_policy=dns_policy,
    )
    return validator.validation_result_to_dict(result)


class ValidatorWebHandler(BaseHTTPRequestHandler):
    server_version = "PublicIPValidatorWeb/1.0"

    def do_GET(self) -> None:
    # Serve the app shell for the root URL; all other GETs are not found.
        if urlparse(self.path).path in ("/", "/index.html"):
            self._send_text(HTML_PAGE, "text/html; charset=utf-8")
            return
        self._send_json({"error": "not found"}, status=404)

    def do_POST(self) -> None:
      # The frontend posts JSON here and receives the shared validation result.
        if urlparse(self.path).path != "/api/validate":
            self._send_json({"error": "not found"}, status=404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
            if not isinstance(payload, dict):
                raise ValueError("request body must be a JSON object")
            self._send_json(run_validation(payload))
        except (ValueError, RuntimeError) as exc:
            self._send_json({"error": str(exc)}, status=400)
        except Exception as exc:
            self._send_json({"error": str(exc)}, status=500)

    def log_message(self, format: str, *args: Any) -> None:
        print(f"{self.address_string()} - {format % args}")

    def _send_text(self, text: str, content_type: str, status: int = 200) -> None:
      # Send explicit lengths so browsers know when each response is complete.
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, payload: dict[str, Any], status: int = 200) -> None:
      # All API responses, including errors, use the same JSON envelope style.
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Public IP Validator web app.")
    parser.add_argument("--host", default="127.0.0.1", help="host/interface to bind")
    parser.add_argument("--port", default=8000, type=int, help="port to bind")
    args = parser.parse_args()

    # Threading lets multiple browser requests wait on network checks independently.
    server = ThreadingHTTPServer((args.host, args.port), ValidatorWebHandler)
    print(f"Public IP Validator web app running at http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()