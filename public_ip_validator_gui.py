#!/usr/bin/env python3
"""Desktop GUI for public_ip_validator.py."""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from tkinter import messagebox, ttk

import public_ip_validator as validator


GUI_SYMBOLS = {
    # GUI-specific symbols keep the CLI output plain while making checks scannable.
    validator.PASS: "✅",
    validator.FAIL: "⛔",
}


class ValidatorApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Public IP Validator")
        self.root.geometry("860x680")
        self.root.minsize(720, 520)
        # Tkinter variables keep widgets and app state synchronized automatically.
        self.ip_var = tk.StringVar()
        self.subnet_var = tk.StringVar()
        self.gateway_var = tk.StringVar()
        self.reverse_dns_var = tk.BooleanVar()
        self.dns_policy_var = tk.StringVar(value="fail")
        self.status_var = tk.StringVar(value="Ready")
        self.verdict_var = tk.StringVar(
            value="Enter an IP, or leave it blank to detect this device's public IP.")
        # Worker threads cannot update Tk widgets directly, so results cross this queue.
        self.result_queue = queue.Queue()
        self.checks = []
        self._build_ui()

    def _build_ui(self) -> None:
        # The main window is split into inputs, a verdict banner, and detailed checks.
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)
        header = ttk.Frame(self.root, padding=(20, 18, 20, 8))
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text="Public IP Validator", font=("Segoe UI", 18, "bold")).grid(
            row=0, column=0, sticky="w")
        ttk.Label(header, text="Check whether an address looks like a genuine ISP-assigned public IP.").grid(
            row=1, column=0, sticky="w", pady=(3, 0))
        self.progress = ttk.Progressbar(header, mode="indeterminate", length=150)
        self.progress.grid(row=0, column=1, rowspan=2, padx=(12, 0))

        content = ttk.Frame(self.root, padding=(20, 8, 20, 20))
        content.grid(row=1, column=0, sticky="nsew")
        content.columnconfigure(0, weight=1)
        content.rowconfigure(2, weight=1)

        options = ttk.LabelFrame(content, text="Validation options", padding=12)
        options.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        options.columnconfigure(1, weight=1)
        options.columnconfigure(3, weight=1)
        ttk.Label(options, text="IP address").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=4)
        ip_entry = ttk.Entry(options, textvariable=self.ip_var)
        ip_entry.grid(row=0, column=1, columnspan=3, sticky="ew", pady=4)
        ip_entry.focus_set()

        # Subnet and gateway are optional, but they must be provided as a pair.
        ttk.Label(options, text="Subnet mask / prefix").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Entry(options, textvariable=self.subnet_var).grid(row=1, column=1, sticky="ew", pady=4)
        ttk.Label(options, text="Default gateway").grid(row=1, column=2, sticky="w", padx=(16, 8), pady=4)
        ttk.Entry(options, textvariable=self.gateway_var).grid(row=1, column=3, sticky="ew", pady=4)
        ttk.Checkbutton(options, text="Check reverse DNS (PTR)", variable=self.reverse_dns_var).grid(
            row=2, column=0, columnspan=2, sticky="w", pady=(8, 2))
        ttk.Label(options, text="Known DNS policy").grid(row=2, column=2, sticky="e", padx=(16, 8), pady=(8, 2))
        ttk.Combobox(options, textvariable=self.dns_policy_var, values=("fail", "warn", "ignore"),
                     state="readonly", width=10).grid(row=2, column=3, sticky="w", pady=(8, 2))
        self.run_button = ttk.Button(options, text="Run validation", command=self.start_validation)
        self.run_button.grid(row=3, column=0, columnspan=4, sticky="ew", pady=(12, 0))
        self.root.bind("<Return>", lambda _event: self.start_validation())

        verdict = ttk.LabelFrame(content, text="Verdict", padding=(12, 8))
        verdict.grid(row=1, column=0, sticky="ew", pady=(0, 12))
        self.verdict_label = ttk.Label(verdict, textvariable=self.verdict_var,
                                       font=("Segoe UI", 11, "bold"), wraplength=780)
        self.verdict_label.grid(row=0, column=0, sticky="w")

        results = ttk.LabelFrame(content, text="Checks", padding=8)
        results.grid(row=2, column=0, sticky="nsew")
        results.columnconfigure(0, weight=1)
        results.rowconfigure(0, weight=1)
        self.checks_text = tk.Text(results, height=10, wrap="word", state="disabled",
                       padx=8, pady=6)
        self.checks_text.grid(row=0, column=0, sticky="nsew")
        self.checks_text.tag_configure("check_heading", font=("Segoe UI", 9, "bold"))
        self.checks_text.tag_configure(validator.FAIL, foreground="#b00020")
        scrollbar = ttk.Scrollbar(results, orient="vertical", command=self.checks_text.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.checks_text.configure(yscrollcommand=scrollbar.set)
        self.details = tk.Text(results, height=5, wrap="word", state="disabled", background="#f7f7f7")
        self.details.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        ttk.Label(self.root, textvariable=self.status_var, relief="sunken", anchor="w", padding=(8, 3)).grid(
            row=2, column=0, sticky="ew")

    def start_validation(self) -> None:
        # Validate paired options before starting network work in the background.
        has_subnet = bool(self.subnet_var.get().strip())
        has_gateway = bool(self.gateway_var.get().strip())
        if has_subnet != has_gateway:
            messagebox.showerror("Missing option", "Subnet mask and default gateway must be provided together.")
            return
        self.run_button.configure(state="disabled")
        self.progress.start(12)
        self.status_var.set("Running network checks...")
        self.verdict_var.set("Working...")
        self.checks_text.configure(state="normal")
        self.checks_text.delete("1.0", "end")
        self.checks_text.configure(state="disabled")
        self._set_details("")
        options = {
            "candidate": self.ip_var.get().strip() or None,
            "subnet_mask": self.subnet_var.get().strip() or None,
            "gateway": self.gateway_var.get().strip() or None,
            "reverse_dns": self.reverse_dns_var.get(),
            "dns_policy": self.dns_policy_var.get(),
        }
        # Network checks can take several seconds; keep the Tk event loop responsive.
        threading.Thread(target=self._validate_worker, args=(options,), daemon=True).start()
        self.root.after(100, self._poll_result)

    def _validate_worker(self, options: dict) -> None:
        # This runs outside the UI thread and sends either a result or error back.
        try:
            result = validator.validate_public_ip(**options)
        except Exception as exc:
            self.result_queue.put(("error", str(exc)))
        else:
            self.result_queue.put(("result", result))

    def _poll_result(self) -> None:
        # Poll instead of blocking so Tk can continue repainting and handling input.
        try:
            kind, value = self.result_queue.get_nowait()
        except queue.Empty:
            self.root.after(100, self._poll_result)
            return
        self.progress.stop()
        self.run_button.configure(state="normal")
        if kind == "error":
            self.status_var.set("Validation could not be completed")
            self.verdict_var.set("Error: " + value)
            messagebox.showerror("Validation error", value)
            return
        result = value
        ip_str = result.ip
        checks = result.checks
        status = result.status
        text = result.message
        self.checks = checks
        self.status_var.set(f"Finished checking {ip_str}")
        self.verdict_var.set(f"{validator.SYMBOLS[status]} {text}")
        self.checks_text.configure(state="normal")
        for index, check in enumerate(checks):
            tag = f"check_{index}"
            self.checks_text.tag_bind(
                tag, "<Button-1>", lambda _event, selected=index: self.show_details(selected))
            self.checks_text.insert(
                "end",
                f"{GUI_SYMBOLS.get(check.status, validator.SYMBOLS[check.status])} "
                f"{check.status}  {check.name}\n",
                ("check_heading", tag, check.status),
            )
            self.checks_text.insert("end", f"    {check.summary}\n\n", (tag, check.status))
        self.checks_text.configure(state="disabled")
        if checks:
            self.show_details(0)

    def show_details(self, check_index: int) -> None:
        check = self.checks[check_index]
        details = "\n".join(check.details)
        self._set_details("\n".join(part for part in (check.summary, details) if part))

    def _set_details(self, text: str) -> None:
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", text)
        self.details.configure(state="disabled")


def main() -> None:
    root = tk.Tk()
    ValidatorApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()