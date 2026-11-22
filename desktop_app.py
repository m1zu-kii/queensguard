import argparse
from collections import deque
from copy import deepcopy
from datetime import datetime
import json
import logging
import os
from pathlib import Path
import shutil
import sys
import threading
from typing import Any

import mix
import packetdetect
import windows_firewall


APP_DIRECTORY = Path(__file__).resolve().parent
RESOURCE_DIRECTORY = Path(getattr(sys, "_MEIPASS", APP_DIRECTORY))
HTML_PATH = RESOURCE_DIRECTORY / "Queen_of_Hearts_Dashboard_Image_Frames_2_1.html"
DATA_DIRECTORY = (
    Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    / "QueensGuard"
    if getattr(sys, "frozen", False)
    else APP_DIRECTORY
)
SIMULATION_ATTACK_PING = (180, 520, 1100, 1400)
SIMULATION_ATTACK_PPS = (9000, 40000, 85000, 121400)
SIMULATION_ATTACK_VOTES = (
    (0.41, 0.38, 0.52),
    (0.78, 0.71, 0.83),
    (0.93, 0.96, 0.91),
    (0.99, 0.98, 0.97),
)
SIMULATION_LAG_PING = (210, 340, 290, 190)
SIMULATION_LAG_PPS = (1150, 980, 1100, 1040)
SIMULATION_RECOVERY_PING = (420, 140, 70)


def load_dashboard_html() -> str:
    if not HTML_PATH.is_file():
        raise FileNotFoundError(f"Dashboard HTML was not found: {HTML_PATH}")
    document = HTML_PATH.read_text(encoding="utf-8")
    if "</head>" not in document:
        raise ValueError(f"Dashboard HTML has no closing head tag: {HTML_PATH}")
    return document.replace(
        "</head>",
        '<script>window.__queenDesktopMode = true;</script>\n</head>',
        1,
    )


class DashboardApi:
    def __init__(
        self,
        simulation_only: bool = False,
        firewall_blocking_enabled: bool = False,
    ) -> None:
        self._lock = threading.RLock()
        self._firewall_action_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._worker: threading.Thread | None = None
        self._window: Any = None
        self._window_ready = threading.Event()
        self._status: dict[str, Any] = {
            "ping_ms": None,
            "ping_target": None,
            "ping_baseline_ms": None,
            "ping_samples": 0,
            "ping_required": mix.PING_BASELINE_SAMPLES,
            "ping_updated_at": None,
            "ping_triggered": False,
            "status": "normal",
            "votes": None,
            "latest_classification": None,
            "packets_per_sec": None,
            "packets_in_window": 0,
            "flows_in_window": 0,
            "total_packets": 0,
            "total_flows": 0,
            "capture_interval_seconds": packetdetect.WINDOW_SECONDS,
            "capture_updated_at": None,
            "capture_window_id": 0,
            "capture_state": "offline demo" if simulation_only else "starting",
            "capture_interface": "Simulated traffic"
            if simulation_only
            else "Selecting default route",
            "capture_csv": str(packetdetect.CSV_PATH.resolve()),
            "last_error": None,
            "firewall_blocking_enabled": firewall_blocking_enabled,
            "firewall_error": None,
            "live_verdict_id": 0,
            "live_verdict_event": None,
        }
        self._capture_windows: deque[tuple[int, list[list[str]]]] = deque(maxlen=2)
        self._log_entries: dict[str, dict[str, Any]] = {}
        self._demo_phase = "normal"
        self._demo_step = 0
        self._simulation_only = simulation_only
        self._firewall_blocking_enabled = firewall_blocking_enabled
        self._whitelisted_ips: set[str] = set()

    def _bind_window(self, window: Any) -> None:
        self._window = window

    def _on_window_loaded(self) -> None:
        self._window_ready.set()
        self._window.evaluate_js(
            "window.__queenDemoBusy = false;"
            "const queenGetStatus = window.pywebview.api.get_status.bind(window.pywebview.api);"
            "window.pywebview.api.get_status = async (...args) => {"
            "const status = await queenGetStatus(...args);"
            "if (window.__queenDemoBusy) {"
            "window.__queenDemoRemaining -= 1;"
            "if (window.__queenDemoRemaining <= 0) window.__queenDemoBusy = false;"
            "}"
            "return status;};"
            "window.pywebview.api._start = (kind) => {"
            "if (window.__queenDemoBusy) return;"
            "window.__queenDemoBusy = true;"
            "window.__queenDemoRemaining = kind === 'attack' ? 7 : 4;"
            "window.pywebview.api.start_demo(kind).catch((error) => {"
            "window.__queenDemoBusy = false; console.error(error);});};"
            "window.pywebview.api._busy = () => window.__queenDemoBusy;"
        )

    def _start_worker(self) -> None:
        if self._worker is not None and self._worker.is_alive():
            return
        self._worker = threading.Thread(
            target=self._run_detector,
            name="ddos-detector",
            daemon=True,
        )
        self._worker.start()

    def _stop(self) -> None:
        self._stop_event.set()

    def _join_worker(self) -> None:
        if self._worker is not None and self._worker is not threading.current_thread():
            self._worker.join(timeout=10)
            if self._worker.is_alive():
                logging.error("The detector worker did not stop within 10 seconds.")

    def _run_detector(self) -> None:
        try:
            mix.run_live_judges(
                on_ping_measurement=self._on_ping_measurement,
                on_classifications=self._on_classifications,
                on_capture_window=self._on_capture_window,
                on_capture_state=self._on_capture_state,
                on_flows_captured=self._on_flows_captured,
                on_capture_interface=self._on_capture_interface,
                stop_event=self._stop_event,
            )
        except Exception as exc:
            logging.exception("The live DDoS detector stopped unexpectedly.")
            with self._lock:
                self._status["last_error"] = str(exc)
                self._status["capture_state"] = "error"
                self._status["status"] = "suspected"

    def _on_ping_measurement(
        self,
        latency: float | None,
        baseline_average: float | None,
        triggered: bool,
        sample_count: int,
        host: str,
    ) -> None:
        with self._lock:
            self._status["ping_target"] = host
            self._status["ping_baseline_ms"] = baseline_average
            self._status["ping_samples"] = sample_count
            if triggered:
                self._status["ping_triggered"] = True
            if latency is not None:
                self._status["ping_ms"] = latency
                self._status["ping_updated_at"] = datetime.now().timestamp() * 1000
            if self._demo_phase != "normal":
                return
            if triggered:
                self._status["status"] = "suspected"
            elif (
                self._status["status"] not in ("attack", "recovering")
                and self._status["latest_classification"] is None
            ):
                self._status["status"] = "normal"

    def _on_capture_window(
        self,
        packets_per_second: float,
        packet_count: int,
        flow_count: int,
        _elapsed_seconds: float,
    ) -> None:
        with self._lock:
            self._status["packets_per_sec"] = max(0.0, packets_per_second)
            self._status["packets_in_window"] = packet_count
            self._status["flows_in_window"] = flow_count
            self._status["capture_interval_seconds"] = max(0.0, _elapsed_seconds)
            self._status["total_packets"] += packet_count
            self._status["total_flows"] += flow_count
            self._status["capture_updated_at"] = datetime.now().timestamp() * 1000

    def _on_capture_state(self, capture_state: str) -> None:
        with self._lock:
            self._status["capture_state"] = capture_state

    def _on_capture_interface(self, interface_name: str) -> None:
        with self._lock:
            self._status["capture_interface"] = interface_name

    def _on_flows_captured(self, rows: list[list[str]]) -> None:
        if any(len(row) != len(packetdetect.CSV_HEADERS) for row in rows):
            raise ValueError(
                "Captured flow row does not match the CSV header width."
            )
        with self._lock:
            window_id = self._status["capture_window_id"] + 1
            self._status["capture_window_id"] = window_id
            self._capture_windows.append((window_id, [row.copy() for row in rows]))

    def get_capture_window(
        self,
        window_id: int,
        page: int = 0,
        page_size: int = 25,
    ) -> dict[str, Any]:
        if page < 0:
            raise ValueError("Capture page cannot be negative.")
        if not 1 <= page_size <= 100:
            raise ValueError("Capture page size must be between 1 and 100.")
        with self._lock:
            selected = next(
                (capture for capture in self._capture_windows if capture[0] == window_id),
                None,
            )
            missed = selected is None and window_id < self._status["capture_window_id"]
            if selected is None and self._capture_windows:
                selected = self._capture_windows[-1]
            selected_id, rows = selected or (0, [])
            total_rows = len(rows)
            page_count = (total_rows + page_size - 1) // page_size
            if page >= page_count and page_count:
                raise ValueError("Capture page is outside the available flow rows.")
            start = page * page_size
            return {
                "window_id": selected_id,
                "requested_window_id": window_id,
                "missed": missed,
                "headers": list(packetdetect.CSV_HEADERS),
                "rows": [row.copy() for row in rows[start : start + page_size]],
                "total_rows": total_rows,
                "page": page,
                "page_size": page_size,
            }

    def _on_classifications(
        self,
        results: list[dict[str, str | float]],
    ) -> None:
        if not results:
            return

        ddos_results = [
            result for result in results
            if result["Unanimous Result"] == "DDoS"
        ]
        latest = (
            max(
                ddos_results,
                key=lambda result: sum(
                    float(result[f"{name.upper()} Confidence"])
                    for name in ("svm", "xgb", "knn")
                ),
            )
            if ddos_results
            else results[-1]
        )
        verdict = "DDoS" if ddos_results else str(latest["Unanimous Result"])
        models = {
            name: {
                "prediction": str(latest[f"{name.upper()} Class"]),
                "confidence": float(latest[f"{name.upper()} Confidence"]),
                "ddos_probability": (
                    float(latest[f"{name.upper()} Confidence"])
                    if latest[f"{name.upper()} Class"] == "DDoS"
                    else 1.0 - float(latest[f"{name.upper()} Confidence"])
                ),
            }
            for name in ("svm", "xgb", "knn")
        }
        with self._lock:
            if self._demo_phase != "normal":
                return
            ping_was_triggered = self._status["ping_triggered"]
            self._status["votes"] = {
                name: value["ddos_probability"]
                for name, value in models.items()
            }
            self._status["latest_classification"] = {
                "verdict": verdict,
                "models": models,
                "rows_scored": len(results),
                "flow_timestamp": str(latest["Flow Timestamp"]),
                "reviewed_at": datetime.now().timestamp() * 1000,
            }
            self._status["ping_triggered"] = False
            if verdict == "DDoS":
                self._status["status"] = "attack"
            elif verdict == "Benign":
                self._status["status"] = (
                    "lag" if ping_was_triggered else "normal"
                )
            else:
                self._status["status"] = "suspected"
            if not ddos_results:
                return
            self._status["live_verdict_id"] += 1
            event_id = self._status["live_verdict_id"]
            if self._firewall_blocking_enabled:
                self._status["firewall_error"] = None

        ip_confidences: dict[str, list[float]] = {}
        for result in ddos_results:
            ip = str(result.get("Src IP", "")).strip()
            if not ip:
                continue
            if self._firewall_blocking_enabled:
                try:
                    ip = windows_firewall.normalize_ip(ip)
                except windows_firewall.FirewallError:
                    pass
            confidence = sum(
                float(result[f"{name.upper()} Confidence"])
                for name in ("svm", "xgb", "knn")
            ) / 3
            ip_confidences.setdefault(ip, []).append(confidence)

        now = datetime.now().timestamp() * 1000
        confidence_values = [
            float(result[f"{name.upper()} Confidence"])
            for result in ddos_results
            for name in ("svm", "xgb", "knn")
        ]
        blocked_ips = 0

        for ip, confidences in ip_confidences.items():
            state = "detected"
            reason = (
                "High-confidence DDoS classification; "
                "traffic blocking is disabled"
            )
            with self._firewall_action_lock:
                with self._lock:
                    existing = self._log_entries.get(ip)
                    if ip in self._whitelisted_ips:
                        continue
                    if existing and existing["state"] == "banned":
                        blocked_ips += 1
                        continue

                if self._firewall_blocking_enabled:
                    try:
                        windows_firewall.block_inbound_ip(ip)
                    except windows_firewall.FirewallError as exc:
                        reason = f"Firewall block failed: {exc}"
                        with self._lock:
                            self._status["firewall_error"] = str(exc)
                        logging.error(
                            "Could not block detected source IP %s: %s",
                            ip,
                            exc,
                        )
                    else:
                        state = "banned"
                        reason = (
                            "High-confidence DDoS classification; "
                            "Windows Firewall inbound rule applied"
                        )
                        blocked_ips += 1

                confidence = sum(confidences) / len(confidences)
                with self._lock:
                    self._log_entries[ip] = {
                        "ip": ip,
                        "blocked_at": now,
                        "reason": reason,
                        "confidence": confidence,
                        "state": state,
                        "pardon_until": 0,
                    }

        with self._lock:
            event = {
                "event_id": event_id,
                "time": now,
                "rows_scored": len(ddos_results),
                "peak_pps": self._status["packets_per_sec"] or 0,
                "ips_blocked": blocked_ips,
                "ips_detected": len(ip_confidences),
                "avg_confidence": (
                    sum(confidence_values) / len(confidence_values)
                    if confidence_values
                    else 0.0
                ),
            }
            self._status["live_verdict_event"] = event
            event = deepcopy(event)
        self._notify_live_verdict(event)

    def _notify_live_verdict(self, event: dict[str, Any]) -> None:
        if not self._window_ready.is_set() or self._window is None:
            return
        try:
            self._window.evaluate_js(
                f"window.onAttackKilled({json.dumps(event)});"
            )
        except Exception:
            logging.exception("Could not deliver the live verdict to the dashboard.")

    def get_log(self) -> list[dict[str, Any]]:
        with self._lock:
            return [
                deepcopy(entry)
                for entry in reversed(list(self._log_entries.values()))
            ]

    def _blocking_disabled(self) -> dict[str, Any]:
        return {
            "ok": False,
            "error": (
                "IP blocking is disabled. Start Queen's Guard with "
                "--enable-firewall-blocking on an authorized Windows test system."
            ),
        }

    def ban_ip(self, ip: str) -> dict[str, Any]:
        if not self._firewall_blocking_enabled:
            return self._blocking_disabled()
        with self._firewall_action_lock:
            try:
                ip = windows_firewall.normalize_ip(ip)
                rule = windows_firewall.block_inbound_ip(ip)
            except windows_firewall.FirewallError as exc:
                logging.error("Could not block source IP %s: %s", ip, exc)
                return {"ok": False, "error": str(exc)}
            with self._lock:
                self._whitelisted_ips.discard(ip)
                self._log_entries[ip] = {
                    "ip": ip,
                    "blocked_at": datetime.now().timestamp() * 1000,
                    "reason": "Manually blocked with Windows Firewall",
                    "confidence": 0.0,
                    "state": "banned",
                    "pardon_until": 0,
                }
        return {"ok": True, "rule": rule}

    def unban_ip(self, ip: str) -> dict[str, Any]:
        if not self._firewall_blocking_enabled:
            return self._blocking_disabled()
        with self._firewall_action_lock:
            try:
                ip = windows_firewall.normalize_ip(ip)
                rule = windows_firewall.unblock_inbound_ip(ip)
            except windows_firewall.FirewallError as exc:
                logging.error(
                    "Could not remove firewall rule for source IP %s: %s",
                    ip,
                    exc,
                )
                return {"ok": False, "error": str(exc)}
            with self._lock:
                self._whitelisted_ips.add(ip)
                entry = self._log_entries.get(ip)
                if entry is not None:
                    entry["state"] = "pardoned"
                    entry["reason"] = "Firewall rule removed; source IP allowlisted"
        return {"ok": True, "rule": rule}

    def whitelist_ip(self, ip: str) -> dict[str, Any]:
        if not self._firewall_blocking_enabled:
            return self._blocking_disabled()
        with self._firewall_action_lock:
            try:
                ip = windows_firewall.normalize_ip(ip)
                rule = windows_firewall.rule_name(ip)
                with self._lock:
                    is_banned = (
                        ip in self._log_entries
                        and self._log_entries[ip]["state"] == "banned"
                    )
                if is_banned:
                    windows_firewall.unblock_inbound_ip(ip)
            except windows_firewall.FirewallError as exc:
                logging.error("Could not allowlist source IP %s: %s", ip, exc)
                return {"ok": False, "error": str(exc)}
            with self._lock:
                self._whitelisted_ips.add(ip)
                entry = self._log_entries.get(ip)
                if entry is not None:
                    entry["state"] = "pardoned"
                    entry["reason"] = "Source IP allowlisted"
        return {"ok": True, "rule": rule}

    def intro_seen(self) -> bool:
        marker = DATA_DIRECTORY / "intro_seen.json"
        if not marker.is_file():
            return False
        with marker.open("r", encoding="utf-8") as marker_file:
            return json.load(marker_file) is True

    def mark_intro_seen(self) -> dict[str, bool]:
        DATA_DIRECTORY.mkdir(parents=True, exist_ok=True)
        marker = DATA_DIRECTORY / "intro_seen.json"
        temporary_marker = marker.with_suffix(".tmp")
        with temporary_marker.open("w", encoding="utf-8") as marker_file:
            json.dump(True, marker_file)
        temporary_marker.replace(marker)
        return {"ok": True}

    def get_status(self) -> dict[str, Any]:
        simulation_event = None
        with self._lock:
            demo_active = self._demo_phase != "normal"
            if self._demo_phase == "attack":
                step = self._demo_step
                svm, xgb, knn = SIMULATION_ATTACK_VOTES[step]
                status = "attack" if step == len(SIMULATION_ATTACK_PING) - 1 else "suspected"
                result = {
                    "ping_ms": SIMULATION_ATTACK_PING[step],
                    "packets_per_sec": SIMULATION_ATTACK_PPS[step],
                    "status": status,
                    "votes": {"svm": svm, "xgb": xgb, "knn": knn},
                }
                self._demo_step += 1
                if status == "attack":
                    simulation_event = self._build_simulated_event()
                    self._demo_phase = "recovering"
                    self._demo_step = 0
            elif self._demo_phase == "lag":
                step = self._demo_step
                result = {
                    "ping_ms": SIMULATION_LAG_PING[step],
                    "packets_per_sec": SIMULATION_LAG_PPS[step],
                    "status": "lag",
                    "votes": {"svm": 0.08, "xgb": 0.06, "knn": 0.10},
                }
                self._demo_step += 1
                if self._demo_step >= len(SIMULATION_LAG_PING):
                    self._demo_phase = "normal"
                    self._demo_step = 0
            elif self._demo_phase == "recovering":
                step = self._demo_step
                result = {
                    "ping_ms": SIMULATION_RECOVERY_PING[step],
                    "packets_per_sec": 1100,
                    "status": "recovering",
                    "votes": {"svm": 0.04, "xgb": 0.03, "knn": 0.05},
                }
                self._demo_step += 1
                if self._demo_step >= len(SIMULATION_RECOVERY_PING):
                    self._demo_phase = "normal"
                    self._demo_step = 0
            else:
                result = {}

            demo_values = result
            result = deepcopy(self._status)
            result.update(demo_values)
            if demo_active:
                result["capture_state"] = "simulation"
                result["capture_interface"] = "Simulated traffic"
                result["capture_updated_at"] = datetime.now().timestamp() * 1000
                result["capture_csv"] = None
                result["total_packets"] = None
                result["total_flows"] = None
                result["packets_in_window"] = round(
                    result["packets_per_sec"] * packetdetect.WINDOW_SECONDS
                )
                result["flows_in_window"] = None
                result["capture_interval_seconds"] = packetdetect.WINDOW_SECONDS
                result["ping_target"] = "Simulated"
                result["ping_samples"] = mix.PING_BASELINE_SAMPLES
                result["ping_required"] = mix.PING_BASELINE_SAMPLES
                result["ping_baseline_ms"] = 40.0
                result["ping_updated_at"] = datetime.now().timestamp() * 1000
                result["ping_triggered"] = False
                model_votes = result["votes"]
                result["latest_classification"] = {
                    "verdict": (
                        "DDoS"
                        if result["status"] == "attack"
                        else "Inconclusive"
                    ),
                    "rows_scored": 1,
                    "flow_timestamp": datetime.now().isoformat(timespec="seconds"),
                    "reviewed_at": datetime.now().timestamp() * 1000,
                    "models": {
                        name: {
                            "prediction": (
                                "DDoS" if probability >= 0.5 else "Benign"
                            ),
                            "confidence": max(probability, 1.0 - probability),
                            "ddos_probability": probability,
                        }
                        for name, probability in model_votes.items()
                    },
                }
            result["simulation_only"] = self._simulation_only
            result["simulation_active"] = demo_active
            result["capture_window_id"] = self._status["capture_window_id"]
            result["votes"] = (
                dict(result["votes"])
                if result["votes"] is not None
                else None
            )

        if simulation_event is not None:
            self._notify_simulated_verdict(simulation_event)
        return result

    def start_demo(self, phase: str) -> None:
        if phase not in ("attack", "lag"):
            raise ValueError("Simulation phase must be 'attack' or 'lag'.")
        with self._lock:
            if self._demo_phase == "normal":
                self._demo_phase = phase
                self._demo_step = 0

    def is_busy(self) -> bool:
        with self._lock:
            return self._demo_phase != "normal"

    def _build_simulated_event(self) -> dict[str, Any]:
        now = datetime.now().timestamp() * 1000
        return {
            "time": now,
            "rows_scored": 1,
            "peak_pps": SIMULATION_ATTACK_PPS[-1],
            "ips_blocked": 0,
            "ips_detected": 0,
            "avg_confidence": 0.98,
        }

    def _notify_simulated_verdict(self, event: dict[str, Any]) -> None:
        if not self._window_ready.is_set() or self._window is None:
            return
        self._window.evaluate_js(
            f"window.onAttackKilled({json.dumps(event)});"
        )


def _prepare_runtime_paths() -> None:
    if not getattr(sys, "frozen", False):
        return

    DATA_DIRECTORY.mkdir(parents=True, exist_ok=True)
    packetdetect.CSV_PATH = DATA_DIRECTORY / "realtime_flow_features.csv"
    mix.JUDGMENT_PATH = DATA_DIRECTORY / "attack_judgments.csv"
    mix.MODEL_PATH = DATA_DIRECTORY / "ddos_vote_models.joblib"
    if not mix.MODEL_PATH.is_file():
        bundled_model = RESOURCE_DIRECTORY / "ddos_vote_models.joblib"
        if not bundled_model.is_file():
            raise FileNotFoundError(
                f"The bundled model artifact was not found: {bundled_model}"
            )
        shutil.copy2(bundled_model, mix.MODEL_PATH)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Launch the Queen's Guard desktop dashboard."
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--train",
        action="store_true",
        help="Train the models and exit.",
    )
    mode.add_argument(
        "--train-and-run",
        action="store_true",
        help="Retrain the models and launch the dashboard.",
    )
    mode.add_argument(
        "--demo",
        action="store_true",
        help=(
            "Launch the dashboard with simulated data only; "
            "do not ping or capture network traffic."
        ),
    )
    parser.add_argument(
        "--enable-firewall-blocking",
        action="store_true",
        help=(
            "Automatically block unanimously detected source IPs using "
            "Windows Firewall. Requires administrator privileges."
        ),
    )
    args = parser.parse_args()

    if args.enable_firewall_blocking and (args.demo or args.train):
        parser.error(
            "--enable-firewall-blocking requires live mode; it cannot be used "
            "with --demo or --train."
        )
    if args.enable_firewall_blocking:
        windows_firewall.require_windows_admin()

    _prepare_runtime_paths()

    if args.train:
        mix.train_and_save_models()
        return
    if args.demo:
        print("Starting offline dashboard demo; no network capture or ping is enabled.")
    elif args.train_and_run:
        mix.train_and_save_models()
    else:
        mix.ensure_current_model_artifact()

    dashboard_html = load_dashboard_html()

    import webview

    api = DashboardApi(
        simulation_only=args.demo,
        firewall_blocking_enabled=args.enable_firewall_blocking,
    )
    window = webview.create_window(
        "Queen's Guard",
        html=dashboard_html,
        js_api=api,
        min_size=(760, 600),
    )
    api._bind_window(window)
    window.events.loaded += api._on_window_loaded
    window.events.closed += api._stop
    if not args.demo:
        api._start_worker()
    webview.start()
    if not args.demo:
        api._stop()
        api._join_worker()


if __name__ == "__main__":
    main()
