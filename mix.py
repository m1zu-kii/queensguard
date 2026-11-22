import argparse
import csv
from collections import deque
from datetime import datetime
import io
from pathlib import Path
import platform
import queue
import re
import subprocess
import threading
import time
from statistics import fmean
from typing import Any, Callable, Sequence

import joblib
import numpy as np
import pandas as pd
from scapy.all import conf
from sklearn import config_context

import modeltrain
import packetdetect


MODEL_PATH = Path(__file__).with_name("ddos_vote_models.joblib")
JUDGMENT_PATH = Path(__file__).with_name("attack_judgments.csv")
# Increment when a release changes the training data, feature contract, or models.
MODEL_VERSION = 1
PING_INTERVAL_SECONDS = 1.0
PING_BASELINE_SAMPLES = 60
PING_SPIKE_MULTIPLIER = 10.0
MIN_CONFIDENCE = 0.95
PREDICTION_BATCH_ROWS = 256
MODEL_NAMES = ("knn", "svm", "xgb")
LABEL_NAMES = {0: "Benign", 1: "DDoS"}
JUDGMENT_HEADERS = (
    "Detection Timestamp",
    "Flow Timestamp",
    "Src IP",
    "Dst IP",
    "KNN Class",
    "KNN Confidence",
    "SVM Class",
    "SVM Confidence",
    "XGB Class",
    "XGB Confidence",
    "Unanimous Result",
)


def train_and_save_models() -> None:
    """Train calibrated voting models once from a bounded labeled sample."""
    row_limit = modeltrain.VOTING_TRAIN_ROWS + modeltrain.CALIBRATION_ROWS
    data = modeltrain.load_ddos_dataset(row_limit=row_limit)
    if len(data) < row_limit:
        print(f"Loaded {len(data):,} usable labeled rows for training.")
    else:
        print(f"Loaded {len(data):,} labeled rows for training.")

    models = modeltrain.train_voting_models(data)
    artifact = {
        "model_version": MODEL_VERSION,
        "feature_columns": tuple(data.drop(columns="Label").columns),
        "models": models,
        "confidence_threshold": MIN_CONFIDENCE,
        "trained_at": datetime.now().isoformat(timespec="seconds"),
    }

    temporary_path = MODEL_PATH.with_suffix(".tmp")
    joblib.dump(artifact, temporary_path, compress=3)
    temporary_path.replace(MODEL_PATH)
    print(f"Saved calibrated voting models to {MODEL_PATH}")


def ensure_current_model_artifact() -> None:
    """Train once when the artifact is missing or incompatible with this release."""
    if not MODEL_PATH.is_file():
        print("No trained model artifact found; training models for first launch.")
        train_and_save_models()
        return

    artifact = joblib.load(MODEL_PATH)
    if not isinstance(artifact, dict):
        raise ValueError(f"Invalid model artifact format: {MODEL_PATH}")

    is_current = (
        artifact.get("model_version") == MODEL_VERSION
        and tuple(artifact.get("feature_columns", ()))
        == tuple(packetdetect.MODEL_FEATURE_COLUMNS)
        and set(artifact.get("models", {})) == set(MODEL_NAMES)
    )
    if not is_current:
        print("Saved models are outdated; retraining for this application update.")
        train_and_save_models()


def load_models() -> dict[str, Any]:
    if not MODEL_PATH.is_file():
        raise FileNotFoundError(
            f"Model artifacts are missing: {MODEL_PATH}. "
            "Train them once with `python mix.py --train`."
        )

    artifact = joblib.load(MODEL_PATH)
    if artifact.get("model_version") != MODEL_VERSION:
        raise ValueError(
            "Saved models are outdated. Start the application to retrain them."
        )
    expected_columns = tuple(packetdetect.MODEL_FEATURE_COLUMNS)
    if tuple(artifact.get("feature_columns", ())) != expected_columns:
        raise ValueError(
            "Saved model feature columns do not match packetdetect's CSV schema. "
            "Retrain the voting models with `python mix.py --train`."
        )

    models = artifact.get("models", {})
    if set(models) != set(MODEL_NAMES):
        raise ValueError(
            "Saved model artifact must contain exactly the KNN, SVM, and XGBoost "
            "classifiers."
        )
    return models


def get_default_gateway() -> str:
    route = conf.route.route("0.0.0.0")
    gateway = route[2]
    if not gateway or gateway == "0.0.0.0":
        raise RuntimeError(
            "Could not determine the default gateway to monitor with ping."
        )
    return str(gateway)


def ping_latency_ms(host: str) -> float | None:
    if platform.system() == "Windows":
        command = ["ping", "-n", "1", "-w", "1000", host]
    else:
        command = ["ping", "-c", "1", "-W", "1", host]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
        timeout=2,
    )
    output = f"{result.stdout}\n{result.stderr}"
    match = re.search(r"time[=<]\s*([\d.,]+)\s*ms", output, re.IGNORECASE)
    if result.returncode != 0 or match is None:
        return None
    return float(match.group(1).replace(",", "."))


def monitor_ping(
    host: str,
    stop_event: threading.Event,
    trigger_queue: queue.Queue[tuple[float, float, str]],
    on_measurement: (
        Callable[[float | None, float | None, bool, int, str], None] | None
    ) = None,
) -> None:
    """Trigger on a 10x ping rise over the trailing 60 non-triggered samples."""
    baseline: deque[float] = deque(maxlen=PING_BASELINE_SAMPLES)
    warmup_reported = False

    while not stop_event.is_set():
        started = time.monotonic()
        latency = ping_latency_ms(host)
        triggered = False
        if latency is None:
            print(f"Ping to {host} failed; skipping this measurement.")
        elif len(baseline) < PING_BASELINE_SAMPLES:
            baseline.append(latency)
            if (
                len(baseline) == PING_BASELINE_SAMPLES
                and not warmup_reported
            ):
                print(
                    f"Ping baseline ready: {fmean(baseline):.2f} ms "
                    f"(last {PING_BASELINE_SAMPLES} successful pings)."
                )
                warmup_reported = True
        else:
            average_latency = fmean(baseline)
            if latency > PING_SPIKE_MULTIPLIER * average_latency:
                triggered = True
                triggered_at = datetime.now().isoformat(timespec="seconds")
                trigger_queue.put((latency, average_latency, triggered_at))
                print(
                    f"Ping spike: {latency:.2f} ms vs "
                    f"{average_latency:.2f} ms average; queued for classification."
                )
            else:
                baseline.append(latency)

        if on_measurement is not None:
            on_measurement(
                latency,
                fmean(baseline) if baseline else None,
                triggered,
                len(baseline),
                host,
            )

        remaining = PING_INTERVAL_SECONDS - (time.monotonic() - started)
        stop_event.wait(max(0.0, remaining))


def classify_window(
    rows: Sequence[Sequence[str | int | float]],
    models: dict[str, Any],
) -> list[dict[str, str | float]]:
    """Score one flushed CSV window and require a confident unanimous vote."""
    frame = pd.DataFrame(rows, columns=packetdetect.CSV_HEADERS)
    features = frame.loc[:, packetdetect.MODEL_FEATURE_COLUMNS].apply(
        pd.to_numeric, errors="coerce"
    )
    finite_mask = np.isfinite(features.to_numpy(dtype=np.float64)).all(axis=1)
    valid_positions = np.flatnonzero(finite_mask)
    if valid_positions.size == 0:
        return []

    valid_features = features.iloc[valid_positions].to_numpy(
        dtype=np.float32,
        copy=False,
    )
    model_votes: dict[str, tuple[np.ndarray, np.ndarray]] = {
        name: (
            np.empty(len(valid_features), dtype=np.int8),
            np.empty(len(valid_features), dtype=np.float32),
        )
        for name in MODEL_NAMES
    }
    with config_context(working_memory=128):
        for name in MODEL_NAMES:
            model = models[name]
            classes = np.asarray(model.classes_)
            labels, confidences = model_votes[name]
            for start in range(0, len(valid_features), PREDICTION_BATCH_ROWS):
                end = min(start + PREDICTION_BATCH_ROWS, len(valid_features))
                probabilities = model.predict_proba(valid_features[start:end])
                best_indices = probabilities.argmax(axis=1)
                labels[start:end] = classes[best_indices].astype(np.int8)
                confidences[start:end] = probabilities[
                    np.arange(end - start), best_indices
                ]

    results: list[dict[str, str | float]] = []
    for row_index, position in enumerate(valid_positions):
        labels = {
            name: int(model_votes[name][0][row_index])
            for name in MODEL_NAMES
        }
        confidences = {
            name: float(model_votes[name][1][row_index])
            for name in MODEL_NAMES
        }
        unanimous = (
            len(set(labels.values())) == 1
            and all(value >= MIN_CONFIDENCE for value in confidences.values())
        )
        result = (
            LABEL_NAMES[next(iter(labels.values()))]
            if unanimous
            else "Inconclusive"
        )
        csv_row = frame.iloc[position]
        results.append(
            {
                "Detection Timestamp": datetime.now().isoformat(timespec="seconds"),
                "Flow Timestamp": str(csv_row["Timestamp"]),
                "Src IP": str(csv_row["Src IP"]),
                "Dst IP": str(csv_row["Dst IP"]),
                "KNN Class": LABEL_NAMES[labels["knn"]],
                "KNN Confidence": confidences["knn"],
                "SVM Class": LABEL_NAMES[labels["svm"]],
                "SVM Confidence": confidences["svm"],
                "XGB Class": LABEL_NAMES[labels["xgb"]],
                "XGB Confidence": confidences["xgb"],
                "Unanimous Result": result,
            }
        )
    return results


def read_flushed_csv_window(
    path: Path,
    start_position: int,
    end_position: int,
) -> list[list[str]]:
    if end_position <= start_position:
        return []

    with path.open("r", newline="", encoding="utf-8") as input_file:
        input_file.seek(start_position)
        csv_text = input_file.read(end_position - start_position)
    return list(csv.reader(io.StringIO(csv_text, newline="")))


def write_judgments(results: list[dict[str, str | float]]) -> None:
    if not results:
        print("No valid flow rows were available for the triggered window.")
        return

    needs_header = not JUDGMENT_PATH.exists() or JUDGMENT_PATH.stat().st_size == 0
    with JUDGMENT_PATH.open("a", newline="", encoding="utf-8") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=JUDGMENT_HEADERS)
        if needs_header:
            writer.writeheader()
        writer.writerows(results)

    counts = pd.Series(
        [str(result["Unanimous Result"]) for result in results]
    ).value_counts().to_dict()
    print(
        f"Classified {len(results)} flow(s) after ping trigger: {counts}. "
        f"Details saved to {JUDGMENT_PATH}"
    )


def run_live_judges(
    on_ping_measurement: (
        Callable[[float | None, float | None, bool, int, str], None] | None
    ) = None,
    on_classifications: Callable[[list[dict[str, str | float]]], None] | None = None,
    on_capture_window: (
        Callable[[float, int, int, float], None] | None
    ) = None,
    on_capture_state: Callable[[str], None] | None = None,
    on_flows_captured: Callable[[list[list[str]]], None] | None = None,
    on_capture_interface: Callable[[str], None] | None = None,
    stop_event: threading.Event | None = None,
) -> None:
    models = load_models()
    gateway = get_default_gateway()
    print(f"Monitoring ping latency to default gateway {gateway}.")
    print(
        f"Collecting a {packetdetect.WINDOW_SECONDS}-second ping baseline; "
        "classification starts after 60 successful pings."
    )
    print("No traffic-blocking action is configured.")

    if stop_event is None:
        stop_event = threading.Event()
    if on_capture_state is not None:
        on_capture_state("starting")
    trigger_queue: queue.Queue[tuple[float, float, str]] = queue.Queue()
    ping_errors: queue.Queue[Exception] = queue.Queue()

    def ping_worker() -> None:
        try:
            monitor_ping(
                gateway,
                stop_event,
                trigger_queue,
                on_measurement=on_ping_measurement,
            )
        except Exception as exc:
            ping_errors.put(exc)
            stop_event.set()

    ping_thread = threading.Thread(
        target=ping_worker,
        name="ping-monitor",
        daemon=True,
    )
    ping_thread.start()

    def analyze_triggered_window(
        csv_path: Path,
        start_position: int,
        end_position: int,
    ) -> None:
        try:
            ping_error = ping_errors.get_nowait()
        except queue.Empty:
            ping_error = None
        if ping_error is not None:
            raise RuntimeError("Ping monitoring stopped unexpectedly.") from ping_error

        if end_position <= start_position or trigger_queue.empty():
            return

        rows = read_flushed_csv_window(csv_path, start_position, end_position)
        if not rows:
            return

        triggers: list[tuple[float, float, str]] = []
        while True:
            try:
                triggers.append(trigger_queue.get_nowait())
            except queue.Empty:
                break

        print(f"Scoring the latest {len(rows)} flow row(s) from the CSV window.")
        results = classify_window(rows, models)
        write_judgments(results)
        if on_classifications is not None:
            on_classifications(results)
        if len(triggers) > 1:
            print(f"Coalesced {len(triggers)} ping spikes into this window vote.")

    try:
        packetdetect.run_realtime_extractor(
            on_window_flushed=analyze_triggered_window,
            stop_event=stop_event,
            on_capture_window=on_capture_window,
            on_capture_state=on_capture_state,
            on_flows_captured=on_flows_captured,
            on_capture_interface=on_capture_interface,
        )
    finally:
        stop_event.set()
        ping_thread.join(timeout=3)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Run ping-triggered live classification, training models "
            "automatically on first launch or when their version changes."
        )
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--train",
        action="store_true",
        help="Train calibrated classifiers and save the model artifact, then exit.",
    )
    mode.add_argument(
        "--train-and-run",
        action="store_true",
        help="Train calibrated classifiers, save the artifact, then start live mode.",
    )
    args = parser.parse_args()

    if args.train:
        train_and_save_models()
        return

    if args.train_and_run:
        train_and_save_models()
    else:
        ensure_current_model_artifact()

    run_live_judges()


if __name__ == "__main__":
    main()
