import csv
from datetime import datetime, timedelta
import os
from pathlib import Path
import tempfile
import threading
import time
from typing import Callable, TextIO

from cicflowmeter.features.context import (
    PacketDirection,
    get_packet_flow_key,
)
from cicflowmeter.flow import Flow
from scapy.all import AsyncSniffer, IP, TCP, UDP, conf
from scapy.packet import Packet


CSV_PATH = Path(__file__).with_name("realtime_flow_features.csv")
WINDOW_SECONDS = 5
CSV_RETENTION_SECONDS = 3 * 60
CSV_PRUNE_INTERVAL_SECONDS = 3 * 60
INTERFACE = None

MODEL_FEATURE_COLUMNS = (
    "Src Port",
    "Dst Port",
    "Protocol",
    "Flow Duration",
    "Tot Fwd Pkts",
    "Tot Bwd Pkts",
    "TotLen Fwd Pkts",
    "TotLen Bwd Pkts",
    "Fwd Pkt Len Max",
    "Fwd Pkt Len Min",
    "Fwd Pkt Len Mean",
    "Fwd Pkt Len Std",
    "Bwd Pkt Len Max",
    "Bwd Pkt Len Min",
    "Bwd Pkt Len Mean",
    "Bwd Pkt Len Std",
    "Flow Byts/s",
    "Flow Pkts/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Tot",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Tot",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Len",
    "Bwd Header Len",
    "Fwd Pkts/s",
    "Bwd Pkts/s",
    "Pkt Len Min",
    "Pkt Len Max",
    "Pkt Len Mean",
    "Pkt Len Std",
    "Pkt Len Var",
    "FIN Flag Cnt",
    "SYN Flag Cnt",
    "RST Flag Cnt",
    "PSH Flag Cnt",
    "ACK Flag Cnt",
    "URG Flag Cnt",
    "CWE Flag Count",
    "ECE Flag Cnt",
    "Down/Up Ratio",
    "Pkt Size Avg",
    "Fwd Seg Size Avg",
    "Bwd Seg Size Avg",
    "Fwd Byts/b Avg",
    "Fwd Pkts/b Avg",
    "Fwd Blk Rate Avg",
    "Bwd Byts/b Avg",
    "Bwd Pkts/b Avg",
    "Bwd Blk Rate Avg",
    "Subflow Fwd Pkts",
    "Subflow Fwd Byts",
    "Subflow Bwd Pkts",
    "Subflow Bwd Byts",
    "Init Fwd Win Byts",
    "Init Bwd Win Byts",
    "Fwd Act Data Pkts",
    "Fwd Seg Size Min",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
)

CSV_HEADERS = (
    "Timestamp",
    "Src IP",
    "Dst IP",
    *MODEL_FEATURE_COLUMNS,
    "Label",
)


def _normalize_column_name(name: str) -> str:
    return "".join(character for character in name.casefold() if character.isalnum())


def flow_to_csv_row(flow: Flow) -> list[str | int | float]:
    extracted = flow.get_data()
    extracted["cwr_flag_count"] = sum(
        "C" in packet[TCP].flags
        for packet, _ in flow.packets
        if TCP in packet
    )
    values_by_name = {
        _normalize_column_name(name): value
        for name, value in extracted.items()
    }
    values_by_name["cweflagcount"] = extracted["cwr_flag_count"]

    missing_columns = [
        column
        for column in MODEL_FEATURE_COLUMNS
        if _normalize_column_name(column) not in values_by_name
    ]
    if missing_columns:
        raise ValueError(
            "CICFlowMeter did not produce required model features: "
            + ", ".join(missing_columns)
        )

    return [
        extracted["timestamp"],
        extracted["src_ip"],
        extracted["dst_ip"],
        *(
            values_by_name[_normalize_column_name(column)]
            for column in MODEL_FEATURE_COLUMNS
        ),
        "",
    ]


class FlowWindow:
    def __init__(self) -> None:
        self._flows: dict[tuple, Flow] = {}
        self._packet_count = 0
        self._lock = threading.Lock()

    def add_packet(self, packet: Packet) -> None:
        if IP not in packet or (TCP not in packet and UDP not in packet):
            return

        forward_key = get_packet_flow_key(packet, PacketDirection.FORWARD)
        reverse_key = get_packet_flow_key(packet, PacketDirection.REVERSE)

        with self._lock:
            self._packet_count += 1
            flow = self._flows.get(forward_key)
            if flow is not None:
                flow.add_packet(packet, PacketDirection.FORWARD)
                return

            flow = self._flows.get(reverse_key)
            if flow is not None:
                flow.add_packet(packet, PacketDirection.REVERSE)
                return

            self._flows[forward_key] = Flow(packet, PacketDirection.FORWARD)

    def take_flows(self) -> list[Flow]:
        flows, _ = self.take_window()
        return flows

    def take_window(self) -> tuple[list[Flow], int]:
        with self._lock:
            current_flows = self._flows
            self._flows = {}
            packet_count = self._packet_count
            self._packet_count = 0
        return list(current_flows.values()), packet_count


def open_csv_output(path: Path) -> TextIO:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        with path.open("r", newline="", encoding="utf-8") as existing_file:
            reader = csv.reader(existing_file)
            existing_headers = next(reader, [])
            has_rows = next(reader, None) is not None

        if existing_headers != list(CSV_HEADERS):
            if has_rows:
                raise ValueError(
                    f"{path} has a different CSV schema and contains data. "
                    "Choose a new output path to avoid mixing incompatible rows."
                )
            with path.open("w", newline="", encoding="utf-8") as output_file:
                csv.writer(output_file).writerow(CSV_HEADERS)

        return path.open("a", newline="", encoding="utf-8")

    output_file = path.open("w", newline="", encoding="utf-8")
    csv.writer(output_file).writerow(CSV_HEADERS)
    output_file.flush()
    return output_file


def write_flows(output_file: TextIO, flows: list[Flow]) -> list[list[str]]:
    if not flows:
        return []
    rows = [flow_to_csv_row(flow) for flow in flows]
    csv.writer(output_file).writerows(rows)
    output_file.flush()
    return [
        ["" if value is None else str(value) for value in row]
        for row in rows
    ]


def get_capture_interface() -> object:
    if INTERFACE is not None:
        return INTERFACE
    route_interface, _source_address, gateway = conf.route.route("0.0.0.0")
    if not route_interface or not gateway or gateway == "0.0.0.0":
        raise RuntimeError(
            "Could not determine the active network interface from the default route."
        )
    if not isinstance(route_interface, str):
        return route_interface

    capture_interface = next(
        (
            device
            for device in conf.ifaces.values()
            if getattr(device, "network_name", None) == route_interface
            or getattr(device, "name", None) == route_interface
        ),
        None,
    )
    if capture_interface is None:
        raise RuntimeError(
            "Scapy could not map the active default route to a capture interface: "
            f"{route_interface}"
        )
    return capture_interface


def prune_csv_output(
    path: Path,
    output_file: TextIO,
    cutoff: datetime,
) -> tuple[TextIO, int]:
    """Keep only flow rows at or newer than cutoff, preserving the CSV header."""
    temporary_path: Path | None = None
    removed_rows = 0
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            newline="",
            encoding="utf-8",
            dir=path.parent,
            prefix=f"{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)
            writer = csv.writer(temporary_file)
            with path.open("r", newline="", encoding="utf-8") as input_file:
                reader = csv.reader(input_file)
                headers = next(reader, [])
                if headers != list(CSV_HEADERS):
                    raise ValueError(f"{path} has an unexpected CSV schema.")
                writer.writerow(headers)
                for row_number, row in enumerate(reader, start=2):
                    if len(row) != len(CSV_HEADERS):
                        raise ValueError(
                            f"{path} row {row_number} has {len(row)} columns; "
                            f"expected {len(CSV_HEADERS)}."
                        )
                    try:
                        flow_timestamp = datetime.strptime(
                            row[0], "%Y-%m-%d %H:%M:%S"
                        )
                    except ValueError as exc:
                        raise ValueError(
                            f"{path} row {row_number} has an invalid flow "
                            f"timestamp: {row[0]!r}."
                        ) from exc

                    if flow_timestamp >= cutoff:
                        writer.writerow(row)
                    else:
                        removed_rows += 1

            temporary_file.flush()
            os.fsync(temporary_file.fileno())

        output_file.close()
        os.replace(temporary_path, path)
        temporary_path = None
        return path.open("a", newline="", encoding="utf-8"), removed_rows
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


def run_realtime_extractor(
    on_window_flushed: Callable[[Path, int, int], None] | None = None,
    stop_event: threading.Event | None = None,
    on_capture_window: (
        Callable[[float, int, int, float], None] | None
    ) = None,
    on_capture_state: Callable[[str], None] | None = None,
    on_flows_captured: Callable[[list[list[str]]], None] | None = None,
    on_capture_interface: Callable[[str], None] | None = None,
) -> None:
    if stop_event is None:
        stop_event = threading.Event()

    flow_window = FlowWindow()
    capture_interface = get_capture_interface()
    interface_name = str(
        getattr(capture_interface, "name", capture_interface)
    )
    if on_capture_interface is not None:
        on_capture_interface(interface_name)
    sniffer = AsyncSniffer(
        iface=capture_interface,
        filter="ip and (tcp or udp)",
        prn=flow_window.add_packet,
        store=False,
    )

    output_file = open_csv_output(CSV_PATH)
    try:
        output_file, removed_rows = prune_csv_output(
            CSV_PATH,
            output_file,
            datetime.now() - timedelta(seconds=CSV_RETENTION_SECONDS),
        )
        print(
            f"CSV retention is {CSV_RETENTION_SECONDS // 60} minutes; "
            f"removed {removed_rows} expired flow row(s) at startup."
        )
        sniffer.start()
        if on_capture_state is not None:
            on_capture_state("running")
        print(
            f"Capturing IPv4 TCP/UDP flows on {interface_name} "
            f"in {WINDOW_SECONDS}-second windows. "
            "Press Ctrl+C to stop."
        )
        next_flush = time.monotonic() + WINDOW_SECONDS
        next_prune = time.monotonic() + CSV_PRUNE_INTERVAL_SECONDS
        last_rate_sample = time.monotonic()

        try:
            while not stop_event.is_set():
                if stop_event.wait(max(0, next_flush - time.monotonic())):
                    break
                flows, packet_count = flow_window.take_window()
                now = time.monotonic()
                elapsed = max(now - last_rate_sample, 1e-6)
                last_rate_sample = now
                start_position = output_file.tell()
                captured_rows = write_flows(output_file, flows)
                if on_capture_window is not None:
                    on_capture_window(
                        packet_count / elapsed,
                        packet_count,
                        len(captured_rows),
                        elapsed,
                    )
                if captured_rows and on_flows_captured is not None:
                    on_flows_captured(captured_rows)
                end_position = output_file.tell()
                if on_window_flushed is not None:
                    on_window_flushed(CSV_PATH, start_position, end_position)
                print(
                    f"[{datetime.now():%H:%M:%S}] "
                    f"Wrote {len(flows)} flows to {CSV_PATH}"
                )

                if time.monotonic() >= next_prune:
                    output_file, removed_rows = prune_csv_output(
                        CSV_PATH,
                        output_file,
                        datetime.now() - timedelta(seconds=CSV_RETENTION_SECONDS),
                    )
                    print(
                        f"CSV retention removed {removed_rows} expired flow row(s)."
                    )
                    next_prune = time.monotonic() + CSV_PRUNE_INTERVAL_SECONDS

                next_flush += WINDOW_SECONDS
                if next_flush <= time.monotonic():
                    next_flush = time.monotonic() + WINDOW_SECONDS
        except KeyboardInterrupt:
            print("\nStopping packet capture...")
            stop_event.set()
        finally:
            if sniffer.running:
                sniffer.stop()
            if not output_file.closed:
                flows, packet_count = flow_window.take_window()
                now = time.monotonic()
                elapsed = max(now - last_rate_sample, 1e-6)
                start_position = output_file.tell()
                captured_rows = write_flows(output_file, flows)
                if on_capture_window is not None:
                    on_capture_window(
                        packet_count / elapsed,
                        packet_count,
                        len(captured_rows),
                        elapsed,
                    )
                if captured_rows and on_flows_captured is not None:
                    on_flows_captured(captured_rows)
                end_position = output_file.tell()
                if on_window_flushed is not None:
                    on_window_flushed(CSV_PATH, start_position, end_position)
                output_file.close()
                if on_capture_state is not None:
                    on_capture_state("stopped")
    except BaseException:
        if on_capture_state is not None:
            on_capture_state("error")
        if not output_file.closed:
            output_file.close()
        raise


if __name__ == "__main__":
    run_realtime_extractor()
