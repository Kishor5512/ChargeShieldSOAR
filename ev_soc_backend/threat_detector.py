import asyncio
import logging
import math
import socket
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import psutil

# Import the global SOAR engine instance from soar_engine.py
try:
    from soar_engine import soar
except ImportError:
    # Fallback dummy SOAR instance if soar_engine.py is missing or not in the same directory
    class MockSOAR:
        def is_ip_blocked(self, ip: str) -> bool:
            return False

        async def dispatch(self, **kwargs) -> Dict[str, Any]:
            print("\n[MOCK SOAR DISPATCH]:", kwargs)
            return {"status": "mock_mitigated"}

    soar = MockSOAR()

# Configure Logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("LIVE_THREAT_DETECTOR")


class SystemNetworkTelemetryCollector:
    """Collects real-time OS system metrics and network socket parameters."""

    def __init__(self, interface_name: Optional[str] = None):
        self.interface_name = interface_name or self._get_default_interface()
        self.prev_net_io = psutil.net_io_counters()
        self.prev_cpu_times = psutil.cpu_times()
        self.last_sample_time = time.time()

    def _get_default_interface(self) -> str:
        """Finds the primary active network interface."""
        stats = psutil.net_if_stats()
        for iface, stat in stats.items():
            if stat.isup and iface != "lo":
                return iface
        return "eth0"

    def capture_telemetry_snapshot(self) -> Dict[str, Any]:
        """Captures low-level system CPU, RAM, Process, and Network Socket metrics."""
        now = time.time()
        dt = max(now - self.last_sample_time, 0.001)

        # 1. System CPU & Memory Utilization
        cpu_percent = psutil.cpu_percent(interval=None)
        memory = psutil.virtual_memory()

        # 2. Process Monitored High-Load Processes (e.g., Malware/Crypto-miners)
        high_cpu_processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
            try:
                if proc.info['cpu_percent'] and proc.info['cpu_percent'] > 50.0:
                    high_cpu_processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        # 3. Low-Level Network Socket Metrics & Connections
        connections = psutil.net_connections(kind='inet')
        established_sockets = 0
        failed_auth_indicators = 0
        active_ips: List[str] = []

        for conn in connections:
            if conn.status == psutil.CONN_ESTABLISHED:
                established_sockets += 1
                if conn.raddr:
                    active_ips.append(conn.raddr.ip)
            elif conn.status in (psutil.CONN_SYN_SENT, psutil.CONN_SYN_RECV, psutil.CONN_CLOSE_WAIT):
                failed_auth_indicators += 1
                if conn.raddr:
                    active_ips.append(conn.raddr.ip)

        # Primary source IP targeting/connecting to the machine
        primary_source_ip = active_ips[0] if active_ips else "127.0.0.1"

        # 4. Network I/O Rates (Bytes/Packets per second)
        current_net_io = psutil.net_io_counters()
        bytes_recv_rate = (current_net_io.bytes_recv - self.prev_net_io.bytes_recv) / dt
        packets_recv_rate = (current_net_io.packets_recv - self.prev_net_io.packets_recv) / dt

        # Mean Packet Inter-Arrival Time (IAT) approximation (in milliseconds)
        packet_iat_mean_ms = (1000.0 / packets_recv_rate) if packets_recv_rate > 0 else 0.0

        # Update state pointers
        self.prev_net_io = current_net_io
        self.last_sample_time = now

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "cpu_utilization": cpu_percent,
            "memory_utilization": memory.percent,
            "bytes_recv_rate": bytes_recv_rate,
            "packets_recv_rate": packets_recv_rate,
            "packet_iat_mean_ms": packet_iat_mean_ms,
            "established_sockets": established_sockets,
            "failed_auth_attempts": failed_auth_indicators,
            "high_cpu_processes": high_cpu_processes,
            "source_ip": primary_source_ip,
        }


class RealTimeAnomalyPredictor:
    """Evaluates incoming live system metrics using rule-based/threshold probabilistic models."""

    def __init__(self):
        # Baseline threshold parameters
        self.MAX_PACKETS_PER_SEC = 1500.0   # DoS Flooding threshold
        self.MIN_IAT_MS = 2.0               # Recon / Port Scanning threshold
        self.MAX_CPU_LOAD = 85.0            # Malware / Mining threshold
        self.AUTH_FAILURE_LIMIT = 5         # Brute Force threshold

    def predict_threat(self, telemetry: Dict[str, Any]) -> Tuple[Optional[str], float, float]:
        """Analyzes real-time metrics and returns (threat_type, confidence, risk_score).

        Returns (None, 0.0, 0.0) if network/system state is benign.
        """
        packets_rate = telemetry.get("packets_recv_rate", 0.0)
        iat_ms = telemetry.get("packet_iat_mean_ms", 0.0)
        cpu_load = telemetry.get("cpu_utilization", 0.0)
        failed_auth = telemetry.get("failed_auth_attempts", 0)

        # Vector 1: DoS Flooding Detection
        if packets_rate > self.MAX_PACKETS_PER_SEC:
            confidence = min(0.99, packets_rate / (self.MAX_PACKETS_PER_SEC * 1.5))
            risk_score = round(confidence * 85.0, 2)
            return "DOS_FLOODING", confidence, risk_score

        # Vector 2: Reconnaissance / Port Scanning Detection
        if 0.0 < iat_ms < self.MIN_IAT_MS and packets_rate > 300:
            confidence = 0.92
            risk_score = 65.0
            return "RECON_SCANNING", confidence, risk_score

        # Vector 3: Host Malware / Rogue Process Detection
        if cpu_load > self.MAX_CPU_LOAD and len(telemetry.get("high_cpu_processes", [])) > 0:
            confidence = 0.88
            risk_score = 78.5
            return "HOST_MALWARE", confidence, risk_score

        # Vector 4: Unauthorized Access / Brute Force
        if failed_auth >= self.AUTH_FAILURE_LIMIT:
            confidence = min(0.95, failed_auth / 10.0)
            risk_score = 70.0
            return "UNAUTHORIZED_ACCESS", confidence, risk_score

        # System state is Benign
        return None, 0.0, 0.0


class SystemThreatDetectorMonitor:
    """Main daemon loop running real-time metric capture, threat prediction, and SOAR dispatch."""

    def __init__(self, soar_engine_instance: Any, poll_interval_sec: float = 1.0):
        self.collector = SystemNetworkTelemetryCollector()
        self.predictor = RealTimeAnomalyPredictor()
        self.soar = soar_engine_instance
        self.poll_interval = poll_interval_sec
        self.is_running = False

    async def start_monitoring(self):
        """Starts the real-time background monitoring loop."""
        self.is_running = True
        logger.info("🔍 Live System & Network Threat Detector active. Monitoring host metrics...")

        while self.is_running:
            try:
                # Step 1: Capture direct OS & Network Telemetry Snapshot
                telemetry = self.collector.capture_telemetry_snapshot()

                # Step 2: Skip evaluation if source IP is already blacklisted by SOAR
                source_ip = telemetry.get("source_ip", "127.0.0.1")
                if self.soar.is_ip_blocked(source_ip):
                    await asyncio.sleep(self.poll_interval)
                    continue

                # Step 3: Run Threat Anomaly Prediction Model
                threat_type, confidence, risk_score = self.predictor.predict_threat(telemetry)

                # Step 4: Dispatch Threat to SOAR Engine if Anomaly Detected
                if threat_type:
                    logger.warning(
                        f"⚠️ THREAT DETECTED: {threat_type} | Confidence: {confidence:.2f} | Risk: {risk_score}"
                    )
                    await self.soar.dispatch(
                        threat_type=threat_type,
                        confidence=confidence,
                        risk_score=risk_score,
                        telemetry=telemetry
                    )

            except Exception as e:
                logger.error(f"Error in threat detection pipeline loop: {e}", exc_info=True)

            await asyncio.sleep(self.poll_interval)

    def stop(self):
        self.is_running = False


# --------------------------------------------------------------------------
# EXECUTION ENTRY POINT
# --------------------------------------------------------------------------
if __name__ == "__main__":
    # Pass the imported `soar` instance to the monitoring daemon
    monitor = SystemThreatDetectorMonitor(soar_engine_instance=soar, poll_interval_sec=1.0)

    try:
        asyncio.run(monitor.start_monitoring())
    except KeyboardInterrupt:
        monitor.stop()
        print("\n[+] Monitoring daemon stopped cleanly by user.")