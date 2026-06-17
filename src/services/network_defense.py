from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List

from sqlalchemy.orm import Session

from src.models.models import AuditLog, Workspace
from src.utils.audit import AuditLogger


class NetworkDefenseService:
    @staticmethod
    def _get_ip(flow: Dict[str, Any], *keys: str) -> str | None:
        for key in keys:
            value = flow.get(key)
            if value:
                return str(value)
        return None

    @staticmethod
    def evaluate_flow(db: Session, workspace: Workspace, flow: Dict[str, Any]) -> Dict[str, Any]:
        src_ip = NetworkDefenseService._get_ip(flow, "Source IP", "src_ip", "source_ip", "ip")
        dst_ip = NetworkDefenseService._get_ip(flow, "Destination IP", "dst_ip", "destination_ip")
        dst_port = flow.get("Destination Port") or flow.get("dst_port") or flow.get("port")
        flow_rate = float(flow.get("Flow Bytes/s") or flow.get("flow_rate") or 0)
        packet_rate = float(flow.get("Flow Packets/s") or flow.get("packet_rate") or 0)
        failed_auth = int(flow.get("failed_auth_count") or flow.get("login_failures") or 0)
        protocol = str(flow.get("Protocol") or flow.get("protocol") or "").lower()
        syn_flags = int(flow.get("SYN Flag Count") or flow.get("syn_flag_count") or 0)

        reasons: List[str] = []
        severity = "LOW"
        anomaly_score = 0
        temporary_block = False
        rate_limit = False

        if flow_rate > 100000 or packet_rate > 5000:
            reasons.append("abnormally_high_traffic_rate")
            anomaly_score += 25

        if failed_auth >= 5:
            reasons.append("multiple_failed_authentication_attempts")
            anomaly_score += 30

        if protocol and protocol not in {"tcp", "udp", "icmp", "6", "17", "1"}:
            reasons.append("suspicious_protocol_usage")
            anomaly_score += 20

        if syn_flags >= 20:
            reasons.append("repeated_connection_attempts")
            anomaly_score += 20

        if src_ip:
            recent_window = datetime.utcnow() - timedelta(minutes=10)
            recent_events = db.query(AuditLog).filter(
                AuditLog.workspace_id == workspace.id,
                AuditLog.module == "network_prevention",
                AuditLog.created_at >= recent_window
            ).all()

            ip_events = [
                event for event in recent_events
                if (event.event_metadata or {}).get("source_ip") == src_ip
            ]
            if len(ip_events) >= 3:
                reasons.append("repeat_offender_ip")
                anomaly_score += 25

        if src_ip and isinstance(dst_port, (int, float)) and dst_port:
            scanned_ports = defaultdict(set)
            recent_window = datetime.utcnow() - timedelta(minutes=15)
            recent_events = db.query(AuditLog).filter(
                AuditLog.workspace_id == workspace.id,
                AuditLog.module == "network_prevention",
                AuditLog.created_at >= recent_window
            ).all()
            for event in recent_events:
                metadata = event.event_metadata or {}
                ip = metadata.get("source_ip")
                port = metadata.get("destination_port")
                if ip and port:
                    scanned_ports[ip].add(str(port))
            scanned_ports[src_ip].add(str(dst_port))
            if len(scanned_ports[src_ip]) >= 10:
                reasons.append("port_scanning_pattern")
                anomaly_score += 35

        if anomaly_score >= 70:
            severity = "CRITICAL"
            temporary_block = True
            rate_limit = True
        elif anomaly_score >= 45:
            severity = "HIGH"
            rate_limit = True
        elif anomaly_score >= 20:
            severity = "MEDIUM"

        event = {
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "destination_port": dst_port,
            "protocol": protocol,
            "anomaly_score": min(anomaly_score, 100),
            "severity": severity,
            "reasons": reasons,
            "temporary_block": temporary_block,
            "rate_limited": rate_limit,
            "alert": bool(reasons),
        }

        if reasons:
            AuditLogger.log(
                db,
                action="network_intrusion_rule_triggered",
                module="network_prevention",
                status="warning" if severity != "CRITICAL" else "failure",
                workspace_id=workspace.id,
                metadata=event,
            )

        return event
