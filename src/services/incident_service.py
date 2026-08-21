import uuid
from datetime import datetime, timedelta
from typing import List, Dict, Any, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc
from urllib.parse import urlparse

from src.models.models import Incident, Alert, ScanHistory, UserBehaviorEvent, ThreatIntel
from src.services.alert_service import AlertSeverity

class IncidentService:
    @staticmethod
    def correlate_alert_to_incident(
        db: Session,
        workspace_id: uuid.UUID,
        alert: Alert,
        scan_history: ScanHistory | None = None
    ) -> Incident:
        """
        Correlates a newly generated alert with existing incidents in the workspace.
        Clusters related events into a single Attack Incident/Campaign.
        """
        # Determine candidate indicators
        entities_to_check = set()
        if alert.entity:
            entities_to_check.add(alert.entity.lower())
        
        if scan_history and scan_history.entities:
            for ent in scan_history.entities:
                entities_to_check.add(ent.lower())
        
        mitre_ids = set()
        if scan_history and scan_history.mitre_mappings:
            for m in scan_history.mitre_mappings:
                if m.get("technique_id"):
                    mitre_ids.add(m.get("technique_id").upper())

        # Configurable correlation window: 24 hours
        time_window = datetime.utcnow() - timedelta(hours=24)

        # Look for open incidents
        open_incidents = db.query(Incident).filter(
            Incident.workspace_id == workspace_id,
            Incident.status.in_(["OPEN", "INVESTIGATING"]),
            Incident.last_seen >= time_window
        ).all()

        matched_incident = None

        for inc in open_incidents:
            # Check overlap on affected IPs, URLs/domains, users, or MITRE techniques
            inc_ips = {ip.lower() for ip in (inc.affected_ips or [])}
            inc_urls = {u.lower() for u in (inc.affected_urls_domains or [])}
            inc_mitre = {m.upper() for m in (inc.mitre_techniques or [])}
            
            # Check if any candidate entity is already linked
            if entities_to_check.intersection(inc_ips) or entities_to_check.intersection(inc_urls):
                matched_incident = inc
                break
                
            # Check if user matches
            if alert.user_id and str(alert.user_id) in (inc.affected_users or []):
                matched_incident = inc
                break

            # Check if MITRE technique matches
            if mitre_ids.intersection(inc_mitre):
                matched_incident = inc
                break

        if matched_incident:
            # Update existing incident
            matched_incident.last_seen = alert.created_at
            
            # Update alerts list
            alerts_list = list(matched_incident.related_alerts or [])
            if str(alert.id) not in alerts_list:
                alerts_list.append(str(alert.id))
            matched_incident.related_alerts = alerts_list

            # Update assets
            ips = list(matched_incident.affected_ips or [])
            urls = list(matched_incident.affected_urls_domains or [])
            users = list(matched_incident.affected_users or [])
            reasons = list(matched_incident.correlation_reasons or [])
            m_techs = list(matched_incident.mitre_techniques or [])

            # Classify new entities
            for ent in entities_to_check:
                if "." in ent or ":" in ent:  # Simple IP/domain check
                    if ent.replace(".", "").isdigit() or ":" in ent:
                        if ent not in ips:
                            ips.append(ent)
                    else:
                        if ent not in urls:
                            urls.append(ent)
                elif "://" in ent:
                    if ent not in urls:
                        urls.append(ent)

            if alert.user_id and str(alert.user_id) not in users:
                users.append(str(alert.user_id))

            if alert.alert_type not in reasons:
                reasons.append(alert.alert_type)

            for m_id in mitre_ids:
                if m_id not in m_techs:
                    m_techs.append(m_id)

            matched_incident.affected_ips = ips
            matched_incident.affected_urls_domains = urls
            matched_incident.affected_users = users
            matched_incident.correlation_reasons = reasons
            matched_incident.mitre_techniques = m_techs

            # Recalculate score (max + slight boost)
            base_score = max(matched_incident.risk_score, alert.risk_score)
            boost = 5 * (len(alerts_list) - 1)
            matched_incident.risk_score = min(100, base_score + boost)
            matched_incident.severity = AlertSeverity.from_risk_score(matched_incident.risk_score)
            matched_incident.confidence = max(matched_incident.confidence, alert.ml_confidence)
            
            # Link alert and scan
            alert.incident_id = matched_incident.id
            if scan_history:
                scan_history.incident_id = matched_incident.id

            db.flush()
            return matched_incident
        else:
            # Create new incident
            ips = []
            urls = []
            users = []
            m_techs = list(mitre_ids)

            # Classify entities
            for ent in entities_to_check:
                if "." in ent or ":" in ent:
                    if ent.replace(".", "").isdigit() or ":" in ent:
                        ips.append(ent)
                    else:
                        urls.append(ent)
                elif "://" in ent:
                    urls.append(ent)

            if alert.user_id:
                users.append(str(alert.user_id))

            new_inc = Incident(
                id=uuid.uuid4(),
                workspace_id=workspace_id,
                severity=alert.severity,
                risk_score=alert.risk_score,
                confidence=alert.ml_confidence,
                first_seen=alert.created_at,
                last_seen=alert.created_at,
                affected_users=users,
                affected_ips=ips,
                affected_urls_domains=urls,
                affected_endpoints=[],
                related_alerts=[str(alert.id)],
                mitre_techniques=m_techs,
                correlation_reasons=[alert.alert_type],
                status="OPEN"
            )
            db.add(new_inc)
            db.flush()

            # Link alert and scan
            alert.incident_id = new_inc.id
            if scan_history:
                scan_history.incident_id = new_inc.id

            db.flush()
            return new_inc

    @staticmethod
    def generate_timeline(db: Session, workspace_id: uuid.UUID, incident_id: uuid.UUID) -> List[Dict[str, Any]]:
        """
        Compiles all events belonging to an incident in chronological order.
        """
        timeline = []

        # 1. Fetch alerts
        alerts = db.query(Alert).filter(
            Alert.workspace_id == workspace_id,
            Alert.incident_id == incident_id
        ).all()

        for a in alerts:
            timeline.append({
                "timestamp": a.created_at.isoformat(),
                "event_type": "Alert Generated",
                "entity": a.entity,
                "source": a.source_vector,
                "severity": a.severity,
                "risk_score": a.risk_score,
                "detection_result": a.alert_type.upper(),
                "related_evidence": [a.description],
                "mitre_technique": a.indicators[0].get("value") if (a.indicators and len(a.indicators) > 0) else None,
                "correlation_reason": f"System raised alert {a.title} with score {a.risk_score}"
            })

        # 2. Fetch scan histories
        scans = db.query(ScanHistory).filter(
            ScanHistory.workspace_id == workspace_id,
            ScanHistory.incident_id == incident_id
        ).all()

        for s in scans:
            # Avoid duplicate alert records in timeline
            # If scan triggered alert, alert covers it, but scans without alerts are useful too
            # For this exercise, add scan events as "Scan Analyzed"
            m_techs = [m.get("technique_id") for m in (s.mitre_mappings or []) if m.get("technique_id")]
            timeline.append({
                "timestamp": s.created_at.isoformat(),
                "event_type": "Payload Scanned",
                "entity": s.entity,
                "source": s.input_type.upper(),
                "severity": s.severity,
                "risk_score": s.risk_score,
                "detection_result": s.verdict,
                "related_evidence": [f"Scanned {s.input_type} payload: {s.entity}"],
                "mitre_technique": m_techs[0] if m_techs else None,
                "correlation_reason": f"Payload analysis completed. Verdict: {s.verdict}"
            })

        # 3. Fetch related UBA events
        incident = db.query(Incident).filter(Incident.id == incident_id).first()
        if incident:
            # Query UBA events matching users or IPs within time window
            user_ids = [uuid.UUID(uid) for uid in incident.affected_users if uid]
            ips = incident.affected_ips
            
            uba_query = db.query(UserBehaviorEvent).filter(
                UserBehaviorEvent.workspace_id == workspace_id,
                UserBehaviorEvent.timestamp >= incident.first_seen - timedelta(hours=2),
                UserBehaviorEvent.timestamp <= incident.last_seen + timedelta(hours=2)
            )

            uba_filters = []
            if user_ids:
                uba_filters.append(UserBehaviorEvent.user_id.in_(user_ids))
            if ips:
                uba_filters.append(UserBehaviorEvent.ip_address.in_(ips))

            if uba_filters:
                uba_events = uba_query.filter(or_(*uba_filters)).all()
                for ue in uba_events:
                    timeline.append({
                        "timestamp": ue.timestamp.isoformat(),
                        "event_type": "UBA Anomaly Observed",
                        "entity": ue.ip_address or str(ue.user_id),
                        "source": "UBA Engine",
                        "severity": ue.risk_level,
                        "risk_score": ue.anomaly_score,
                        "detection_result": "ANOMALOUS BEHAVIOR",
                        "related_evidence": [f"UBA detected: {ue.event_type} anomaly"],
                        "mitre_technique": "T1110" if "auth" in ue.event_type.lower() else None,
                        "correlation_reason": f"Deviation score of {ue.anomaly_score} detected for {ue.event_type}"
                    })

        # Sort chronologically
        timeline.sort(key=lambda x: x["timestamp"])
        return timeline

    @staticmethod
    def generate_attack_path(db: Session, workspace_id: uuid.UUID, incident_id: uuid.UUID) -> List[Dict[str, Any]]:
        """
        Generates a simplified sequential flow of attack events.
        """
        timeline = IncidentService.generate_timeline(db, workspace_id, incident_id)
        
        path = []
        step = 1
        
        # Build logical sequences: IP -> Event -> Alert -> Anomaly
        for item in timeline:
            # Extract relevant step information
            path.append({
                "step": step,
                "timestamp": item["timestamp"],
                "type": item["event_type"],
                "label": f"{item['event_type']}: {item['entity']}",
                "description": item["related_evidence"][0] if item["related_evidence"] else ""
            })
            step += 1
            
        return path

    @staticmethod
    def generate_attack_graph(db: Session, workspace_id: uuid.UUID, incident_id: uuid.UUID) -> Dict[str, Any]:
        """
        Builds a relationship graph between security entities involved in the incident.
        """
        nodes = {}
        edges = []

        incident = db.query(Incident).filter(
            Incident.workspace_id == workspace_id,
            Incident.id == incident_id
        ).first()

        if not incident:
            return {"nodes": [], "edges": []}

        # 1. Add Incident root node
        nodes["incident"] = {
            "id": f"incident_{incident.id}",
            "type": "INCIDENT",
            "label": f"Incident Campaign ({incident.severity})",
            "risk_score": incident.risk_score,
            "severity": incident.severity
        }

        # Fetch all alerts
        alerts = db.query(Alert).filter(
            Alert.workspace_id == workspace_id,
            Alert.incident_id == incident_id
        ).all()

        # Fetch scans
        scans = db.query(ScanHistory).filter(
            ScanHistory.workspace_id == workspace_id,
            ScanHistory.incident_id == incident_id
        ).all()

        # Populate nodes & relationships
        for a in alerts:
            alert_node_id = f"alert_{a.id}"
            nodes[alert_node_id] = {
                "id": alert_node_id,
                "type": "ALERT",
                "label": a.title,
                "risk_score": a.risk_score,
                "severity": a.severity
            }
            edges.append({
                "source": alert_node_id,
                "target": f"incident_{incident.id}",
                "type": "belongs_to"
            })

            # Map alert entity
            entity_id = f"entity_{a.entity.lower()}"
            entity_type = a.entity_type.upper() if a.entity_type else "IP"
            if entity_id not in nodes:
                nodes[entity_id] = {
                    "id": entity_id,
                    "type": entity_type,
                    "label": a.entity,
                    "risk_score": a.risk_score,
                    "severity": a.severity
                }
            
            # Entity -> generated -> ALERT or ALERT -> target -> Entity
            edges.append({
                "source": entity_id,
                "target": alert_node_id,
                "type": "generated" if entity_type == "IP" else "triggered"
            })

        for s in scans:
            scan_node_id = f"scan_{s.id}"
            nodes[scan_node_id] = {
                "id": scan_node_id,
                "type": "NETWORK_EVENT" if s.input_type == "network" else s.input_type.upper(),
                "label": f"{s.input_type.upper()} Scan: {s.entity[:20]}",
                "risk_score": s.risk_score,
                "severity": s.severity
            }

            # Link scan to its alert if scan_history_id matches
            for a in alerts:
                if a.scan_history_id == s.id:
                    edges.append({
                        "source": scan_node_id,
                        "target": f"alert_{a.id}",
                        "type": "triggered"
                    })

            # Check detailed entities inside scan
            # E.g. email contained URL
            if s.input_type == "email" and s.entities:
                for ent in s.entities:
                    ent_id = f"entity_{ent.lower()}"
                    if ent_id not in nodes:
                        nodes[ent_id] = {
                            "id": ent_id,
                            "type": "URL" if "://" in ent or "." in ent else "EMAIL",
                            "label": ent,
                            "risk_score": s.risk_score,
                            "severity": s.severity
                        }
                    edges.append({
                        "source": scan_node_id,
                        "target": ent_id,
                        "type": "contained"
                    })
            
            # URL resolves to IP/Domain
            if s.input_type == "url":
                try:
                    parsed = urlparse(s.entity)
                    domain = parsed.netloc or s.entity
                    domain_id = f"entity_{domain.lower()}"
                    if domain_id not in nodes:
                        nodes[domain_id] = {
                            "id": domain_id,
                            "type": "DOMAIN",
                            "label": domain,
                            "risk_score": s.risk_score,
                            "severity": s.severity
                        }
                    edges.append({
                        "source": scan_node_id,
                        "target": domain_id,
                        "type": "contacted"
                    })
                except Exception:
                    pass

            # MITRE ATT&CK techniques mapping
            if s.mitre_mappings:
                for m in s.mitre_mappings:
                    m_id = m.get("technique_id")
                    if m_id:
                        node_m_id = f"mitre_{m_id.lower()}"
                        if node_m_id not in nodes:
                            nodes[node_m_id] = {
                                "id": node_m_id,
                                "type": "MITRE_TECHNIQUE",
                                "label": f"{m.get('technique')} ({m_id})",
                                "risk_score": s.risk_score,
                                "severity": m.get("severity", "MEDIUM")
                            }
                        edges.append({
                            "source": scan_node_id,
                            "target": node_m_id,
                            "type": "mapped_to"
                        })

        # Add affected users
        for uid in incident.affected_users:
            user_node_id = f"user_{uid}"
            if user_node_id not in nodes:
                nodes[user_node_id] = {
                    "id": user_node_id,
                    "type": "USER",
                    "label": f"User: {uid[:8]}...",
                    "risk_score": incident.risk_score,
                    "severity": incident.severity
                }
            # User received/accessed entities
            for ent_id, ent_node in list(nodes.items()):
                if ent_node["type"] == "EMAIL":
                    edges.append({
                        "source": user_node_id,
                        "target": ent_id,
                        "type": "received"
                    })
                elif ent_node["type"] == "URL":
                    edges.append({
                        "source": user_node_id,
                        "target": ent_id,
                        "type": "accessed"
                    })

        return {
            "nodes": list(nodes.values()),
            "edges": edges
        }

    @staticmethod
    def process_scan_correlation(
        db: Session,
        workspace_id: uuid.UUID,
        scan_log: ScanHistory,
        result: Dict[str, Any]
    ):
        """
        Processes correlation and evidence collection after a scan is completed.
        Called by both endpoint handlers and website monitoring background services.
        """
        alert_info = result.get("alert") or {}
        alert_id_str = alert_info.get("alert_id")
        if alert_id_str:
            try:
                alert_id = uuid.UUID(alert_id_str)
                generated_alert = db.query(Alert).filter(Alert.id == alert_id).first()
                
                if generated_alert:
                    from src.services.evidence_service import EvidenceEngine

                    # Correlate alert and scan_log
                    incident = IncidentService.correlate_alert_to_incident(
                        db=db,
                        workspace_id=workspace_id,
                        alert=generated_alert,
                        scan_history=scan_log
                    )
                    
                    # Ensure the scan log has the incident ID linked
                    scan_log.incident_id = incident.id
                    
                    # Collect evidence for the incident
                    EvidenceEngine.collect_evidence(
                        db=db,
                        workspace_id=workspace_id,
                        incident_alert_id=incident.id,
                        result=result,
                        supporting_entity_id=str(scan_log.id)
                    )
            except Exception as e:
                # Log error but don't fail the primary threat detection path
                print(f"Incident/Evidence processing failed: {e}")
