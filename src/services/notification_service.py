"""
Alert Notification Service
Handles email, webhook, and in-dashboard notifications
"""
from typing import Dict, Any, Optional, List
from datetime import datetime
import asyncio
import json
import logging
from sqlalchemy.orm import Session
from src.models.models import Alert

logger = logging.getLogger(__name__)


class NotificationService:
    """
    Multi-channel notification service for alert distribution
    Supports email, webhooks, and in-dashboard notifications
    """
    
    # Email configuration (production should use environment variables)
    SMTP_ENABLED = False  # Enable in production with real SMTP
    SMTP_HOST = "smtp.gmail.com"
    SMTP_PORT = 587
    SMTP_USER = "alerts@cyberguard.ai"
    SMTP_PASSWORD = "your-password-here"
    
    # Webhook configuration
    WEBHOOK_TIMEOUT = 5  # seconds
    
    @staticmethod
    def prepare_alert_payload(alert: Alert) -> Dict[str, Any]:
        """
        Prepare alert data for webhook delivery
        
        Args:
            alert: Alert object
            
        Returns:
            Dictionary formatted for external consumption
        """
        return {
            "alert_id": str(alert.id),
            "timestamp": alert.created_at.isoformat() if alert.created_at else None,
            "severity": alert.severity,
            "alert_type": alert.alert_type,
            "title": alert.title,
            "description": alert.description,
            "entity": alert.entity,
            "entity_type": alert.entity_type,
            "source_vector": alert.source_vector,
            "risk_score": alert.risk_score,
            "ml_confidence": alert.ml_confidence,
            "recommended_action": alert.recommended_action,
            "indicators": alert.indicators,
            "correlated_events": alert.correlated_events,
            "workspace_id": str(alert.workspace_id),
        }
    
    @staticmethod
    def prepare_email_content(alert: Alert) -> Dict[str, str]:
        """
        Prepare email content for alert notification
        
        Args:
            alert: Alert object
            
        Returns:
            Dictionary with subject and body
        """
        severity_emoji = {
            "CRITICAL": "🚨",
            "HIGH": "⚠️",
            "MEDIUM": "⚡",
            "LOW": "ℹ️",
        }.get(alert.severity, "📌")
        
        subject = f"{severity_emoji} [{alert.severity}] {alert.title}"
        
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; background-color: #f3f4f6; }}
                .container {{ max-width: 600px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }}
                .header {{ background: linear-gradient(135deg, #3b82f6, #8b5cf6); color: white; padding: 20px; border-radius: 8px 8px 0 0; margin: -20px -20px 20px -20px; }}
                .alert-title {{ font-size: 24px; margin: 0 0 8px; }}
                .severity-badge {{
                    display: inline-block;
                    padding: 8px 16px;
                    border-radius: 6px;
                    font-weight: bold;
                    margin-bottom: 20px;
                }}
                .severity-critical {{ background: rgba(239, 68, 68, 0.2); color: #ef4444; }}
                .severity-high {{ background: rgba(249, 115, 22, 0.2); color: #f97316; }}
                .severity-medium {{ background: rgba(245, 158, 11, 0.2); color: #f59e0b; }}
                .severity-low {{ background: rgba(16, 185, 129, 0.2); color: #10b981; }}
                .info-section {{ margin: 20px 0; padding: 15px; background: #f9fafb; border-left: 4px solid #3b82f6; border-radius: 4px; }}
                .info-label {{ font-weight: bold; color: #374151; margin-bottom: 4px; }}
                .info-value {{ color: #6b7280; font-family: 'Courier New', monospace; }}
                .action-section {{ background: rgba(59, 130, 246, 0.1); border-left: 4px solid #3b82f6; padding: 15px; border-radius: 4px; margin: 20px 0; }}
                .action-label {{ font-weight: bold; color: #1e40af; margin-bottom: 8px; }}
                .action-text {{ color: #1e3a8a; line-height: 1.6; }}
                .button {{ display: inline-block; background: #3b82f6; color: white; padding: 12px 24px; border-radius: 6px; text-decoration: none; margin-top: 10px; }}
                .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb; color: #6b7280; font-size: 12px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <div class="alert-title">{alert.title}</div>
                </div>
                
                <div class="severity-badge severity-{alert.severity.lower()}">
                    {severity_emoji} {alert.severity} Severity Alert
                </div>
                
                <div class="info-section">
                    <div class="info-label">Description</div>
                    <div class="info-value">{alert.description}</div>
                </div>
                
                <div class="info-section">
                    <div class="info-label">Alert Details</div>
                    <table style="width: 100%; border-collapse: collapse;">
                        <tr>
                            <td style="padding: 6px 0; font-weight: bold; color: #374151;">Alert Type:</td>
                            <td style="padding: 6px 0; color: #6b7280; font-family: 'Courier New', monospace;">{alert.alert_type}</td>
                        </tr>
                        <tr>
                            <td style="padding: 6px 0; font-weight: bold; color: #374151;">Entity:</td>
                            <td style="padding: 6px 0; color: #6b7280; font-family: 'Courier New', monospace;">{alert.entity}</td>
                        </tr>
                        <tr>
                            <td style="padding: 6px 0; font-weight: bold; color: #374151;">Risk Score:</td>
                            <td style="padding: 6px 0; color: #6b7280;">{alert.risk_score}/100</td>
                        </tr>
                        <tr>
                            <td style="padding: 6px 0; font-weight: bold; color: #374151;">Source Vector:</td>
                            <td style="padding: 6px 0; color: #6b7280;">{alert.source_vector}</td>
                        </tr>
                        <tr>
                            <td style="padding: 6px 0; font-weight: bold; color: #374151;">ML Confidence:</td>
                            <td style="padding: 6px 0; color: #6b7280;">{alert.ml_confidence}%</td>
                        </tr>
                    </table>
                </div>
                
                {f'''
                <div class="action-section">
                    <div class="action-label">Recommended Action</div>
                    <div class="action-text">{alert.recommended_action}</div>
                </div>
                ''' if alert.recommended_action else ''}
                
                {f'''
                <div class="info-section">
                    <div class="info-label">Indicators ({len(alert.indicators)} detected)</div>
                    <ul style="margin: 8px 0; padding-left: 20px;">
                        {"".join([f"<li>{ind['type'].upper()}: {ind['value']} ({ind['source']})</li>" for ind in alert.indicators[:5]])}
                        {f"<li style='color: #9ca3af;'>... and {len(alert.indicators) - 5} more</li>" if len(alert.indicators) > 5 else ""}
                    </ul>
                </div>
                ''' if alert.indicators else ''}
                
                <a href="https://cyberguard.ai/dashboard/alerts/{alert.id}" class="button">
                    View in Dashboard
                </a>
                
                <div class="footer">
                    <p>Alert ID: {alert.id}<br/>
                    Timestamp: {alert.created_at.strftime('%Y-%m-%d %H:%M:%S UTC') if alert.created_at else 'N/A'}<br/>
                    CyberGuard AI - Enterprise Threat Detection</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return {
            "subject": subject,
            "html": html_body,
            "text": NotificationService._prepare_text_content(alert, severity_emoji),
        }
    
    @staticmethod
    def _prepare_text_content(alert: Alert, severity_emoji: str) -> str:
        """Prepare plain text version of alert"""
        text = f"""
{severity_emoji} {alert.severity} SEVERITY ALERT

TITLE: {alert.title}

DESCRIPTION:
{alert.description}

ALERT DETAILS:
- Alert Type: {alert.alert_type}
- Entity: {alert.entity}
- Risk Score: {alert.risk_score}/100
- Source Vector: {alert.source_vector}
- ML Confidence: {alert.ml_confidence}%

RECOMMENDED ACTION:
{alert.recommended_action if alert.recommended_action else 'Review alert details and take appropriate action.'}

INDICATORS:
{chr(10).join([f"- {ind['type'].upper()}: {ind['value']} (Source: {ind['source']})" for ind in alert.indicators[:5]]) if alert.indicators else '- No indicators'}

---
Alert ID: {alert.id}
Timestamp: {alert.created_at.strftime('%Y-%m-%d %H:%M:%S UTC') if alert.created_at else 'N/A'}
CyberGuard AI - Enterprise Threat Detection
        """
        return text.strip()
    
    @staticmethod
    async def send_email_notification(
        recipient_emails: List[str],
        alert: Alert,
    ) -> Dict[str, bool]:
        """
        Send email notification (async, production implementation)
        
        Args:
            recipient_emails: List of email recipients
            alert: Alert object
            
        Returns:
            Dictionary with success status for each recipient
        """
        content = NotificationService.prepare_email_content(alert)
        results = {}
        
        if not NotificationService.SMTP_ENABLED:
            # Simulated sending
            logger.info("email_notification_simulated", extra={"recipients": recipient_emails, "subject": content['subject']})
            
            for email in recipient_emails:
                results[email] = True
            return results
        
        # Production implementation would use smtplib or similar
        # import smtplib
        # from email.mime.text import MIMEText
        # from email.mime.multipart import MIMEMultipart
        
        # ... implementation here ...
        
        return results
    
    @staticmethod
    async def send_webhook_notification(
        webhook_url: str,
        alert: Alert,
    ) -> bool:
        """
        Send webhook notification (async, production implementation)
        
        Args:
            webhook_url: Webhook endpoint URL
            alert: Alert object
            
        Returns:
            Success status
        """
        payload = NotificationService.prepare_alert_payload(alert)
        
        # Simulated webhook sending
        logger.info("webhook_notification_simulated", extra={"url": webhook_url, "payload": payload})
        
        # Production implementation would use httpx or aiohttp
        # import httpx
        # async with httpx.AsyncClient(timeout=NotificationService.WEBHOOK_TIMEOUT) as client:
        #     try:
        #         response = await client.post(webhook_url, json=payload)
        #         return response.status_code < 400
        #     except Exception as e:
        #         print(f"Webhook delivery failed: {e}")
        #         return False
        
        return True
    
    @staticmethod
    async def send_notifications(
        db: Session,
        alert: Alert,
        recipient_emails: Optional[List[str]] = None,
        webhook_urls: Optional[List[str]] = None,
    ) -> None:
        """
        Send notifications through multiple channels
        
        Args:
            db: Database session
            alert: Alert object
            recipient_emails: List of email recipients
            webhook_urls: List of webhook endpoints
        """
        tasks = []
        
        # Queue email notifications
        if recipient_emails:
            tasks.append(NotificationService.send_email_notification(recipient_emails, alert))
            alert.email_sent = True
        
        # Queue webhook notifications
        if webhook_urls:
            for url in webhook_urls:
                tasks.append(NotificationService.send_webhook_notification(url, alert))
            alert.webhook_sent = True
        
        # Mark notification as sent (in-dashboard)
        if recipient_emails or webhook_urls:
            alert.notification_sent = True
        
        # Execute all async tasks
        if tasks:
            await asyncio.gather(*tasks)
        
        db.commit()
    
    @staticmethod
    def get_alert_recipients(
        db: Session,
        workspace_id,
    ) -> Dict[str, list]:
        """
        Get notification recipients for workspace
        (Can be extended to fetch from workspace settings)
        
        Args:
            db: Database session
            workspace_id: Workspace ID
            
        Returns:
            Dictionary with emails and webhook URLs
        """
        # TODO: Fetch from workspace settings/notification preferences
        # For now, return empty to avoid errors
        return {
            "emails": [],
            "webhooks": [],
        }


class EmailAlertSimulator:
    """
    Simulated email generator for testing
    Generates realistic alert emails without actual SMTP
    """
    
    @staticmethod
    def generate_sample_alert_email(alert_type: str = "phishing") -> Dict[str, str]:
        """
        Generate a sample alert email for demo purposes
        
        Args:
            alert_type: Type of alert (phishing, malware, network_anomaly, etc.)
            
        Returns:
            Dictionary with sample email content
        """
        samples = {
            "phishing": {
                "subject": "🚨 [CRITICAL] Phishing Threat Detected - Urgent Action Required",
                "entity": "secure-login-paypal-update.com",
                "description": "High-confidence phishing domain detected targeting PayPal users. Domain registered 2 hours ago with spoofed branding.",
            },
            "malware": {
                "subject": "🚨 [CRITICAL] Malware C2 Detection - Immediate Response Needed",
                "entity": "192.168.1.100",
                "description": "Network traffic detected to known malware command and control server. Multiple outbound connections to confirmed C2 infrastructure.",
            },
            "network_anomaly": {
                "subject": "⚠️ [HIGH] Network Anomaly Detected - Investigation Required",
                "entity": "10.0.0.50",
                "description": "Unusual network traffic pattern detected. System generating 1000x normal data transfer rate to external IP.",
            },
            "sql_injection": {
                "subject": "⚠️ [HIGH] SQL Injection Attack Detected - Application Alert",
                "entity": "/api/users?id=1' OR '1'='1",
                "description": "SQL injection payload detected in request parameters. Potential database compromise attempted.",
            },
        }
        
        sample = samples.get(alert_type, samples["phishing"])
        
        return {
            "type": alert_type,
            "subject": sample["subject"],
            "entity": sample["entity"],
            "description": sample["description"],
            "severity": "CRITICAL" if "CRITICAL" in sample["subject"] else "HIGH",
            "risk_score": 92 if "CRITICAL" in sample["subject"] else 75,
        }
