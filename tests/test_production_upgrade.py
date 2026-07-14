import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.main import app
from src.core.config import settings
from src.services.threat_explanation_service import ThreatExplanationService
from src.services.email_notification_service import EmailNotificationService


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_health_endpoint(client):
    response = client.get('/health')
    assert response.status_code == 200


def test_version_endpoint(client):
    response = client.get('/api/v1/version')
    assert response.status_code == 200
    assert response.json()['version'] == 'v1'


def test_threat_explanation_service():
    payload = {
        'entity': 'https://phish.example.com',
        'score': 92,
    }
    explanation = ThreatExplanationService.generate(
        'url',
        payload,
        {
            'agent_verdict': {
                'score': 92,
                'label': 'HIGH',
                'contributions': {'ml': 40, 'threat_intel': 20},
                'raw_pillar_scores': {'ml': 40, 'threat_intel': 20},
            },
            'entities': ['https://phish.example.com'],
            'vector_details': [{'confidence': 95, 'attack_type': 'PHISHING URL'}],
            'intelligence': {'threat_intel': {'source': 'blacklist', 'threat_type': 'phishing', 'risk_level': 'high'}, 'correlation': None, 'user_behavior': None},
        },
        mitre_mappings=[{'technique_id': 'T1566', 'technique': 'Phishing'}],
    )
    assert explanation['risk_score'] == 92
    assert 'headline' in explanation
    assert explanation['recommended_action']


def test_email_notification_template():
    html = EmailNotificationService.build_html_template('Critical Alert', 'A phishing domain was detected')
    assert 'CyberGuard AI' in html
    assert 'Critical Alert' in html


def test_settings_database_url_defaults():
    assert settings.DATABASE_URL
