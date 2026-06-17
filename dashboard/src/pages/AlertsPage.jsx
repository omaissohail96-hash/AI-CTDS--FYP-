import React from 'react';
import { AlertsPanel } from '../components';
import './AlertsPage.css';

/**
 * Alerts Management Page
 * Full-featured alert management interface
 */
const AlertsPage = () => {
  return (
    <div className="alerts-page">
      <div className="page-header">
        <h1>Alert Management Center</h1>
        <p>Monitor, manage, and respond to security threats in real-time</p>
      </div>

      <AlertsPanel />
    </div>
  );
};

export default AlertsPage;
