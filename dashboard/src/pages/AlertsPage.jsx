import React from 'react';
import { motion } from 'framer-motion';
import { AlertCircle } from 'lucide-react';
import { AlertsPanel } from '../components';
import PageHeader from '../components/PageHeader';

const AlertsPage = () => {
  return (
    <div>
      <PageHeader
        icon={AlertCircle}
        iconColor="#FF3D57"
        title="Alert Management Center"
        subtitle="Monitor, manage, and respond to security threats in real-time"
        badges={[
          { label: 'Real-Time Feed', variant: 'accent' },
          { label: 'Webhook Ready', variant: 'info' },
        ]}
      />
      <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}>
        <AlertsPanel />
      </motion.div>
    </div>
  );
};

export default AlertsPage;
