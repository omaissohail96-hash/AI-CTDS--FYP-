import { motion } from 'framer-motion';
import { Network, Zap, CheckCircle } from 'lucide-react';
import { NetworkScanner, PageHeader } from '../components';

const NetworkMonitorPage = () => (
  <div>
    <PageHeader
      icon={Network}
      iconColor="#FF6A3D"
      title="Network IDS"
      subtitle="Real-time traffic classifier detecting port scans, SYN floods, lateral movement, and anomalous network flows"
      badges={[
        { label: 'Real-Time IDS', variant: 'success', icon: Zap },
        { label: '92% Accuracy', variant: 'accent', icon: CheckCircle },
      ]}
    />
    <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}>
      <NetworkScanner />
    </motion.div>
  </div>
);

export default NetworkMonitorPage;
