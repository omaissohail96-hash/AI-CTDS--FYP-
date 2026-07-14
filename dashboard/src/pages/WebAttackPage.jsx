import { motion } from 'framer-motion';
import { ShieldAlert, Zap, CheckCircle } from 'lucide-react';
import { WebAttackScanner, PageHeader } from '../components';

const WebAttackPage = () => (
  <div>
    <PageHeader
      icon={ShieldAlert}
      iconColor="#FF3D57"
      title="Web Attack Scanner"
      subtitle="HTTP log parser detecting XSS, SQL injection, command injection, SSRF, and path traversal attacks autonomously"
      badges={[
        { label: 'OWASP Coverage', variant: 'success', icon: Zap },
        { label: '96% Accuracy', variant: 'danger', icon: CheckCircle },
      ]}
    />
    <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}>
      <WebAttackScanner />
    </motion.div>
  </div>
);

export default WebAttackPage;
