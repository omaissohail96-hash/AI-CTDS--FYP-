import { motion } from 'framer-motion';
import { Mail, Zap, CheckCircle } from 'lucide-react';
import { EmailScanner, PageHeader } from '../components';

const EmailScannerPage = () => (
  <div>
    <PageHeader
      icon={Mail}
      iconColor="#FF8C42"
      title="Email Scanner"
      subtitle="LSTM-powered NLP pipeline detecting phishing, BEC, and spam at the SMTP layer with explainable AI"
      badges={[
        { label: 'LSTM Model', variant: 'success', icon: Zap },
        { label: '91% Accuracy', variant: 'warning', icon: CheckCircle },
      ]}
    />
    <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}>
      <EmailScanner />
    </motion.div>
  </div>
);

export default EmailScannerPage;
