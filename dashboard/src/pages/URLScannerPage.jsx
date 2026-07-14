import { motion } from 'framer-motion';
import { Globe, Zap, CheckCircle } from 'lucide-react';
import { URLScanner, PageHeader } from '../components';

const URLScannerPage = () => (
  <div>
    <PageHeader
      icon={Globe}
      iconColor="#5AA9FF"
      title="URL Scanner"
      subtitle="AI-powered phishing & malicious URL detection using Random Forest classifiers trained on 500k+ indicators"
      badges={[
        { label: '<15ms Inference', variant: 'success', icon: Zap },
        { label: '94% Accuracy', variant: 'info', icon: CheckCircle },
      ]}
    />
    <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}>
      <URLScanner />
    </motion.div>
  </div>
);

export default URLScannerPage;
