import { motion } from 'framer-motion';

/**
 * Consistent page header used across all dashboard views.
 * Preserves layout spacing — does not alter page logic.
 */
const PageHeader = ({ icon: Icon, iconColor = '#FF6A3D', iconBg, title, subtitle, badges = [], actions }) => {
  const bg = iconBg || `linear-gradient(135deg, ${iconColor}2E, ${iconColor}14)`;
  const border = `1px solid ${iconColor}40`;

  return (
    <motion.div
      className="page-header"
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
    >
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px', marginBottom: subtitle ? '6px' : 0 }}>
          {Icon && (
            <div className="page-icon-wrap" style={{ background: bg, border }}>
              <Icon size={20} style={{ color: iconColor }} />
            </div>
          )}
          <h1 className="page-title" style={{ marginBottom: 0 }}>{title}</h1>
        </div>
        {subtitle && <p className="page-subtitle">{subtitle}</p>}
      </div>
      <div className="header-actions">
        {badges.map((b) => (
          <span key={b.label} className={`page-badge ${b.variant || 'accent'}`}>
            {b.icon && <b.icon size={12} />}
            {b.label}
          </span>
        ))}
        {actions}
      </div>
    </motion.div>
  );
};

export default PageHeader;
