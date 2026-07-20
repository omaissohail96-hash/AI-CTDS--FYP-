import { AlertTriangle, Clock3 } from 'lucide-react'

const formatResetTime = (resetAt) => {
  if (!resetAt) return null
  const date = new Date(resetAt)
  return Number.isNaN(date.getTime())
    ? null
    : date.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })
}

export const getScanError = (error) => {
  const detail = error.response?.data?.detail
  if (error.response?.status === 429 && detail && typeof detail === 'object') {
    return detail
  }
  if (error.response?.status === 401) {
    return { code: 'session_expired', message: 'Your session has expired. Please sign in again.' }
  }
  return { code: 'scan_failed', message: 'The scan could not be completed. Please try again.' }
}

const ScanLimitNotice = ({ error }) => {
  if (!error) return null

  const isQuota = error.code === 'monthly_quota_exhausted'
  const isRateLimit = error.code === 'rate_limit_exceeded' || error.code === 'ip_rate_limit_exceeded'
  const resetTime = formatResetTime(error.reset_at)
  const retryText = error.retry_after_seconds
    ? `Try again in ${error.retry_after_seconds} second${error.retry_after_seconds === 1 ? '' : 's'}.`
    : null

  return (
    <div className="scan-limit-notice" role="alert">
      {isQuota || !isRateLimit ? <AlertTriangle size={19} /> : <Clock3 size={19} />}
      <div>
        <strong>{isQuota ? 'You are out of scans for this month' : isRateLimit ? 'Scanning is temporarily limited' : 'Scan could not be completed'}</strong>
        <p>{error.message}</p>
        {typeof error.usage === 'number' && typeof error.limit === 'number' && (
          <p>{error.usage} of {error.limit} scans used.</p>
        )}
        {(resetTime || retryText) && <p>{retryText} {resetTime ? `Limit resets ${resetTime}.` : ''}</p>}
      </div>
    </div>
  )
}

export default ScanLimitNotice
