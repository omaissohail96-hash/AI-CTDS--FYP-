import { EmailScanner } from '../components'

function EmailScannerPage() {
    return (
        <>
            <div className="page-header">
                <h1 className="page-title">Email Scanner</h1>
                <p className="page-subtitle">Analyze emails for phishing attempts</p>
            </div>
            <EmailScanner />
        </>
    )
}

export default EmailScannerPage
