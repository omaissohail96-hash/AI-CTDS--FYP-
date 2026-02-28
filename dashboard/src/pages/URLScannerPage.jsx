import { URLScanner } from '../components'

function URLScannerPage() {
    return (
        <>
            <div className="page-header">
                <h1 className="page-title">URL Scanner</h1>
                <p className="page-subtitle">Detect phishing and malicious URLs using ML</p>
            </div>
            <URLScanner />
        </>
    )
}

export default URLScannerPage
