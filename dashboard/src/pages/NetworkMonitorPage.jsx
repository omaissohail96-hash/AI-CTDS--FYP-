import { NetworkScanner } from '../components'

function NetworkMonitorPage() {
    return (
        <>
            <div className="page-header">
                <h1 className="page-title">Network Monitor</h1>
                <p className="page-subtitle">Detect network intrusions and anomalies</p>
            </div>
            <NetworkScanner />
        </>
    )
}

export default NetworkMonitorPage
