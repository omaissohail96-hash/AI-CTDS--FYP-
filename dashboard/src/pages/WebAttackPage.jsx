import { WebAttackScanner } from '../components'

function WebAttackPage() {
    return (
        <>
            <div className="page-header">
                <h1 className="page-title">Web Attack Detector</h1>
                <p className="page-subtitle">Analyze websites for security threats</p>
            </div>
            <WebAttackScanner />
        </>
    )
}

export default WebAttackPage
