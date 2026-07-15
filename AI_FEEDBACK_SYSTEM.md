# AI Feedback & Continuous Learning

CyberGuard uses human-in-the-loop feedback, not online reinforcement learning. Every scan remains an inference-only operation. Analysts submit a verdict review; a super administrator may approve it. Only approved records are appended to `datasets/feedback_dataset.csv` for later offline training.

## Workflow

1. A security analyst submits `correct`, `false_positive`, `false_negative`, or `wrong_category` feedback for a scan in their workspace.
2. A workspace administrator may reject invalid feedback. A super administrator approves valid feedback.
3. Approval records an audit event and exports the immutable review record. Rejected and pending feedback never enter the dataset.
4. An administrator runs `python train_with_feedback.py --original-dataset <web.csv>` outside the API process. It creates a timestamped model, vectorizer, and `metadata.json` in `models/versions/`.
5. Publishing remains a deliberate deployment action after metric review; the API never retrains or loads a new model automatically.

## API

- `POST /api/v1/feedback` — analyst feedback for a workspace-owned scan.
- `GET /api/v1/feedback?status=&search=` — workspace-isolated review records.
- `GET /api/v1/feedback/stats` — dashboard counts and feedback by detector.
- `PUT /api/v1/feedback/{id}/approve` — super admin approval and CSV export.
- `PUT /api/v1/feedback/{id}/reject` — workspace/super admin rejection.
- `DELETE /api/v1/feedback/{id}` — removes pending/rejected feedback only.

The `ai_feedback` table stores the source scan, prediction, corrected label, reviewer state and approval provenance. Every mutation writes an `audit_logs` record. Approved entries are immutable so retraining data remains traceable.

## Model metadata

Each offline retrain writes `model_version`, training date, merged dataset size, feedback sample count, and accuracy/precision/recall/F1. Current retraining supports web-payload data (`payload,label`) because that is the compatible text model dataset; other detectors require their own feature-compatible training pipelines.
