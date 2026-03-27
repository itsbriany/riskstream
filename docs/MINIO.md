# MinIO Integration

RiskStream uses MinIO for S3-compatible object storage across all environments.

## Architecture

- **Local-dev**: MinIO deployed in `local-dev` namespace
- **Staging**: MinIO deployed in `staging` namespace  
- **Production**: MinIO deployed in `production` namespace

Each environment has its own MinIO instance with isolated storage.

## Automatic Bucket Initialization

Buckets are automatically created via a Kubernetes Job that runs after MinIO deployment:

### Default Buckets
- `threat-indicators` - Processed threat indicators
- `raw-feeds` - Raw data from threat feeds
- `processed-data` - Analyzed and enriched data
- `archives` - Historical data archives

### Current Raw Feed Prefixes
- `threatfox/recent/` - ThreatFox recent IOC snapshots
- `cisa-kev/catalog/` - CISA KEV catalog snapshots
- `urlhaus/checkpoints/` - URLhaus daily raw checkpoints
- `urlhaus/deltas/` - URLhaus immutable change sets between polls
- `urlhaus/state/` - URLhaus mutable latest-state working object

### Current Processed Data Prefixes
- `normalized/threat-signals/threat_signal.v1/threatfox/recent/` - ThreatFox normalized JSONL batches
- `normalized/threat-signals/threat_signal.v1/cisa-kev/catalog/` - CISA KEV normalized JSONL batches
- `normalized/threat-signals/threat_signal.v1/urlhaus/recent/checkpoints/` - URLhaus checkpoint normalization output
- `normalized/threat-signals/threat_signal.v1/urlhaus/recent/deltas/` - URLhaus delta normalization output
- `normalization-state/threat-signal/threat_signal.v1/` - Threat-signal normalizer checkpoint state by raw bucket, source, and stream

### Current Archive Prefixes
- `urlhaus/checkpoints/` - Archived URLhaus daily checkpoints
- `urlhaus/deltas/` - Archived URLhaus deltas

These prefixes are created on first write. The MinIO init job creates buckets only, not object-prefix placeholders.

### How It Works

#### Local Development
When you run `./scripts/build-and-deploy-local.sh`, the script:
1. Deploys MinIO and the init job
2. Waits for MinIO to be ready
3. Waits for the init job to complete
4. Buckets are ready to use!

#### Staging & Production (ArgoCD)
The init job includes ArgoCD PostSync hook annotations:
```yaml
annotations:
  argocd.argoproj.io/hook: PostSync
  argocd.argoproj.io/hook-delete-policy: HookSucceeded
```

When ArgoCD syncs the application:
1. Deploys all resources (MinIO, services, etc.)
2. Waits for sync to complete
3. **Automatically runs the init job** (PostSync hook)
4. Creates buckets if they don't exist
5. Deletes the job after success (HookSucceeded policy)

This is fully automated - no manual intervention needed!

## Configuration

### Storage Size by Environment
- **local-dev**: 5Gi
- **staging**: 20Gi  
- **production**: 50Gi

### Credentials

Credentials are stored in Kubernetes Secrets:

```yaml
# k8s/base/minio-deployment.yaml
apiVersion: v1
kind: Secret
metadata:
  name: minio-secret
type: Opaque
stringData:
  root-user: minioadmin
  root-password: minioadmin
```

**⚠️ Important**: Override credentials in staging/production overlays for security!

Staging and production overlays include their own secret patches:
- `k8s/overlays/staging/minio-patch.yaml`
- `k8s/overlays/production/minio-patch.yaml`

## Accessing MinIO

### Local Development
```bash
# Port forward MinIO console
./scripts/port-forward-minio.sh local-dev

# Open browser to http://localhost:9001
# Login: minioadmin/minioadmin
```

### Staging/Production
```bash
# Port forward from staging
./scripts/port-forward-minio.sh staging

# Port forward from production
./scripts/port-forward-minio.sh production
```

## Using MinIO in Services

Services can access MinIO using environment variables:

```yaml
env:
  - name: S3_ENDPOINT
    value: "minio:9000"
  - name: S3_ACCESS_KEY
    valueFrom:
      secretKeyRef:
        name: minio-secret
        key: root-user
  - name: S3_SECRET_KEY
    valueFrom:
      secretKeyRef:
        name: minio-secret
        key: root-password
  - name: S3_USE_SSL
    value: "false"
```

### Python Usage

Use the shared storage utility:

```python
from riskstream.shared.utils.storage import StorageClient

# Client automatically reads from environment variables
client = StorageClient()

# Upload a file
minio_client = client.get_client()
minio_client.fput_object(
    "threat-indicators",
    "indicator-123.json",
    "/path/to/file.json"
)
```

## Troubleshooting

### Check MinIO pods
```bash
kubectl get pods -n local-dev -l app=minio
```

### Check init job status
```bash
kubectl get jobs -n local-dev -l app=minio-init
kubectl logs -n local-dev job/minio-init
```

### Manually verify buckets

**Note**: MinIO client (`mc`) is optional for troubleshooting. It's not required for normal operations since bucket initialization happens automatically via Kubernetes Jobs using the `minio/mc` container image.

To install `mc` locally (optional):
```bash
# macOS
brew install minio/stable/mc

# Linux
wget https://dl.min.io/client/mc/release/linux-amd64/mc
chmod +x mc
sudo mv mc /usr/local/bin/
```

Once installed:
```bash
# Port forward MinIO
./scripts/port-forward-minio.sh local-dev

# Configure mc and list buckets
mc alias set local http://localhost:9000 minioadmin minioadmin
mc ls local
```

### Re-run initialization
If buckets weren't created, delete and recreate the job:

```bash
kubectl delete job -n local-dev minio-init
kubectl apply -k k8s/overlays/local-dev -n local-dev
```

## Migration to AWS S3

To migrate from MinIO to AWS S3:

1. Update service environment variables to point to S3
2. The storage utility is already S3-compatible - no code changes needed!
3. Use Terraform/CloudFormation to create S3 buckets
4. Update credentials to use AWS access keys

```yaml
env:
  - name: S3_ENDPOINT
    value: "s3.amazonaws.com"
  - name: S3_USE_SSL
    value: "true"
  - name: S3_REGION
    value: "us-east-1"
```
