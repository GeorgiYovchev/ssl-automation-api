# SSL Automation API More Info

Web UI for SSL certificate management with automated deployment to HAProxy and IIS.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Kubernetes (ArgoCD App)                             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                    Flask API + Web UI                               │    │
│  │                    (Deployment + Service)                           │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ HTTP POST /api/deploy
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         GitLab CI/CD Pipeline                               │
│  prepare → validate → build_pem → deploy_haproxy → deploy_iis               │
└─────────────────────────────────────────────────────────────────────────────┘
                    │                               │
                    ▼                               ▼
          ┌─────────────────┐             ┌─────────────────┐
          │     HAProxy     │             │       IIS       │
          │   (Linux VM)    │             │   (Windows VM)  │
          │   PEM deploy    │             │  HTTP bindings  │
          └─────────────────┘             └─────────────────┘
```

## Project Structure

```
ssl-automation/
├── api/                    # Flask application
│   ├── app.py
│   ├── templates/
│   ├── Dockerfile
│   └── requirements.txt
├── k8s/                    # Kubernetes manifests (ArgoCD)
│   ├── namespace.yaml
│   ├── configmap.yaml
│   ├── secret.yaml
│   ├── deployment.yaml
│   ├── service.yaml
│   ├── ingress.yaml
│   └── kustomization.yaml
├── pipeline/               # CI/CD resources
│   ├── ansible/
│   │   ├── inventory/
│   │   └── playbooks/
│   └── scripts/
│       └── powershell/
├── certs/                  # Certificate files (gitignored)
└── .gitlab-ci.yml
```

## Setup Guide

### 1. Create GitLab Repository

```bash
git init
git remote add origin https://gitlab.oddstech.net/devops/ssl-pronet.git
git add .
git commit -m "Initial commit"
git push -u origin main
```

### 2. Configure GitLab CI/CD Variables

Go to Settings → CI/CD → Variables and add:

| Variable | Type | Protected | Masked | Description |
|----------|------|-----------|--------|-------------|
| `HAPROXY_USER` | Variable | ✓ | ✗ | SSH username for HAProxy |
| `HAPROXY_PASSWORD` | Variable | ✓ | ✓ | SSH password for HAProxy |
| `GITLAB_TOKEN` | Variable | ✓ | ✓ | Pipeline trigger token |

### 3. Build Docker Image

```bash
cd api
docker build -t registry.example.com/ssl-automation:latest .
docker push registry.example.com/ssl-automation:latest
```

### 4. Configure Kubernetes Manifests

Edit the following files before deploying to ArgoCD:

**k8s/configmap.yaml:**
```yaml
data:
  GITLAB_URL: "https://gitlab.oddstech.net"
  GITLAB_PROJECT_ID: "123"
```

**k8s/secret.yaml:**
```yaml
stringData:
  GITLAB_TOKEN: "glpat-xxxxxxxxxxxx"
  SECRET_KEY: "your-random-secret-key"
```

**k8s/deployment.yaml:**
```yaml
image: registry.example.com/ssl-automation:latest
```

**k8s/ingress.yaml:**
```yaml
host: ssl-automation.oddstech.net
```

### 5. Create ArgoCD Application

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: ssl-automation
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://gitlab.oddstech.net/deveops/ssl-pronet.git
    targetRevision: main
    path: k8s
  destination:
    server: https://kubernetes.default.svc
    namespace: ssl-automation
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
```

### 6. Access the UI

```
https://ssl-automation.oddstech.net
```

## Usage

1. Open Web UI
2. Upload `.crt` and `.key` files
3. Enter domains (comma or newline separated)
4. Click **Deploy**
5. GitLab Pipeline triggers automatically:
   - Validates certificate
   - Generates PEM for HAProxy
   - Deploys to HAProxy via Ansible
   - Configures IIS HTTP bindings via PowerShell

## Local Development

```bash
cd api
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

export GITLAB_URL=https://gitlab.oddstech.net
export GITLAB_PROJECT_ID=123
export GITLAB_TOKEN=glpat-xxx

python app.py
# Open http://localhost:5000
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Web UI |
| `/health` | GET | Health check |
| `/api/validate` | POST | Validate cert/key without deploying |
| `/api/deploy` | POST | Upload files and trigger pipeline |
| `/api/status/<id>` | GET | Get pipeline status |

## Pipeline Stages

| Stage | Description |
|-------|-------------|
| `build` | Build Docker image (on api/ changes) |
| `prepare` | Create cert files from API variables |
| `validate` | Validate certificate and key pair |
| `build_pem` | Generate PEM file for HAProxy |
| `deploy_haproxy` | Deploy to HAProxy via Ansible |
| `deploy_iis` | Configure IIS HTTP bindings |

---
---
---
---
---

# SSL Certificate Automation - User Guide

## Overview

This tool allows you to deploy SSL certificates to HAProxy and IIS servers automatically through a simple web interface.

---

## Step-by-Step Guide

### 1. Access the Application

Open your browser and go to:
```
https://autossl.oddstech.net
```

---

### 2. Upload Certificate Files

You will see a form with the following fields:

#### Certificate File (.crt)
- Click **"Choose File"** or drag and drop
- Select the `.crt` certificate file

#### Private Key File (.key)
- Click **"Choose File"** or drag and drop
- Select the `.key` private key file

#### Domains
- Enter the domains in the text area
- One domain per line, for example:
  ```
  ultraplay.example1.com
  ultraplay.example2.com
  ultraplay.example3.com
  ```

---

### 3. Validate (Optional but Recommended)

Click the **"Validate Only"** button to check:
- Certificate format is valid
- Private key format is valid
- Certificate and key match each other
- Domains are in correct format

If validation passes, you will see a green success message.

---

### 4. Deploy

Click the **"Deploy"** button to start the deployment process.

If successful, you will see:
- ✅ Success message
- 🔗 **Pipeline URL** - click this link to monitor the deployment

---

### 5. Monitor the Pipeline

Click the pipeline link to open GitLab and watch the deployment progress:

| Stage | Description |
|-------|-------------|
| **prepare** | Prepares certificate files |
| **validate** | Validates certificate and key |
| **build_pem** | Creates PEM file for HAProxy |
| **deploy** | Deploys to HAProxy and IIS (runs in parallel) |

Wait for all stages to turn **green** ✅

---

## Troubleshooting

### "Certificate and key do not match"
- Make sure you uploaded the correct `.crt` and `.key` files that belong together

### "Invalid domain format"
- Check for typos in domain names
- Domains should be like: `subdomain.domain.com`

### Pipeline fails at deploy_haproxy
- Check if HAProxy server is accessible
- Contact DevOps team

### Pipeline fails at deploy_iis
- Check if IIS server is accessible
- Contact DevOps team

---

## Important Notes

⚠️ **The PEM file name** is automatically generated from the first domain's second-level name.
- Example: `ultraplay.betper695.com` → `betper695.pem`

⚠️ **Certificate files should be in PEM format** (text files starting with `-----BEGIN`)

⚠️ **Do not close the browser** until you see the pipeline link

---

## Need Help?

Contact the DevOps team if you encounter any issues not covered in this guide.
