# 🛡️ Multi-Cloud DevSecOps Auditor (CSPM)

> **A lightweight Cloud Security Posture Management (CSPM) tool designed to detect, visualize, and prevent cloud infrastructure misconfigurations across multi-cloud environments and IaC pipelines.**

---

## 📖 Project Overview

Developed in alignment with the **Cyber Security Innovation Challenge 1.0**, this project addresses the critical threat of cloud misconfigurations. It provides early identification of risky exposures by auditing live cloud environments (AWS, Azure) and implementing "Shift-Left" security by parsing Infrastructure as Code (Terraform) before deployment.

### 🎯 Key Objectives Achieved
* **Rules Engine:** Built a modular rules engine aligned with CIS benchmarks for cloud configuration checks.
* **Shift-Left Integration:** Automated detection of vulnerabilities in `.tf` files to prevent insecure deployments.
* **Multi-Cloud Scalability:** Extensible backend architecture natively scanning both Amazon Web Services and Microsoft Azure simultaneously.
* **Compliance Dashboard:** Real-time Next.js visualization of security findings and historical audit logging.

---

## 🏗️ System Architecture

The application is built on a decoupled, modular DevSecOps architecture:

1. **Frontend (Next.js & Tailwind CSS):** A responsive, state-driven dashboard that triggers on-demand scans and displays real-time compliance metrics.
2. **Backend Engine (FastAPI & Python):** A high-performance, asynchronous REST API orchestrating independent scanning modules.
3. **Live Cloud Integration:** Authenticated SDK connections (`boto3`, `azure-identity`) to query live infrastructure state without modifying resources.
4. **Local IaC Parser:** Utilizes `python-hcl2` to translate HCL (HashiCorp Configuration Language) into queryable Python dictionaries for pre-deployment analysis.
5. **Persistence Layer (MongoDB):** Maintains a historical ledger of all security audits for compliance tracking.

---

## 🚀 Core Features & Capabilities

### 1. Shift-Left: Infrastructure as Code (IaC) Scanning
* **Terraform Parser:** Analyzes raw `.tf` files locally to catch explicitly enabled public access blocks before they reach the cloud.

### 2. Live Environment Scanning: AWS
* **S3 Buckets:** Detects globally accessible storage endpoints.
* **EC2 Security Groups:** Audits firewall rules for risky open ports (e.g., 0.0.0.0/0 on port 22).
* **IAM Users:** Identifies privileged users operating without Multi-Factor Authentication (MFA).
* **EC2 Instances:** Verifies the enforcement of IMDSv2 to prevent SSRF credential theft.

### 3. Live Environment Scanning: Microsoft Azure
* **Storage Accounts:** Audits Azure blob storage to ensure `allow_blob_public_access` is strictly disabled.
* **Network Security Groups (NSGs):** Audits inbound firewall rules to prevent administrative ports (SSH/RDP) from being exposed to the public internet.

---

## 💻 Tech Stack

* **Frontend:** React, Next.js, Tailwind CSS, TypeScript
* **Backend:** Python 3.x, FastAPI, Uvicorn
* **Database:** MongoDB
* **Cloud SDKs & Parsers:** `boto3` (AWS), `azure-mgmt-storage`, `azure-mgmt-network`, `azure-identity` (Microsoft Azure), `python-hcl2` (Terraform)

---

## ⚙️ Local Installation & Setup
*(See repository documentation for detailed `.env` setup instructions for AWS and Azure credentials).*

### Prerequisites
* Python 3.9+
* Node.js v18+
* MongoDB running locally (port 27017)
* Active AWS and Azure Cloud Credentials

### Backend Setup
```bash
cd backend
python -m venv venv
venv\Scripts\activate on Windows
pip install -r requirements.txt

Create a .env file in the backend directory:
# AWS Credentials
AWS_ACCESS_KEY_ID=your_aws_access_key
AWS_SECRET_ACCESS_KEY=your_aws_secret_key
AWS_DEFAULT_REGION=ap-south-1

# Azure Credentials
AZURE_TENANT_ID=your_tenant_id
AZURE_CLIENT_ID=your_client_id
AZURE_CLIENT_SECRET=your_client_secret_value
AZURE_SUBSCRIPTION_ID=your_subscription_id

# Database
MONGO_URI=mongodb://localhost:27017/

Start the API:

uvicorn main:app --reload

Frontend Setup

cd frontend
npm install
npm run dev

Navigate to http://localhost:3000 to view the dashboard.

🗺️ Future Roadmap (Phase 2)
To continue evolving this tool into a comprehensive, enterprise-ready CSPM, the following modules are slated for future development:

Google Cloud Platform (GCP) Integration: Expand the rules engine to audit GCP Cloud Storage buckets using the google-cloud-storage SDK and Service Account JSON authentication.

Advanced Azure Identity Checks: Implement the msgraph-sdk-python library to integrate with Microsoft Entra ID (formerly Azure AD) for auditing Azure user Multi-Factor Authentication (MFA) compliance.

CI/CD Pipeline Hooks: Package the local IaC scanner into a GitHub Action / GitLab CI pipeline step to automatically fail pull requests containing vulnerable infrastructure code.
