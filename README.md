# 4160-5160-Group-1-Project
**Overview**
This project is a FastAPI application that demonstrates a simple version of a Cloud Security Posture Management (CSPM) tool. It detects common AWS misconfigurations, prioritizes them based on severity and impact, and uses a language model to suggest Infrastructure-as-Code (IaC) fixes.

The app can run in two modes:
1. Mock mode (default): Uses sample data so it runs even without AWS credentials.
2. AWS mode: Uses boto3 to check a real AWS account for issues when the environment variable USE_BOTO=1 is set.

Features
Scans for issues like public S3 buckets, admin IAM roles, and open SSH ports.
Prioritizes findings using a simple scoring formula.
Generates suggested Terraform or JSON fixes with help from an LLM.
Automatically provides safe fallback suggestions if the model or API key is missing.
Includes clear Swagger documentation for testing each API route.

Project Structure
project-folder/
app_boto.py        Main FastAPI app and API routes
collectors.py       AWS collectors using boto3
main.tf             Example Terraform seed file (optional for demo)
requirements.txt    Python dependencies (optional if installing manually)
README.txt          This file

Setup
1. Create a Virtual Environment
python -m venv .venv
.venv\Scripts\activate

2. Install Dependencies
pip install fastapi uvicorn pydantic openai boto3 python-dotenv

3. (Optional) Add Your OpenAI Key
setx OPENAI_API_KEY "your_openai_key_here"

Without this key, the app still works by returning safe fallback patches.

4. (Optional) Enable AWS Collectors
setx USE_BOTO 1

Make sure your AWS CLI credentials are configured first.

Running the App
From the project directory, run:
uvicorn app_boto:app --reload --port 8000

You should see something like:
Uvicorn running on http://127.0.0.1:8000

Open a browser and visit http://127.0.0.1:8000/docs to use Swagger UI.

API Endpoints
Endpoint              Description                                      Example
POST /scan            Scans for misconfigurations (mock or AWS)        { "account_id": "demo-account" }
POST /prioritize      Assigns scores to findings                      Input: output of /scan
POST /fix             Suggests IaC changes using the LLM              Input: output of /prioritize

Example Workflow
1. Run /scan
   Returns detected issues, for example a public S3 bucket or an open SSH port.

2. Run /prioritize
   Calculates scores so teams can focus on the most important issues first.

3. Run /fix
   Suggests Terraform or JSON patches that could fix those problems.
   If there is no API key, the app returns safe fallback recommendations.

Notes for Testing
Swagger UI at /docs makes testing simple without writing code.
The project works even without AWS or OpenAI setup.
The LLM output is guarded by filters that prevent unsafe patches (like making a bucket public).

Future Improvements
Add parsing for uploaded Terraform files to scan user-provided configurations.
Include multi-cloud support for Azure and GCP.
Add a small front-end dashboard for visualizing risk scores.
