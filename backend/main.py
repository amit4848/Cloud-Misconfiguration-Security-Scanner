from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from scanner import run_all_scans
from iac_scanner import scan_terraform_file
# from database import save_scan_result  # Import our new DB function
from database import save_scan_result, get_scan_history
# from scanner_azure import check_azure_storage_public_access
from scanner_azure import check_azure_storage_public_access, check_azure_nsg_open_ports

app = FastAPI(title="Cloud Security Scanner API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return {"message": "Cloud Security API is running! 🚀"}


@app.get("/api/scan")
def trigger_scan():
    data = run_all_scans()
    
    data["azure_storage_results"] = check_azure_storage_public_access()
    # NEW: Run the Azure NSG Scan
    data["azure_nsg_results"] = check_azure_nsg_open_ports()
    
    save_scan_result(data)
    return {"status": "success", "data": data}

# @app.get("/api/scan")
# def trigger_scan():
#     # 1. Run the AWS scans
#     data = run_all_scans()
    
#     # 2. Run the Azure scans and append them to the data dictionary
#     data["azure_storage_results"] = check_azure_storage_public_access()
    
#     # 3. Save the results to MongoDB
#     save_scan_result(data)
    
#     # 4. Return the data to the Next.js frontend
#     return {"status": "success", "data": data}

@app.get("/api/history")
def fetch_history():
    history_data = get_scan_history()
    return {"status": "success", "data": history_data}

@app.get("/api/scan-iac")
def trigger_iac_scan():
    # Point it to your test file
    target_file = "../terraform_tests/vulnerable_s3.tf"
    
    # Run the scan
    iac_results = scan_terraform_file(target_file)
    
    return {"status": "success", "data": {"iac_results": iac_results}}