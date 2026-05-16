import os
from dotenv import load_dotenv
from azure.identity import DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.network import NetworkManagementClient  # NEW IMPORT

load_dotenv()

def check_azure_storage_public_access():
    print("\n🚀 Starting Azure Storage Scan...")
    results = []
    try:
        credential = DefaultAzureCredential()
        subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")
        if not subscription_id: return [{"resource": "Azure Config", "type": "Azure Storage", "status": "ERROR", "details": "Missing AZURE_SUBSCRIPTION_ID"}]

        storage_client = StorageManagementClient(credential, subscription_id)
        accounts = list(storage_client.storage_accounts.list())
        
        if not accounts:
            return [{"resource": "Azure Subscription", "type": "Azure Storage", "status": "WARNING", "details": "No Storage Accounts found."}]
            
        for account in accounts:
            if account.allow_blob_public_access:
                results.append({"resource": account.name, "type": "Azure Storage", "status": "VULNERABLE", "details": "Blob public access is ALLOWED"})
            else:
                results.append({"resource": account.name, "type": "Azure Storage", "status": "SECURE", "details": "Blob public access is BLOCKED"})
    except Exception as e:
        results.append({"resource": "Azure Service", "type": "Azure Storage", "status": "ERROR", "details": f"Connection failed: {str(e)}"})
    return results

# NEW FUNCTION: Check Azure Firewalls (NSGs)
def check_azure_nsg_open_ports():
    print("🚀 Starting Azure NSG (Firewall) Scan...")
    results = []
    try:
        credential = DefaultAzureCredential()
        subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")
        
        network_client = NetworkManagementClient(credential, subscription_id)
        nsgs = list(network_client.network_security_groups.list_all())
        
        if not nsgs:
            return [{"resource": "Azure Subscription", "type": "Azure NSG", "status": "WARNING", "details": "No Network Security Groups found."}]
            
        for nsg in nsgs:
            is_vulnerable = False
            bad_port = ""
            
            # Loop through all security rules in the firewall
            for rule in nsg.security_rules:
                if rule.access.lower() == 'allow' and rule.direction.lower() == 'inbound':
                    source = str(rule.source_address_prefix).lower()
                    # Check if it allows traffic from anywhere
                    if source in ['*', '0.0.0.0/0', 'internet']:
                        port = str(rule.destination_port_range)
                        # Check if it's a risky management port
                        if port == '22' or port == '3389' or port == '*':
                            is_vulnerable = True
                            bad_port = port
                            break
                            
            if is_vulnerable:
                results.append({"resource": nsg.name, "type": "Azure NSG", "status": "VULNERABLE", "details": f"Port {bad_port} open to internet!"})
            else:
                results.append({"resource": nsg.name, "type": "Azure NSG", "status": "SECURE", "details": "No risky open ports."})
                
    except Exception as e:
        results.append({"resource": "Azure Service", "type": "Azure NSG", "status": "ERROR", "details": f"Connection failed: {str(e)}"})
    return results

# import os
# from dotenv import load_dotenv
# from azure.identity import DefaultAzureCredential
# from azure.mgmt.storage import StorageManagementClient

# # Ensure environment variables are loaded
# load_dotenv()

# def check_azure_storage_public_access():
#     print("\n🚀 Starting Azure Storage Scan...")
#     results = []
    
#     try:
#         # DefaultAzureCredential automatically reads the AZURE_ variables from your .env file
#         credential = DefaultAzureCredential()
#         subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")
        
#         if not subscription_id:
#             return [{"resource": "Azure Config", "type": "Azure Storage", "status": "ERROR", "details": "Missing AZURE_SUBSCRIPTION_ID in .env"}]

#         # Connect to Azure
#         storage_client = StorageManagementClient(credential, subscription_id)
        
#         # Fetch all storage accounts in the subscription
#         accounts = storage_client.storage_accounts.list()
#         accounts_found = False
        
#         for account in accounts:
#             accounts_found = True
            
#             # The core security check: Is public blob access explicitly allowed?
#             if account.allow_blob_public_access:
#                 results.append({
#                     "resource": account.name,
#                     "type": "Azure Storage",
#                     "status": "VULNERABLE",
#                     "details": "Blob public access is ALLOWED"
#                 })
#             else:
#                 results.append({
#                     "resource": account.name,
#                     "type": "Azure Storage",
#                     "status": "SECURE",
#                     "details": "Blob public access is BLOCKED"
#                 })
                
#         if not accounts_found:
#             results.append({"resource": "Azure Subscription", "type": "Azure Storage", "status": "WARNING", "details": "No Storage Accounts found."})
            
#     except Exception as e:
#         results.append({"resource": "Azure Service", "type": "Azure Storage", "status": "ERROR", "details": f"Connection failed: {str(e)}"})
        
#     return results

# # For testing the file locally
# if __name__ == "__main__":
#     print(check_azure_storage_public_access())