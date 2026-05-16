import hcl2
import os

def scan_terraform_file(filepath):
    results = []
    
    if not os.path.exists(filepath):
        return [{"resource": filepath, "type": "Terraform", "status": "ERROR", "details": "File not found"}]

    try:
        with open(filepath, 'r') as file:
            tf_data = hcl2.load(file)

        resources = tf_data.get('resource', [])
        
        for resource_block in resources:
            for resource_type, resource_contents in resource_block.items():
                # Clean the rogue quotes
                clean_type = resource_type.strip(' "\'') 
                
                if clean_type == 'aws_s3_bucket_public_access_block':
                    for block_name, config in resource_contents.items():
                        
                        acls = str(config.get('block_public_acls', 'true')).lower()
                        ignore = str(config.get('ignore_public_acls', 'true')).lower()
                        policy = str(config.get('block_public_policy', 'true')).lower()
                        restrict = str(config.get('restrict_public_buckets', 'true')).lower()

                        if 'false' in acls or 'false' in ignore or 'false' in policy or 'false' in restrict:
                            results.append({
                                "resource": f"{clean_type}.{block_name}", 
                                "type": "IaC (Terraform)", 
                                "status": "VULNERABLE", 
                                "details": "Public access explicitly allowed in code!"
                            })
                        else:
                            results.append({
                                "resource": f"{clean_type}.{block_name}", 
                                "type": "IaC (Terraform)", 
                                "status": "SECURE", 
                                "details": "Public access blocked securely."
                            })
                            
        # If we scanned it but found no S3 blocks at all
        if not results:
             results.append({"resource": filepath, "type": "IaC (Terraform)", "status": "SECURE", "details": "No vulnerable configurations found."})

    except Exception as e:
        results.append({"resource": filepath, "type": "IaC (Terraform)", "status": "ERROR", "details": f"Parse error: {str(e)}"})
        
    return results