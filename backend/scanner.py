import os
import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv

# Load credentials
load_dotenv()

def get_aws_client(service_name):
    return boto3.client(
        service_name,
        aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
        region_name=os.getenv('AWS_DEFAULT_REGION')
    )

def check_s3_public_access():
    s3_client = get_aws_client('s3')
    results = [] # We will store our findings here
    
    try:
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])
        
        for bucket in buckets:
            bucket_name = bucket['Name']
            try:
                pab = s3_client.get_public_access_block(Bucket=bucket_name)
                config = pab['PublicAccessBlockConfiguration']
                
                if not (config.get('BlockPublicAcls') and config.get('IgnorePublicAcls') and 
                        config.get('BlockPublicPolicy') and config.get('RestrictPublicBuckets')):
                    results.append({"resource": bucket_name, "type": "S3", "status": "VULNERABLE", "details": "Public access allowed"})
                else:
                    results.append({"resource": bucket_name, "type": "S3", "status": "SECURE", "details": "Public access blocked"})

            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                    results.append({"resource": bucket_name, "type": "S3", "status": "WARNING", "details": "No public access block configured"})
                else:
                    results.append({"resource": bucket_name, "type": "S3", "status": "ERROR", "details": str(e)})
                    
    except Exception as e:
        results.append({"resource": "S3 Service", "type": "S3", "status": "ERROR", "details": str(e)})
        
    return results

def check_ec2_security_groups():
    ec2_client = get_aws_client('ec2')
    results = []
    
    try:
        response = ec2_client.describe_security_groups()
        for sg in response.get('SecurityGroups', []):
            sg_name = sg['GroupName']
            sg_id = sg['GroupId']
            is_vulnerable = False
            
            for rule in sg.get('IpPermissions', []):
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        from_port = rule.get('FromPort', -1)
                        if from_port in [22, 3389] or from_port == -1:
                            results.append({"resource": f"{sg_name} ({sg_id})", "type": "EC2 SG", "status": "VULNERABLE", "details": f"Port {from_port} open to internet"})
                            is_vulnerable = True
                            
            if not is_vulnerable:
                results.append({"resource": f"{sg_name} ({sg_id})", "type": "EC2 SG", "status": "SECURE", "details": "No risky open ports"})
                
    except Exception as e:
        results.append({"resource": "EC2 Service", "type": "EC2 SG", "status": "ERROR", "details": str(e)})
        
    return results

def check_iam_mfa():
    print("\n🚀 Starting IAM MFA Scan...")
    iam_client = get_aws_client('iam')
    results = []
    
    try:
        # Fetch all IAM users in the account
        response = iam_client.list_users()
        users = response.get('Users', [])
        
        if not users:
            results.append({"resource": "Account", "type": "IAM", "status": "WARNING", "details": "No IAM users found."})
            return results

        for user in users:
            username = user['UserName']
            try:
                # Check if this specific user has an MFA device attached
                mfa_response = iam_client.list_mfa_devices(UserName=username)
                mfa_devices = mfa_response.get('MFADevices', [])
                
                if not mfa_devices:
                    results.append({"resource": username, "type": "IAM User", "status": "VULNERABLE", "details": "MFA is NOT enabled"})
                else:
                    results.append({"resource": username, "type": "IAM User", "status": "SECURE", "details": "MFA is enabled"})
                    
            except Exception as e:
                results.append({"resource": username, "type": "IAM User", "status": "ERROR", "details": str(e)})
                
    except Exception as e:
        results.append({"resource": "IAM Service", "type": "IAM", "status": "ERROR", "details": str(e)})
        
    return results



def check_ec2_imds():
    print("\n🚀 Starting EC2 Instance (IMDSv2) Scan...")
    ec2_client = get_aws_client('ec2')
    results = []
    
    try:
        # Fetch all EC2 instances
        response = ec2_client.describe_instances()
        instances_found = False
        
        for reservation in response.get('Reservations', []):
            for instance in reservation.get('Instances', []):
                instances_found = True
                instance_id = instance['InstanceId']
                
                # Try to get a friendly name from the AWS Tags, fallback to the ID
                instance_name = instance_id
                for tag in instance.get('Tags', []):
                    if tag['Key'] == 'Name':
                        instance_name = f"{tag['Value']} ({instance_id})"
                        break
                
                # The core security check: Is IMDSv2 strictly required?
                metadata_options = instance.get('MetadataOptions', {})
                http_tokens = metadata_options.get('HttpTokens', 'optional')
                
                if http_tokens == 'optional':
                    results.append({"resource": instance_name, "type": "EC2 Instance", "status": "VULNERABLE", "details": "IMDSv2 NOT enforced (SSRF risk)"})
                else:
                    results.append({"resource": instance_name, "type": "EC2 Instance", "status": "SECURE", "details": "IMDSv2 is enforced"})
                    
        if not instances_found:
            results.append({"resource": "Region", "type": "EC2 Instance", "status": "WARNING", "details": "No EC2 instances running."})
            
    except Exception as e:
        results.append({"resource": "EC2 Service", "type": "EC2 Instance", "status": "ERROR", "details": str(e)})
        
    return results

# A master function to run everything and compile the data

def run_all_scans():
    return {
        "s3_results": check_s3_public_access(),
        "ec2_results": check_ec2_security_groups(),
        "iam_results": check_iam_mfa(),
        "ec2_imds_results": check_ec2_imds()  
    }