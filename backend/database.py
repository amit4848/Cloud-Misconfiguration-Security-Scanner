import os
from pymongo import MongoClient
from dotenv import load_dotenv
from datetime import datetime

# Load environment variables
load_dotenv()

# Connect to MongoDB
MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI)

# Create/Connect to the database and collection
db = client["CloudSecurityDB"]
collection = db["scan_history"]

def save_scan_result(scan_data):
    """
    Takes the JSON scan results, adds a timestamp, and saves it to MongoDB.
    """
    try:
        # Create a document record
        record = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "results": scan_data
        }
        
        # Insert into MongoDB
        inserted_id = collection.insert_one(record).inserted_id
        print(f"💾 Scan saved to database! ID: {inserted_id}")
        
        return True
    except Exception as e:
        print(f"❌ Database error: {e}")
        return False
    
def get_scan_history(limit=5):
    """
    Fetches the most recent scans from MongoDB.
    """
    try:
        # Find the documents, exclude the internal '_id' (since it doesn't translate to JSON well),
        # sort by timestamp descending (-1), and limit to the last 5 scans.
        scans = list(collection.find({}, {"_id": 0}).sort("timestamp", -1).limit(limit))
        return scans
    except Exception as e:
        print(f"❌ Error fetching history: {e}")
        return []