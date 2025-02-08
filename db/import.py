import os
import json
from pymongo import MongoClient

# MongoDB connection details
MONGO_URI = "mongodb://localhost:27017/"
DATABASE_NAME = "SKCET"
IMPORT_DIR = "./data"

# Connect to MongoDB
client = MongoClient(MONGO_URI)
db = client[DATABASE_NAME]

# Loop through JSON files in the import directory
for filename in os.listdir(IMPORT_DIR):
    if filename.endswith(".json"):
        collection_name = filename.replace(".json", "")  # Extract collection name
        file_path = os.path.join(IMPORT_DIR, filename)

        # Read JSON file
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Convert "_id" back to ObjectId if needed
        for doc in data:
            if "_id" in doc:
                from bson import ObjectId
                try:
                    doc["_id"] = ObjectId(doc["_id"])  # Convert back to ObjectId
                except:
                    pass  # If conversion fails, keep as string

        # Insert data into MongoDB
        if data:
            db[collection_name].insert_many(data)
            print(f"Imported {len(data)} documents into {collection_name}")

print("All collections have been imported successfully.")
