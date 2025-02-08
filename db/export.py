import os
import json
from pymongo import MongoClient

MONGO_URI = "mongodb://localhost:27017/"
DATABASE_NAME = "SKCET"

client = MongoClient(MONGO_URI)
db = client[DATABASE_NAME]

os.makedirs("./data", exist_ok=True)

for collection_name in db.list_collection_names():
    collection = db[collection_name]
    data = list(collection.find({}))  

    for doc in data:
        doc["_id"] = str(doc["_id"])

    file_path = os.path.join("./data", f"{collection_name}.json")
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

    print(f"Exported {collection_name} to {file_path}")

print("All collections have been exported successfully.")
