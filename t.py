from pymongo import MongoClient

client = MongoClient("mongodb://localhost:27017/")
db = client['SKCET']

team_member = "727721epci035".upper()

query = {"TeamDetails": team_member}

# Fetch all matching documents
results = db.HackathonParticipations.find(query)

print(len(list(results)))