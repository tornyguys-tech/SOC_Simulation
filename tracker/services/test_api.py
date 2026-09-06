import requests

import os
API_KEY = "xg3To2I8jAzWTfzP"

FACTION_ID = 54815

url = (
    f"https://api.torn.com/faction/{FACTION_ID}"
    f"?selections=basic"
    f"&key={API_KEY}"
)

response = requests.get(url)

print(response.status_code)
print(response.json())