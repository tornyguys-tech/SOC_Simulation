import requests
import os


API_KEY = "xg3To2I8jAzWTfzP"


def get_faction_data(faction_id, api_key=None):
    if not api_key:
        api_key = API_KEY

    url = (
        f"https://api.torn.com/faction/{faction_id}"
        f"?selections=basic"
        f"&key={api_key}"
    )

    response = requests.get(url)

    return response.json()