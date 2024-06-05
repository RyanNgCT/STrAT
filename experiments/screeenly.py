from APIGetter import getSpecificAPIKey
import requests, json, base64, sys
from PIL import Image
from io import BytesIO

def useAPI(urlToSS: str):
    base_api_uri = "https://secure.screeenly.com/api/v1/fullsize"

    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
    }
    params = {
        'key': getSpecificAPIKey(4),
        'url': urlToSS
    }

    raw_response = requests.post(base_api_uri, headers=headers, data=params)
    if raw_response.status_code == 200:
        response = json.loads(raw_response.text)
    elif raw_response.status_code == 401:
        sys.exit("Check your API key!")
    else:
        sys.exit("An error occurred!")

    try:
        raw_image_bytes = response['base64']
    except Exception as e:
        sys.exit(f"An error occurred: {type(e)}, {str(e.args)}")

    # don't ask why need to decode twice lol...
    image_data = base64.b64decode(raw_image_bytes.split(',')[1])
    image_data = base64.b64decode(image_data)

    image = Image.open(BytesIO(image_data))
    image = image.convert('RGB')
    image.save("output.jpg")

    return 0

useAPI('https://www.nus.edu.sg')