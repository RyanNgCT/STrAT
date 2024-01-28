from ipData_API import getSpecificAPIKey
import requests, re, json, pprint


def useAPI(method : str, queryIP : str = None):

    # globals
    base_uri = "https://sicehice.com/api"
    info_uri = "https://iplocation.sicehice.com"


    ipv4_pattern = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')
    if method.upper() == "SEARCH" and re.match(ipv4_pattern, queryIP):
        params = { 'apikey' : getSpecificAPIKey(3), 'query' : queryIP }
        uri = f'{base_uri}/getip'
        try:
            resp = requests.post(uri, headers=params)
            return resp.text
        except:
            return "Error retrieving IP Information!"
    
    elif method.upper() == "QUOTA":
        params = { 'apikey' : getSpecificAPIKey(3)}
        uri = f'{base_uri}/searchquota'
        try:
            resp = requests.post(uri, headers=params)
            return resp.text
        except:
            return "Error retrieving usage quota info!"
    
    elif method.upper() == "GETOWNINFO":
        resp = requests.get(info_uri)
        json_out = json.dumps(resp.text, sort_keys=True)
        return json_out.strip('\\')
    
    elif method.upper() == "GETIPINFO":
        uri = f'{info_uri}/api'
        params = { 'apikey' : getSpecificAPIKey(3), 'ip' : queryIP}
        resp = requests.get(uri, headers=params)
        return resp.text



def handleIPv4():
    pass

print(useAPI("GETIPINFO", "8.8.4.4"))
