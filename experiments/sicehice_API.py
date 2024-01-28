from ipData_API import getSpecificAPIKey
import requests, re, json, sys


def useAPI(method : str, orgIP : str = None):
    # globals
    base_uri = "https://sicehice.com/api"
    info_uri = "https://iplocation.sicehice.com"

    if orgIP:
        queryIP = handleIPv4(orgIP)
        if (not queryIP) and (orgIP.lower() != "localhost"):
            sys.exit("Enter a valid IPv4 address!")

    if method.upper() == "SEARCH":
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
    
    elif method.upper() == "GETOWNINFO" or (method.upper() == "GETIPINFO" and orgIP.lower() == "localhost"):
        resp = requests.get(info_uri)
        json_out = json.dumps(resp.text, sort_keys=True)
        return json_out.strip('\\')
    
    elif method.upper() == "GETIPINFO":
        uri = f'{info_uri}/api'
        resp = requests.get(uri, params={'ip' : queryIP})
        return resp.text

def handleIPv4(orgIP):
    ipv4_pattern = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')
    match = ipv4_pattern.match(orgIP)
    if match:
        return orgIP
    return False

print(useAPI("SEARCH", "localhost"))
