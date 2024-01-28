from ipData_API import getSpecificAPIKey
import requests, re, sys
import logging

def useAPI(method : str, orgIP : str = None):
    # globals
    base_uri = "https://sicehice.com/api"
    info_uri = "https://iplocation.sicehice.com"

    if orgIP:
        queryIP = handleIPv4(orgIP)
        if (not queryIP) and (orgIP.lower() != "localhost"):
            sys.exit("Enter a valid IPv4 address!")

    if method.upper() == "SEARCHTHREATINFO":
        params = { 'apikey' : getSpecificAPIKey(3), 'query' : queryIP }
        uri = f'{base_uri}/getip'
        try:
            raw_resp = requests.post(uri, headers=params)
            resp = raw_resp.json()
            return logThreatInfo(resp['data'], queryIP)
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
        json_out = resp.json()
        return json_out
    
    elif method.upper() == "GETIPINFO":
        uri = f'{info_uri}/api'
        resp = requests.get(uri, params={'ip' : queryIP})
        return resp.text


def handleIPv4(orgIP : str):
    ipv4_pattern = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')
    match = ipv4_pattern.match(orgIP)
    if match:
        return orgIP
    return False


def logThreatInfo(threatList: list, queryIP: str):
    try:
        logging.basicConfig(filename='threat.log', filemode='a', format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)
    except Exception as e:
        print(f"An exception occurred during logging setup: {e}")

    if threatList == []:
        logging.error("No threat info available!")
        return 
    
    logging.info(f"IP Address: {queryIP}\n\n")
    for threat in threatList:
        source = threat.get('source', 'N/A')
        note = threat.get('note', 'N/A')
        print(source, note)
        logging.info(f"Source: {source}\nClassification: {note}\n")

useAPI("SEARCHTHREATINFO", "148.163.93.51")
useAPI("SEARCHTHREATINFO", "77.91.68.78")