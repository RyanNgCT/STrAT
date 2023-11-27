import ipdata
import re, sys


def getSpecificAPIKey():
    try:
        with open("../.env", "r") as secretsFile:
            for key in secretsFile:
                # need to grep API_KEY as a string
                if re.match(r"IPDATA\_API\_KEY", key):
                    key = key.rpartition(" = ")[2]
            return key
            

    except FileNotFoundError:
        sys.exit(
            f"File containing API Key not found. Please ensure file '.env' is in same parent directory as script."
        )

    except IndexError:
        sys.exit(
            f"Please ensure API keys are CRLF-delimited and in key value pairs surrounded in **single quotes**."
        )


def getIPCountryInfo():
    ipToLookFor = str(input('Enter IP Address to lookup: '))
    ipdata.api_key = getSpecificAPIKey().strip("'") # need to remove quotes
    ipdata.endpoint = "https://eu-api.ipdata.co" # set to EU API endpoint for GDPR
    response = ipdata.lookup(ipToLookFor)
    if response != None:
        print(response.country_name, type(response))


# def getIPCountryInfo(api_key, ip_addr):
#     ipdata.api_key = api_key
#     ipdata.endpoint = "https://eu-api.ipdata.co" # set to EU API endpoint for GDPR
#     response = ipdata.lookup(ip_addr)
#     if response != None:
#         return response


if __name__ == "__main__":
    getIPCountryInfo()