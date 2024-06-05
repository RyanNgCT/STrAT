import ipdata
import re, sys

def getSpecificAPIKey(index: int) -> str:
    try:
       with open("../.env", "r") as secrets_file:
            lines = secrets_file.readlines()

            if 0 <= int(index) < len(lines):
                key_value = lines[int(index)].strip().split(" = ")
                if len(key_value) == 2 and key_value[1].startswith("'") and key_value[1].endswith("'"):
                    return key_value[1][1:-1]
                else:
                    sys.exit("Invalid format for API key in .env file.")
            else:
                sys.exit(f"Index {index} out of range. Please provide a valid index.")

    except FileNotFoundError:
        sys.exit("File containing API Key not found. Please ensure file '.env' is in the same directory as the script.")
            

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
    ipdata.api_key = getSpecificAPIKey(2).strip("'") # need to remove quotes
    ipdata.endpoint = "https://eu-api.ipdata.co" # set to EU API endpoint for GDPR
    response = ipdata.lookup(ipToLookFor.lstrip().rstrip())
    print(response)
    if response != None:
        print(response.country_name, response.city)


# def getIPCountryInfo(api_key, ip_addr):
#     ipdata.api_key = api_key
#     ipdata.endpoint = "https://eu-api.ipdata.co" # set to EU API endpoint for GDPR
#     response = ipdata.lookup(ip_addr)
#     if response != None:
#         return response


if __name__ == "__main__":
    getIPCountryInfo()