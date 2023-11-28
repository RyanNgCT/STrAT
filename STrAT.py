import requests, re, json, sys, time, os, shutil, argparse, ipdata
import aiohttp, asyncio
from assets.colours import bcolors
from datetime import datetime
from urllib.parse import urlparse
from assets.CustomThread import *
from assets.Wheel import SpinnerThread
from pycountry import countries

""" 
NOTES
======
1. Lookup limit of 4 requests per minute for VT

2. VT Request Format:
curl --request POST \
  --url https://www.virustotal.com/api/v3/urls \
  --form url=<Your URL here>
  --header 'x-apikey: <your API key>'

3. Urlscan Request Format:
headers = {'API-Key':'$apikey','Content-Type':'application/json'}
data = {"url": "https://urlyouwanttoscan.com/path/", "visibility": "public"}
response = requests.post('https://urlscan.io/api/v1/scan/',headers=headers, data=json.dumps(data))

4. All Scans are default as public
"""


def getAPIKey():
    try:
        secrets = []
        with open(".env", "r") as secretsFile:
            for key in secretsFile:
                # need to grep API_KEY as a string
                key = re.findall(r"'(.*?)'", key)[0]
                secrets.append(key)
            return secrets

    except FileNotFoundError:
        print(
            f"File containing API Key not found. Please ensure file '.env' is in same parent directory as script."
        )
        sys.exit()

    except IndexError:
        print(
            f"Please ensure API keys are CRLF-delimited and in key value pairs surrounded in **single quotes**."
        )
        sys.exit()


# check if url has suffix, if not add on suffix and attempt connection
def checkURLProtoinURI(raw_uri):
    if (
        "http" in raw_uri
        or "https" in raw_uri
        or "hxxp" in raw_uri
        or "hxxps" in raw_uri
    ):
        return raw_uri
    else:
        if "[.]" in raw_uri:
            raw_uri = raw_uri.replace("[.]", ".")
        if "[:]" in raw_uri:
            raw_uri = raw_uri.replace("[:]", ":")
        if "hxxp" in raw_uri:
            raw_uri = raw_uri.replace("hxxp", "http")
        if "hxxps" in raw_uri:
            raw_uri = raw_uri.replace("hxxps", "https")

        # Use Phishtank API to check connectivity if no proto specified
        phishTankAPILink = "https://checkurl.phishtank.com/checkurl/"
        tryHTTPFirst = "http://" + raw_uri
        print(f"[INFO] Trying {defangUrl(tryHTTPFirst)}...\n")
        try:
            result = requests.post(
                url=phishTankAPILink, data={"url": tryHTTPFirst, "format": "json"}
            )
        except requests.exceptions.ConnectionError:
            return False
        if result.status_code == 200:
            return tryHTTPFirst
        elif ( 
            result.status_code == 429 and 
            b"You have exceeded the request rate limit for this method." in result.content 
            ):
            sys.exit("Please wait before submitting request again. PhishTank is throttling your traffic...")

        # Redirect (Perm or Temp) -> Change proto to https
        elif result.status_code == 301 or result.status_code == 302:
            tryHTTPSNext = "https://" + raw_uri
            print(f"[INFO] Trying {defangUrl(tryHTTPSNext)} now...\n")
            try:
                result2 = requests.post(
                    url=phishTankAPILink, data={"url": tryHTTPSNext, "format": "json"}
                )
            except requests.exceptions.ConnectionError:
                return False
            if result2.status_code == 200:
                return tryHTTPSNext
            elif (
                result.status_code == 429 and
                b"You have exceeded the request rate limit for this method." in result.content
            ):
                sys.exit(
                    "Please wait before submitting request again. PhishTank is throttling your traffic..."
                )
        return False


# validate format of url, allow url to be defanged
def checkAndSanitizeUri(raw_uri):
    # Define regex pattern to match a valid URI with or without defanging (from ChatGPT)
    uri_pattern = r"^(?:https?|hxxps?):\/\/(?:\[\.\]|\[\.\]\[\.\]|[^\[\]])+|(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)(?:$|\s)"

    # Check if the URI is defanged, and replace defanging characters with their original counterparts
    protoTrue = checkURLProtoinURI(raw_uri)
    if protoTrue:
        uri = protoTrue  # for perfect uris (require no re-fanging)
        if "[.]" in protoTrue:
            uri = uri.replace("[.]", ".")
        if "[:]" in protoTrue:
            uri = uri.replace("[:]", ":")
        if "hxxp" in protoTrue:
            uri = uri.replace("hxxp", "http")
        if "hxxps" in protoTrue:
            uri = uri.replace("hxxps", "https")

        # Check if the uri matches the regex pattern
        if not re.match(uri_pattern, uri):
            raise ValueError("Invalid URL format.")
    else:
        return False
    return uri


async def fetch(session, url):
    async with session.get(url) as response:
        return response.status


async def waitTilReply(url):
    async with aiohttp.ClientSession() as session:
        while True:
            response_status = await fetch(session, url)
            if response_status == 200:
                print("\nUrlscan API endpoint returned 200.\n")
                async with session.get(url) as resp:
                    text = await resp.json()
                return text
            else:
                pass
            await asyncio.sleep(4)


def defangUrl(url):
    return url.replace(".", "[.]").replace("http", "hxxp")


def defangIP(ipAddr):
    octets = ipAddr.split('.')
    defanged_ip = '.'.join(octets[:-1]) + '[.]' + octets[-1]
    return defanged_ip


def downloadURLScanImage(dir, uuid):
    imageURI = f"https://urlscan.io/screenshots/{uuid}.png"
    try:
        imageURI_resp = requests.get(url=imageURI, stream=True)
    except requests.exceptions.ConnectionError:
        sys.exit("Error in downloading the screenshot.")
    if imageURI_resp.status_code == 200:
        directoryToStore = f'{dir}/target.png'
        with open(directoryToStore, "wb") as f:
            shutil.copyfileobj(imageURI_resp.raw, f)
            print("\nURLScan Screenshot sucessfully downloaded.\n")
    else:
        print("\nURLScan Screenshot couldn't be retrieved...\n")


def createDirAndLog(finalurl, urlscanUriUid):
    now = datetime.now().strftime("%Y-%m-%d_%H%M")
    storeDir = f'results/{now}-{urlparse(finalurl).netloc}'
    if os.path.exists(storeDir):
        shutil.rmtree(storeDir)
    os.makedirs(storeDir)
    # optional custom method to download urlscan screenshot
    downloadURLScanImage(storeDir, urlscanUriUid)
    return storeDir


def runVT(rawURL, API_KEYS, VTIndex, scanVisibility="public"):
    headerFormat = {"Content-Type": "application/json", "x-apikey": API_KEYS[0]}
    data = {"url": rawURL, "visibility": scanVisibility, "analyze": "true"}
    try:
        VT_Response = requests.post(
            url="https://www.virustotal.com/api/v3/urls",
            headers=headerFormat,
            params=data,
        )
    except requests.exceptions.ConnectionError:
        sys.exit(
            "VirusTotal endpoint unreachable. Check your internet connection please."
        )
    if VT_Response.status_code == 200:
        vtUri = json.loads(VT_Response.content)["data"]["links"]["self"]
        headerFormat = {"accept": "application/json", "x-apikey": API_KEYS[0]}

        orgId = json.loads(VT_Response.content)["data"]["id"]

        # only will use "front" variable as new request id
        front, _char , _end = str(orgId).rpartition("-") # strips last `-` char
        moddedId = front.strip("u-")

        # code for checking if url was previously scanned by VT
        harmlessCount, maliciousCount = 0, 0

        # limit count of 90s (catch API timeout/unresponsive issues)
        limit = 30

        while True:
            vtReport = requests.get(url=vtUri, headers=headerFormat)
            vtReport = vtReport.json()
            harmlessCount = vtReport["data"]["attributes"]["stats"]["harmless"]
            maliciousCount = vtReport["data"]["attributes"]["stats"]["malicious"]

            if limit == 0: # limit check needed as status will be stuck and not completed if API times out.
                return -1, None, None, None
            
            # Scan Complete Check (didn't wanna implement async)
            if vtReport["data"]["attributes"]["status"] == "completed":
                otherFormat = (
                    f"https://www.virustotal.com/api/v3/urls/{moddedId}"
                )
                resp = requests.get(url=otherFormat, headers=headerFormat)
                resp = resp.json()
                try:
                    finalURL = resp["data"]["attributes"]["last_final_url"]
                except KeyError:
                    finalURL = rawURL
                break
            limit -= 1
            time.sleep(3)

        # need to relook these metrics
        if (harmlessCount > maliciousCount) and maliciousCount < 8:
            VTIndex = 0
            return VTIndex, finalURL, harmlessCount, maliciousCount
        return 1, defangUrl(finalURL), harmlessCount, maliciousCount # malicious
    else:
        print(f"VT: Request failed with status code {VT_Response.status_code}")


def runURS(rawURL, API_KEYS, URLScanIndex, scanVisibility="public"):
    headers = {"API-Key": API_KEYS[1], "Content-Type": "application/json"}
    data = {"url": rawURL, "visibility": scanVisibility}

    # Request
    try:
        URLScan_Response = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers=headers,
            data=json.dumps(data),
        )
    except requests.exceptions.ConnectionError:
        sys.exit(
            "URLScan endpoint unreachable. Check your internet connection please."
        )
    if URLScan_Response.status_code == 200:
        urlscanUriUid = json.loads(URLScan_Response.content)["uuid"]
        resultsPageURLFormat = (
            f"https://urlscan.io/api/v1/result/{urlscanUriUid}/"
        )

        # prevent Event Loop error in Windows
        if os.name == "nt":
            asyncio.set_event_loop_policy(
                asyncio.WindowsSelectorEventLoopPolicy()
            )

        # Response Method
        res_payload = asyncio.run(waitTilReply(resultsPageURLFormat))

        # quite a messy way to sieve output hmm...
        intermediateData = json.loads(json.dumps(res_payload))
        try:
            ipData = intermediateData["page"]
            # print(ipData)
        except TypeError:
            pass
        try:
            finalURL = intermediateData["data"]["requests"][1]["request"]["documentURL"]
        except (IndexError, KeyError) as e:
            finalURL = intermediateData["data"]["requests"][0]["request"]["documentURL"]

        if res_payload["verdicts"]["overall"]["malicious"] == False:
            URLScanIndex = 0
        else:
            finalURL = defangUrl(finalURL)
            URLScanIndex = 1
        resPath = createDirAndLog(finalURL, urlscanUriUid)
        return URLScanIndex, finalURL, resPath, ipData

    elif URLScan_Response.status_code == 400:
        if (
            URLScan_Response.json()["message"] == "DNS Error - Could not resolve domain"
        ):
            print("\nUrlScan: Cannot resolve URL domain.")
        else:
            print("\nBlacklisted site by URL Scan... Skipping...")
        return -1, None, None, None

    else:
        print(
            f"UrlScan: Request failed with status code {URLScan_Response.status_code}"
        )
        return -1, None, None, None

def clearDirectories():
    try:
        directoryCount = len(next(os.walk('results'))[1])
    except StopIteration:
        return 'Unable to clear old directories.'
    
    dirList = []
    for root, dirs, files in os.walk('results'):
        for dir in dirs:
            dirList.append(root + os.sep + dir)

    dirList = sorted(dirList)
    while directoryCount > 14:
        shutil.rmtree(dirList[0])
        dirList.remove(dirList[0])
        directoryCount -= 1


def getIPCountryInfo(api_key, ip_addr):
    ipdata.api_key = api_key
    ipdata.endpoint = "https://eu-api.ipdata.co" # set to EU API endpoint for GDPR
    response = ipdata.lookup(str(ip_addr))
    return response.country_name, response.region_code, response.city

def main():
    API_KEYS = getAPIKey()
    argDesc = '''STrAT v0.6: A VirusTotal x URLScan.io Website Scanning Tool.\nPlease ensure you do not submit sensitive links!\n'''
    parser = argparse.ArgumentParser(formatter_class = argparse.RawDescriptionHelpFormatter, description= argDesc)
    parser.add_argument("-u", "--url", help="Enter url to scan (defanged or ordinary URL both work).", required=True)
    parser.add_argument("-s", "--visibility", help="Select scan visibility: [ 1 ] Public Scan [ 2 ] Private Scan [ 3 ] Unlisted Scan.", \
                        type=int, required=False, choices=[1, 2, 3])
    parser.add_argument("-v","--verbose", help="Display more verbose output", action='store_true', required=False)

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    userUrl = str(args.url).strip()
    if args.visibility:
        scanVisibilityInt = int(args.visibility)
        visibilityMapping = {1: "public", 2: "private", 3: "unlisted"}
        scanVisibility = visibilityMapping[scanVisibilityInt]
    else:
        # default to public scan
        scanVisibility = "public"

    err = clearDirectories()
    if err:
        print(err)

    try:
        rawURL = checkAndSanitizeUri(userUrl)
    except ValueError:
        sys.exit("Invalid URL Supplied.")
    else:
        # send values based on return value of url validation function
        VTIndex, URLScanIndex = -1, -1
        if rawURL:
            spWheel1 = SpinnerThread("Processing...")
            spWheel1.start()
            t1 = CusThread(target=runVT, args=(rawURL, API_KEYS, VTIndex, scanVisibility))
            t2 = CusThread(target=runURS, args=(rawURL, API_KEYS, URLScanIndex, scanVisibility))
            t1.start()
            t2.start()
            try:
                VTmaliciousStatus, VTurl, harmlessCount, maliciousCount = t1.join()
                URLSmaliciousStatus, URLSurl, resPath, ipData = t2.join()
            except AttributeError:
                spWheel1.stop(rawURL)
                sys.exit("\nUnable to start thread. Please check your internet connection.")
            except ValueError: # returns nothing (i.e., url on urlscan blacklist)
                spWheel1.stop()
                print(f"VirusTotal has classified {bcolors.OKGREEN}{VTurl}{bcolors.ENDC} as likely benign.\n")
            except TypeError:
                spWheel1.stop(rawURL)
                sys.exit("Please verify the url entered again.")
            else:
                spWheel1.stop()
                if args.verbose:
                    if VTmaliciousStatus != -1: # No errors/issues in VT API
                        print(f"\nVT classifications:\n==================\nMalicious: {maliciousCount}\nHarmless: {harmlessCount}\n")
                    if ipData and all(key in ipData for key in ["country", "city"]):
                        country, city = countries.get(alpha_2=str(ipData["country"])), ipData["city"]
                        country_ipData, cCode_ipData, city_ipData = getIPCountryInfo(API_KEYS[2], ipData["ip"])
                        if country.name == country_ipData:
                            URS_str = f"URLScan Classifications:\n=======================\nLikely Server location: {country.name}\n"
                            if city and ipData["ip"]:
                                URS_str = URS_str.rstrip("\n")
                                URS_str += f', {city}.\nIP Address: {defangIP(ipData["ip"])}\n'
                            print(URS_str, f'\n{str(country_ipData)}', city_ipData)
                        else:
                            print("URLScan Classifications:\n=======================\nMismatch in likely server locatio, thus not displayed.")
                if VTmaliciousStatus != URLSmaliciousStatus and VTmaliciousStatus == 1:
                    if URLSmaliciousStatus !=-1:
                        print(f"VirusTotal has classified {bcolors.WARNING}{VTurl}{bcolors.ENDC} as MALICIOUS.\nURLScan on the other hand deems this to be not malicious. Proceed with caution.\n")
                    else:
                        print(f"VirusTotal has classified {bcolors.WARNING}{VTurl}{bcolors.ENDC} as MALICIOUS.\n")
                    if resPath:
                        orgPath = resPath
                        finalPath = resPath.replace(".", "[.]")
                        # refang directory name
                        os.renames(os.getcwd() + f"/{orgPath}", os.getcwd() + f"/{finalPath}")
                elif VTmaliciousStatus != URLSmaliciousStatus and URLSmaliciousStatus == 1:
                    print(f"URLScan has classified {bcolors.WARNING}{URLSurl}{bcolors.ENDC} as MALICIOUS.\nVirusTotal on the other hand deems this to be not malicious. May require further validation.\n")
                elif VTmaliciousStatus == 1 and URLSmaliciousStatus == 1:
                    print(f"{bcolors.FAIL}Both scanners have classified {VTurl} as MALICIOUS.{bcolors.ENDC}\n")
                else:
                    if URLSurl != None:
                        print(f"{bcolors.OKGREEN}{URLSurl}{bcolors.ENDC} is quite likely benign.\n")
                    else:
                        print(f"{bcolors.OKGREEN}{VTurl}{bcolors.ENDC} is quite likely benign.\n")

        # issues contacting server/totally invalid -> may need to validate 404
        else:
            print("Invalid URL Entered or server not contactable.")

if __name__ == "__main__":
    v = sys.version_info
    if (v < (3, 10)):
        print(f"{bcolors.WARNING}[-] STrAT v0.6 only works with Python 3.10+.{bcolors.ENDC}")
        sys.exit(f"{bcolors.OKBLUE}[+] Please install the most recent version of Python 3 @ https://www.python.org/downloads/ {bcolors.ENDC}\n")
    main()