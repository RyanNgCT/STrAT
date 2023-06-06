import requests, re, json, sys, time, os, shutil, argparse
import aiohttp, asyncio
from assets.colours import bcolors

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
        print(f"[INFO] Trying {tryHTTPFirst}...\n")
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
            sys.exit(
                "Please wait before submitting request again. PhishTank is throttling your traffic..."
            )

        # Redirect (Perm or Temp) -> Change proto to https
        elif result.status_code == 301 or result.status_code == 302:
            tryHTTPSNext = "https://" + raw_uri
            print(f"[INFO] Trying {tryHTTPSNext} now...\n")
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
                print("API endpoint returned 200. Processing is complete.")
                async with session.get(url) as resp:
                    text = await resp.json()
                return text
            else:
                print(
                    f"Urlscan API endpoint returned {response_status}. Waiting another 5 sec for results..."
                )  # replace with progress bar of sorts(?)
            await asyncio.sleep(5)


def defangUrl(url):
    return url.replace(".", "[.]").replace("http", "hxxp")


def downloadURLScanImage(uuid):
    imageURI = f"https://urlscan.io/screenshots/{uuid}.png"
    try:
        imageURI_resp = requests.get(url=imageURI, stream=True)
    except requests.exceptions.ConnectionError:
        sys.exit("Error in downloading the screenshot.")
    if imageURI_resp.status_code == 200:
        with open("target.png", "wb") as f:
            shutil.copyfileobj(imageURI_resp.raw, f)
            print("URLScan Screenshot sucessfully downloaded.")
    else:
        print("URLScan Screenshot couldn't be retrieved...")


def main():
    API_KEYS = getAPIKey()

    userUrl = input("Enter a site url to check against: ").strip()
    if userUrl == "":
        sys.exit("Empty URL provided. Quitting...")

    try:
        rawURL = checkAndSanitizeUri(userUrl)
    except ValueError:
        sys.exit("Invalid URL Supplied.")
    else:
        # send values based on return value of url validation function
        if rawURL:
            # === VT Request and Response ===
            headerFormat = {"Content-Type": "application/json", "x-apikey": API_KEYS[0]}
            data = {"url": rawURL, "visibility": "public", "analyze": "true"}
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

                # get unique id for VT (scan result)
                moddedId = json.loads(VT_Response.content)["data"]["id"]
                for index, char in enumerate(moddedId[::-1]):
                    if char == "-":
                        index = len(moddedId) - index
                        moddedId = moddedId[: index - 1].strip("u-")
                        break

                # code for checking if url was previously scanned by VT
                harmlessCount, maliciousCount = 0, 0
                while True:
                    vtReport = requests.get(url=vtUri, headers=headerFormat)
                    vtReport = vtReport.json()
                    harmlessCount = vtReport["data"]["attributes"]["stats"]["harmless"]
                    maliciousCount = vtReport["data"]["attributes"]["stats"]["malicious"]

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
                    time.sleep(2)
                print(
                    f"[VT Info] AV(s) Flagging Website as harmless: {harmlessCount}, AV(s) Flagging Website as malicious: {maliciousCount}"
                )

                # need to relook these metrics
                if (harmlessCount > maliciousCount) and maliciousCount <= 9:
                    print(f'{bcolors.OKGREEN}VT: Web Resource "{finalURL}" is not malicious.{bcolors.ENDC}')
                else:
                    print(f'{bcolors.FAIL}VT: Web Resource "{defangUrl(finalURL)}" is MALICIOUS.{bcolors.ENDC}')
            else:
                print(f"VT: Request failed with status code {VT_Response.status_code}")
            print()

            # === Urlscan Request and Response ===
            headers = {"API-Key": API_KEYS[1], "Content-Type": "application/json"}
            data = {"url": rawURL, "visibility": "public"}

            # Request
            URLScan_Response = requests.post(
                "https://urlscan.io/api/v1/scan/",
                headers=headers,
                data=json.dumps(data),
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
                    finalURL = intermediateData["data"]["requests"][1]["request"]["documentURL"]
                except IndexError:
                    finalURL = intermediateData["data"]["requests"][0]["request"]["documentURL"]

                # optional custom method to download urlscan screenshot
                downloadURLScanImage(urlscanUriUid)

                if res_payload["verdicts"]["overall"]["malicious"] == False:
                    print(f'{bcolors.OKGREEN}UrlScan: Web Resource "{finalURL}" is not malicious.{bcolors.ENDC}')
                else:
                    print(
                        f'{bcolors.FAIL}UrlScan: Web Resource "{defangUrl(finalURL)}" is MALICIOUS.{bcolors.ENDC}'
                    )

            elif URLScan_Response.status_code == 400:
                if (
                    URLScan_Response.json()["message"] == "DNS Error - Could not resolve domain"
                ):
                    print("UrlScan: Cannot resolve URL domain.")
                else:
                    print("Blacklisted site by URL Scan... Skipping...")

                    # remove older screenshot so as to not confuse user
                    if os.path.exists("target.png"):
                        os.remove("target.png")
            else:
                print(
                    f"UrlScan: Request failed with status code {URLScan_Response.status_code}"
                )

        # issues contacting server/totally invalid -> may need to validate 404
        else:
            print("Invalid URL Entered or server not contactable.")

        ## Future Feature to implement

        # userSecurityOption = input('Enter a security option: < [P]ublic (default) || [U]nlisted || P[R]ivate > :')
        # securityOptionSettings = ''

        # if userSecurityOption.upper() == 'P' or userSecurityOption == '':
        #     securityOptionSettings = 'public'
        # elif userSecurityOption.upper() == 'U':
        #     securityOptionSettings = 'unlisted'
        # elif userSecurityOption.upper() == 'R':
        #     securityOptionSettings = 'private'
        # else:
        #     print("Incorrect setting entered... Defaulting to public anyways :)")
        #     securityOptionSettings = 'public'


if __name__ == "__main__":
    main()