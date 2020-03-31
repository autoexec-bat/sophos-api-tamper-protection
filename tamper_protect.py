# Sophos Central - Tamper protection checks
# Aaron Bugal, Sophos, 2020
import requests, json, getpass

# Set a chance to break this script if the user so desires.
print("\n\nBefore running this, please ensure that TAMPER PROTECTION is enabled within Global Settings.")
print("This script will not effect any change if the above is not enabled.\n")
print("Press CTRL-C now to STOP or any other key to continue")
input()
# Ask for Client ID and Client Secret
# In the future we will use an external document or AWS secrets file to host credentials
print("\n\nPlease enter your Sophos Central API credentials - to create them please read https://developer.sophos.com/getting-started-tenant\n\n")
client_id = input("Please enter your Client ID: ")
client_secret = getpass.getpass(prompt='Please enter your Client Secret: ')

def CentralAuth():
    # Get the tenants BearerToken
    authurl = "https://id.sophos.com/api/v2/oauth2/token"
    auth_req = "grant_type=client_credentials" + "&client_id=" + client_id + "&client_secret=" + client_secret + "&scope=token"
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'SophosCentralTamperChecker/1.0'
        }
    response = requests.request("POST", authurl, headers=headers, data=auth_req)
    # Take the response and then slot just the access_token from the returned JSON into our BearerToken var
    response = json.loads(response.text)
    global BearerToken
    BearerToken = response.get('access_token')

def CentralWhoamI():
    # Tenant_ID enumeration process is below
    whoamiurl = "https://api.central.sophos.com/whoami/v1"
    payload = {}
    headers = {
        'Authorization': 'Bearer ' + BearerToken +'',
        'User-Agent': 'SophosCentralTamperChecker/1.0'
    }
    tenantresponse = requests.request("GET", whoamiurl, headers=headers, data=payload)
    # Take the tenantresponse and then slot the TenantID and DataRegion returned JSON into our respective vars
    tenantresponse = json.loads(tenantresponse.text)
    global TenantID
    TenantID = tenantresponse['id']
    global DataRegion
    DataRegion = tenantresponse['apiHosts']['dataRegion']
    # The data region is important per the API specification as your data is stored in a specific AWS geo

def CentralTPCheck():
    #Now that we have the authentication sorted, tenant identification and where the actual data is hosted lets wind this up!
    endpointdataurl = DataRegion + "/endpoint/v1/endpoints?tamperProtectionEnabled=false"
    headers = {
        'X-Tenant-ID': TenantID,
        'Authorization': 'Bearer ' + BearerToken +'',
        'User-Agent': 'SophosCentralTamperChecker/1.0',
        'content-type': 'application/json'
    }
    global endpointdataresponse
    endpointdataresponse = requests.get(endpointdataurl, headers=headers)
    # Yep, let's yeet thru some more JSON
    endpointdataresponse = endpointdataresponse.json()
    # Extract the device ID for each systemid and hostname
    for item in endpointdataresponse["items"]:
        systemid = (item["id"])
        devicename = (item["hostname"])
        with open("report.txt", "a") as tpoutput:
            tpoutput.write(systemid)
            tpoutput.write(",")
            tpoutput.write(devicename)
            tpoutput.write("\n")
        tpoutput.close()

def CentralTPChange():
    # let's now make the actual changes
    for item in endpointdataresponse["items"]:
        systemid = (item["id"])
        enabletpurl = DataRegion + "/endpoint/v1/endpoints/" + systemid + "/tamper-protection"
        payload = "{\n  \"enabled\": true\n}"
        headers = {
            'X-Tenant-ID': TenantID,
            'Content-Type': 'application/json',
            'User-Agent': 'SophosCentralTamperChecker/1.0',
            'Authorization': 'Bearer ' + BearerToken +'',
        }
        change = requests.request("POST", enabletpurl, headers=headers, data=payload)
    # There is NO error handling here.  And a resultant execution of this script will fault without notification.

CentralAuth()
CentralWhoamI()
CentralTPCheck()
CentralTPChange()

# Now finish up and report to user.
print("\n")
print("\nProcess Completed.\n")
print("Please see report.txt for a list of systems that DID NOT have Tamper Protection Enabled.\n")
print("These systems NOW have Tamper Protection enabled.\n\n")
print("Please visit https://central.sophos.com and verify these changes.")
