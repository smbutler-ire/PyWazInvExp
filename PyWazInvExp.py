import json
import requests
import urllib3
import csv
from base64 import b64encode

# Disable insecure https warnings (for self-signed SSL certificates)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
protocol = 'https'
host = 'hostname'
port = 55000
user = 'username'
password = 'password'
login_endpoint = 'security/user/authenticate'

login_url = f"{protocol}://{host}:{port}/{login_endpoint}"
basic_auth = f"{user}:{password}".encode()
login_headers = {'Content-Type': 'application/json',
                 'Authorization': f'Basic {b64encode(basic_auth).decode()}'}

print("\nLogin request ...\n")
response = requests.get(login_url, headers=login_headers, verify=False)
token = json.loads(response.content.decode())['data']['token']
print(token)

# New authorization header with the JWT token we got
requests_headers = {'Content-Type': 'application/json',
                    'Authorization': f'Bearer {token}'}

print("\n- API calls with TOKEN environment variable ...\n")

print("Getting API information:")

response = requests.get(f"{protocol}://{host}:{port}/?pretty=true", headers=requests_headers, verify=False)
print(response.text)

print("\nGetting agents status summary:")

response = requests.get(f"{protocol}://{host}:{port}/agents/summary/status?pretty=true", headers=requests_headers, verify=False)
print(response.text)

print("\nGetting agents:")

response = requests.get(f"{protocol}://{host}:{port}/agents/?pretty=true&limit=3000", headers=requests_headers, verify=False)
r = json.loads(response.text)

print("\nGetting Installed Packages:")

for i in r["data"]["affected_items"]:
    agentname = i["name"]
    agentlist = i["id"]
    endpoint = "syscollector/" + agentlist + "/packages"
    second = "{protocol}://{host}:{port}/" + endpoint
    response = requests.get(f"{protocol}://{host}:{port}/{endpoint}", headers=requests_headers, verify=False)
    s = json.loads(response.text)
    for j in s["data"]["affected_items"]:
       with open('Wazuh_Inventory_.csv', mode='a', newline='') as csv_file:
            fieldnames = ['Name', 'Version', "AgentID", "AgentName"]
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            if "version" in j :
                writer.writerow({'Name': j["name"], 'Version': j["version"], 'AgentID':agentlist, 'AgentName':agentname})
            else:
                writer.writerow({'Name': j["name"], 'Version': "NA", 'AgentID':agentlist, 'AgentName':agentname})

print("\nFinished:")
