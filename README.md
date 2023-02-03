# PyWazInvExp
Wazuh Inventory Python Exporter

Uses Wazuh API to query all agents and Export a CSV with all Installed Packages

API has a default limit of 500 returns / limit increased to 3000 within script.

# Python Module Prerequisets
json
requests
urllib3
csv

# Configuration
Modify Configuration to match wazuh env

protocol = 'https'

host = 'hostname'

port = 55000

user = 'username'

password = 'password'
