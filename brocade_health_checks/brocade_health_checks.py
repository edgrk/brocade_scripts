######################################################################################
#Brocade healthcheck script with interaction to IBM Spectrum Control (TPC) as configuration database. 
#Output of script can be direct to to chat solution (Slack, Teams e.t.c)
#Written by Edgar Kacko
import requests
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import xmltodict
import getpass

#Establishing request session
session = requests.Session()
session.verify = False

#Using getpass module for authentification
username = getpass.getuser()
password = getpass.getpass()

#Variables.
tpc = 'https://tpcserver:9569/srm/'
firm = 'v8.2.1c' #Filter for devices upgraded to 8.2.1c FOS. Can be changed to latest version.

#Empty list for future append
listofswn = []

#Main helper functions
def connect_to_tpc(spc_base_url, p_username, p_password):
    '''
    Connects to single TPC, returns the session (connection) hanlder. 
    '''
    session = requests.Session()
    session.verify = False
    response = session.post(spc_base_url + 'j_security_check', data={'j_username': p_username, 'j_password': p_password})
    response.raise_for_status()
    return session

def get_from_tpc(session, url):
    '''
    For given, opened, session it sends HTTP GET call to the TPC.
    '''
    response = session.get(url)
    response.raise_for_status()
    reponse_json = response.json()
    return reponse_json # this returns list

#Get list of switches from TPC Spectrum Control. 
def switch_list(tpc):
    session = connect_to_tpc(tpc, username, password)
    reponse_json = get_from_tpc(session, tpc + 'REST/api/v1/' + 'Switches')
    filt = [i for i in reponse_json if firm in i['Firmware']]
    for name in filt:
        element1 = (name['Name']+"domain") #adding domain name. Can be replaced by name["IP"] for IP address.
        listofswn.append(element1)

#Switch Authorization Function
def switch_auhorization(hostname):
    response = session.post('https://'+hostname+'/rest/login',auth=(username, password))
    headersa = (response.headers['Authorization'])
    headers = {'Authorization': headersa}
    return headers

#Function handles conversion from xml to json format. 
def jsonbr():
    tree1 = response.content
    xml_dict = xmltodict.parse(tree1)
    jsonf = (json.dumps(xml_dict))
    d = json.loads(jsonf)
    return d

#Define function to check health
def healthchk(hostname):
    #Authorization
    print("......... Connecting to "+hostname)
    headers = switch_auhorization(hostname)
    response = session.get('https://'+hostname+'/rest/running/brocade-maps/switch-status-policy-report', headers=headers)
    d = jsonbr()
    print("Checking Switch health status based on MAPS report...")
    print("-"*50)
    ddict = d["Response"]["switch-status-policy-report"] 
    #Check if result dictonary some of items reported other than healthy status
    result = [k for k,v in ddict.items() if v != 'healthy']
    #If this true and something filtered print results.
    if len(result) != 0:
        print("!!! Automated scan results --- Components on {} reportred not healthy state. Please verify switch health with command: mapsdb --show all" .format(hostname))
    else:
        print("All components reported to be heatlthy")
    #Logout
    response = session.post('https://'+hostname+'/rest/logout',headers=headers)
 
####Main
for ip in listofswn:
    try:
        healthchk(ip)
    except:
        print("WARNING: Connection to {} was not successful!".format(ip))
        pass



