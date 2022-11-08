import requests
import time
import os
from datetime import datetime


filename = None
scoreFilter = None

def createFile():
    now = datetime.now()
    now = now.strftime("%d/%m/%Y %H:%M:%S")
    full_path = os.path.realpath(__file__)
    f = open(os.path.dirname(full_path) + "/VirusTotal_results.txt", 'a+')
    f.write('\n\n\n'+now+'\n')
    f.close()

def getList(filename):
    with open(filename, "r") as f:
        ip_list_tmp = f.readlines()
    ip_list_tmp = [x.strip() for x in ip_list_tmp]
    f.close()
    return ip_list_tmp

def checkHash(hashList, percent, apikey, premium):
    # Defining the api-endpoint
    url = 'https://www.virustotal.com/api/v3/files/'
    full_path = os.path.realpath(__file__)
    f = open(os.path.dirname(full_path) + "/VirusTotal_results.txt", 'a')
    for item in hashList:
        response = (requests.get(url+item, headers={'X-Apikey': apikey})).json()
        dist = "unknown"
        if response.get("data") != None:
            if response.get("data").get("attributes").get("known_distributors") != None:
                dist = response.get("data").get("attributes").get("known_distributors").get("distributors", "unknown")
            extension = response.get("data").get("attributes").get("type_description", "unknown")
            name_hash = response.get("data").get("attributes").get("meaningful_name", "unknown")
            sospicious = int(response.get("data").get("attributes").get("last_analysis_stats").get("suspicious", 0))
            malicious = int(response.get("data").get("attributes").get("last_analysis_stats").get("malicious", 0))
            undetected = int(response.get("data").get("attributes").get("last_analysis_stats").get("undetected", 0))
            total = sospicious+malicious+undetected
            positives = sospicious+malicious
            minScore = (int(total)*percent)/100
            if positives >= minScore:
                tmp = ""
                if dist != "unknown":
                    for x in dist:
                        tmp += x+"; "
                else:
                    tmp = "unknown"
                f.writelines("hash: "+item+"\t\tscore: "+str(positives)+" of "+str(total)+"\t\tname: "+name_hash+"\t\textension: "+extension+"\t\tdistributor: "+tmp+"\n")
            if premium == False and len(hashList)>4:
                time.sleep(26)
        else:
            f.writelines("hash: "+item+"\t\tNo match found"+"\n")

while filename == None or filename == "":
    filename = input("Enter the path of the file to import (.txt): ")
    filename = filename.strip()

while scoreFilter == None:
    tmp = input("Enter the minimum percentage of positive scans (Press ENTER for DEFAULT = ALL): ")
    if(tmp.strip() == ""):
        scoreFilter = 0
    else:
        try:
            tmp = int(tmp.strip())
            if(tmp >= 0 and tmp <= 100):
                scoreFilter = tmp
            else:
                print("Score value must be between 0 and 100")
        except:
            print("Dude, no jokes")

api_key = input("Insert your VirusTotal API_KEY (Press ENTER to read from your_KEY.txt): ")
api_key = api_key.strip()
premium_api = False
if api_key == "":
    full_path = os.path.realpath(__file__)
    f = open(os.path.dirname(full_path) + "/your_KEY.txt", 'r')
    api_key_tmp = f.read().splitlines()
    if len(api_key_tmp) == 2:
        api_key = api_key_tmp[0]
        if api_key_tmp[1] == "yes":
            premium_api = True
    else:
        print("Formatting error your_KEY.txt")
        exit()    
else:
    if input("Is your API KEY Premium? (yes/no): ") == "yes":
        premium_api = True


createFile()
checkHash(getList(filename), scoreFilter, api_key, premium_api)
