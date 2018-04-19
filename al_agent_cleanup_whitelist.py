from __future__ import print_function
import json, requests, datetime, os, boto3
from base64 import b64decode

#request API call static Params
HEADERS = {'content-type': 'application/json'}

def lambda_handler(event, context):
	CUST_ID = os.environ["CID"]
	MIN_DELTA = os.environ["DELTA"]
	TAG_WHITELIST = os.environ["WHITELIST"]
	REGION_SCOPE = os.environ["REGION_SCOPE"]
	API_KEY = boto3.client('kms').decrypt(CiphertextBlob=b64decode(os.environ["API_KEY"]))['Plaintext']

	print (str("AL Agent Cleanup Report " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M")))

	DC = os.environ["DC"]
	if DC == "DENVER":
		ALERT_LOGIC_CD_DC = ".alertlogic.net"

	elif DC == "ASHBURN":
		ALERT_LOGIC_CD_DC = ".alertlogic.com"

	elif DC == "NEWPORT":
		ALERT_LOGIC_CD_DC = ".alertlogic.co.uk"

	TARGET_PROTECTED_HOST = []
	TARGET_HOST = []
	TARGET_SOURCE = []
	SNS_HEADER = ""
	SNS_SEARCH_RESULT = ""
	SNS_DELETE_RESULT = ""

	print ("Target CID : " + str(CUST_ID))
	print ("Delta Days : " + str(MIN_DELTA))
	print ("Tag Whitelist: " + str(TAG_WHITELIST))
	print ("Region scope: " + str(REGION_SCOPE) + "\n")
	SNS_HEADER = SNS_HEADER + "Target CID : " + str(CUST_ID) + ".\n"
	SNS_HEADER = SNS_HEADER + "Delta Days : " + str(MIN_DELTA) + ".\n"
	SNS_HEADER = SNS_HEADER + "Tag whitelist : " + str(TAG_WHITELIST) + "\n"
	SNS_HEADER = SNS_HEADER + "Region scope : " + str(REGION_SCOPE) + "\n\n"

	#find protected host, host and log source that match the delta day + whitelist
	TARGET_PROTECTED_HOST, TARGET_HOST, SNS_SEARCH_RESULT = find_inactive_protectedhost(CUST_ID, API_KEY, MIN_DELTA, TAG_WHITELIST, REGION_SCOPE, ALERT_LOGIC_CD_DC)
	if TARGET_PROTECTED_HOST:
		TARGET_SOURCE = find_inactive_source(TARGET_HOST, CUST_ID, API_KEY, ALERT_LOGIC_CD_DC)

	print ("\nTarget protected host: " + str(TARGET_PROTECTED_HOST))
	print ("\nTarget source: " + str(TARGET_SOURCE))
	print ("\nTarget host: " + str(TARGET_HOST))

	SNS_BODY = SNS_SEARCH_RESULT + ""
	SNS_BODY = SNS_BODY + "\nTarget protected host: \n" + str(TARGET_PROTECTED_HOST) + ".\n"
	SNS_BODY = SNS_BODY + "\nTarget source: \n" + str(TARGET_SOURCE) + ".\n"
	SNS_BODY = SNS_BODY + "\nTarget host: \n" + str(TARGET_HOST) + ".\n\n"

	#delete the targeted protected host and source and then host
	if len(TARGET_HOST) >= 0:
		RESULT = delete_inactive_source(TARGET_SOURCE, CUST_ID, API_KEY, ALERT_LOGIC_CD_DC)
		print ("Delete source : " + "\n" + str(RESULT))
		SNS_DELETE_RESULT = SNS_DELETE_RESULT + "Delete source : " + "\n" + str(RESULT) + ".\n"

		RESULT = delete_inactive_protectedhost(TARGET_PROTECTED_HOST, CUST_ID, API_KEY, ALERT_LOGIC_CD_DC)
		print ("Delete protected host : " + "\n" + str(RESULT))
		SNS_DELETE_RESULT = SNS_DELETE_RESULT + "Delete protected host : " + "\n" + str(RESULT) + ".\n"

		RESULT = delete_inactive_host(TARGET_HOST, CUST_ID, API_KEY, ALERT_LOGIC_CD_DC)
		print ("Delete host : " + "\n" + str(RESULT))
		SNS_DELETE_RESULT = SNS_DELETE_RESULT + "Delete host : " + "\n" + str(RESULT) + ".\n"

	else:
		print ("No protected host match criteria to be delete")

	#Push output to SNS topic
	sns_client = boto3.client('sns')
	SNS_MESSAGE = SNS_HEADER + SNS_BODY + SNS_DELETE_RESULT
	sns_response = sns_client.publish(
		TargetArn=os.environ["SNS_ARN"],
		Message=SNS_MESSAGE,
		Subject=str("AL Agent Cleanup Report " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M")))

def find_inactive_protectedhost(target_cid, user_api_key, delta_day, whitelist, region, target_dc):
	RESPONSE = list_inactive_protectedhost(target_cid, user_api_key, target_dc)
	HOST_DATA = RESPONSE["protectedhosts"]
	TEMP_PROTECTED_HOST = []
	TEMP_TARGET_HOST = []
	OUTPUT_MESSAGE = ""

	#find host id based on IP4 meta data excluding the docker host it self
	for item in HOST_DATA:
		if item["protectedhost"]["status"]["status"] == "offline":
			#get the delta days since last update
			LAST_UPDATE = datetime.datetime.utcfromtimestamp(item["protectedhost"]["status"]["updated"])
			DAYS_DELTA = datetime.datetime.utcnow() - LAST_UPDATE

			#add protected host to target to be deleted if it's has been offline for more than MIN_DELTA
			if DAYS_DELTA.days > int(delta_day):
				#if whitelist specified, check if whitelist exist in the phost tags
				phost_include = False
				if whitelist == "":
					if region == "":
						phost_include = True
					elif region != "" and "metadata" in item["protectedhost"]:
						if "ec2_region" in item["protectedhost"]["metadata"]:
							if item["protectedhost"]["metadata"]["ec2_region"] == region:
								phost_include = True
				elif whitelist != "":
					if region == "":
						if any(whitelist in tag['name'] for tag in item["protectedhost"]["tags"] ):
							phost_include = True
					elif region != "" and "metadata" in item["protectedhost"]:
						if "ec2_region" in item["protectedhost"]["metadata"]:
							if item["protectedhost"]["metadata"]["ec2_region"] == region:
								if any(whitelist in tag['name'] for tag in item["protectedhost"]["tags"] ):
									phost_include = True

				if phost_include == True:
					TEMP_PROTECTED_HOST.append(item["protectedhost"]["id"])
					TEMP_TARGET_HOST.append(item["protectedhost"]["host_id"])
					print ("Found host name " + str(item["protectedhost"]["name"]) + " id " + str(item["protectedhost"]["id"]) + " host id " + str(item["protectedhost"]["host_id"]) + " IP Address " + str(item["protectedhost"]["metadata"]["local_ipv4"]) + " Last update " + str(LAST_UPDATE) + " delta days : " + str(DAYS_DELTA.days))
					OUTPUT_MESSAGE = OUTPUT_MESSAGE + "Found host name " + str(item["protectedhost"]["name"]) + " id " + str(item["protectedhost"]["id"]) + " host id " + str(item["protectedhost"]["host_id"]) + " IP Address " + str(item["protectedhost"]["metadata"]["local_ipv4"]) + " Last update " + str(LAST_UPDATE) + " delta days : " + str(DAYS_DELTA.days) + ".\n"

	return TEMP_PROTECTED_HOST, TEMP_TARGET_HOST, OUTPUT_MESSAGE

def find_inactive_source(target_host, target_cid, user_api_key, target_dc):
	RESPONSE = list_inactive_source(target_cid, user_api_key, target_dc)
	SOURCE_DATA = RESPONSE["sources"]
	TEMP_TARGET_SOURCE = []

	#find source id based on host id
	for host_id in target_host:
		for item in SOURCE_DATA:
			if item["syslog"]["agent"]["host_id"] == host_id:
				print ("Found source name " + str(item["syslog"]["name"]) + " id " + str(item["syslog"]["id"]) + " host id " + str(host_id))
				TEMP_TARGET_SOURCE.append(item["syslog"]["id"])

	return TEMP_TARGET_SOURCE

def list_inactive_protectedhost(target_cid, user_api_key, target_dc):
	#find all protected host with deployment model agent and status is offline
	API_ENDPOINT = "https://publicapi" + target_dc +  "/api/tm/v1/" + target_cid + "/protectedhosts?config.collection_method=agent&status.status=offline&type=host&offset=0"
	REQUEST = requests.get(API_ENDPOINT, headers=HEADERS, auth=(user_api_key,''))
	RESULT = json.loads(REQUEST.text)
	return RESULT

def list_inactive_source(target_cid, user_api_key, target_dc):
	#find all the source in log manager with deployment model syslog / agent and status is offline
	API_ENDPOINT = "https://publicapi" + target_dc + "/api/lm/v1/" + target_cid + "/sources/?type=syslog&status=offline&offset=0"
	REQUEST = requests.get(API_ENDPOINT, headers=HEADERS, auth=(user_api_key,''))
	RESULT = json.loads(REQUEST.text)
	return RESULT

def delete_inactive_protectedhost(target, target_cid, user_api_key, target_dc):
	RESULT = ""
	for items in target:
		API_ENDPOINT = "https://publicapi" + target_dc +  "/api/tm/v1/" + target_cid + "/protectedhosts/" + items
		REQUEST = requests.delete(API_ENDPOINT, headers=HEADERS, auth=(user_api_key,''))
		RESULT = RESULT + str(REQUEST.text) + " Protected Host ID : " + items + "\n"
	return RESULT

def delete_inactive_source(target, target_cid, user_api_key, target_dc):
	RESULT = ""
	for items in target:
		API_ENDPOINT = "https://publicapi" + target_dc + "/api/lm/v1/" + target_cid + "/sources/" + items
		REQUEST = requests.delete(API_ENDPOINT, headers=HEADERS, auth=(user_api_key,''))
		RESULT = RESULT + str(REQUEST.status_code) + " Source ID : " + items + "\n"
	return RESULT

def delete_inactive_host(target, target_cid, user_api_key, target_dc):
	RESULT = ""
	for items in target:
		API_ENDPOINT = "https://publicapi" + target_dc +  "/api/tm/v1/" + target_cid + "/hosts/" + items
		REQUEST = requests.delete(API_ENDPOINT, headers=HEADERS, auth=(user_api_key,''))
		RESULT = RESULT + str(REQUEST.status_code) + " Host ID : " + items + "\n"
	return RESULT
