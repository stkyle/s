"""
Simple Client Example for TAXII Service
"""
import libtaxii.messages_11 as tm11
from lxml import etree
import requests
import datetime
import OpenSSL
import uuid

print(__doc__)

###############################################################################
# TAXII Services API URLs #####################################################
###############################################################################
DISCOVERY = "http://taxiitest.mitre.org/services/discovery"
POLL = "http://taxiitest.mitre.org/services/poll/"

###############################################################################
# TAXII Binding ID's ##########################################################
###############################################################################
TAXII_SERVICES = "urn:taxii.mitre.org:services:1.1"
TAXII_PROTOCOL = "urn:taxii.mitre.org:protocol:http:1.0"
TAXII_MESSAGES = "urn:taxii.mitre.org:message:xml:1.1"

###############################################################################
# TAXII Discovery Request #####################################################
###############################################################################
message_id = 'steve-%s' % uuid.uuid4()
discovery_request = tm11.DiscoveryRequest(message_id)
discovery_xml = discovery_request.to_xml()
print discovery_request.to_text()

###############################################################################
# TAXII HTTP Request Binding ##################################################
###############################################################################
s = requests.Session()
headers = {
    'x-taxii-content-type': TAXII_MESSAGES,
    'x-taxii-protocol': TAXII_PROTOCOL,
    'content-type': 'application/xml',
    'accept': 'application/xml',}

req = requests.Request(method='POST', url=DISCOVERY,
                       auth=None, headers=headers,
                       data=discovery_xml)
http_post = req.prepare()

###############################################################################
# TAXII Request Submit & Receive ##############################################
###############################################################################
http_resp = s.send(http_post,
                   verify=None,
                   cert=None,
                   timeout=None)

###############################################################################
# Display HTTP Response #######################################################
###############################################################################
print('HTTP Response Status: ' + str(http_resp.status_code))
print('HTTP Response Header:')
for k, v in sorted(http_resp.headers.iteritems()):
    sep = (28 - len(k)) * ' '
    print('    %s: %s %s' % (k, sep, v))

###############################################################################
# Display TAXII Response ######################################################
###############################################################################
print('HTTP Response Body (TAXII Message): ')
taxii_response = tm11.get_message_from_xml(http_resp.text)
# print etree.tostring(taxii_response.to_etree(), pretty_print=True)
print(taxii_response.to_text())


