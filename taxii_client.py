"""
Sample TAXII Calls
"""
import libtaxii.messages_11 as tm11
from lxml import etree
import requests
import datetime
import OpenSSL
import uuid

"""
The Discovery Service is the mechanism for communicating information related
to the availability and use of TAXII Services. The Discovery Service provides
a requester with a list of TAXII Services and how these Services can be invoked
(i.e., the address of the TAXII Daemon that implements that service and the
bindings that Daemon supports). A single Discovery Service might report on
TAXII Services hosted byTAXII Daemons on multiple endpoints or even across
multiple organizations - the owner of a Discovery Service can define its scope
as they wish, as long as they comply with legal, ethical, and other
considerations. A Discovery Service is not required to disclose all TAXII
Services of which it is aware; a Discovery Service can use a variety of factors
to determine which Services to disclose to the requester, including but not
limited to the requester's identity. In order to facilitate automation, each
TAXII Protocol Binding Specification defines a recommended default address for
the Discovery Service."""

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
extended_headers = {'profile': 'saml'}
discovery_request = tm11.DiscoveryRequest(message_id,
                                          extended_headers=extended_headers)
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
    print('    %s: %s %s' % (k,sep,v))

###############################################################################
# Display TAXII Response ######################################################
###############################################################################
print('HTTP Response Body (TAXII Message): ')
taxii_response = tm11.get_message_from_xml(http_resp.text)
# print etree.tostring(taxii_response.to_etree(), pretty_print=True)
print taxii_response.to_text()

service_options = {}
service_instance_list = taxii_response.service_instances
for service in service_instance_list:
    print service.service_type
    service_options[service.service_type] = service



"""
The Poll service is the mechanism by which a TAXII consumers can pull data from
a TAXII Data Feed. The Poll service can be accessed by transmitting a Poll
request to the /services/poll/ location of this YETI installation. The name of
the TAXII Data Feed for the Poll request is contained within the TAXII message
itself and not specified within the URL. To Poll data from the default Data
Feed established by a quickstart YETI instance, a TAXII client would transmit
a Poll request to http://localhost/services/poll/. YETI comes bundled with a
poll_client.py script to serve as a demonstration of the Poll service. This
script is located in the scripts directory of your YETI installation."""
###############################################################################
# TAXII Poll Request ##########################################################
###############################################################################
poll_service = service_options['POLL']
poll_url = poll_service.service_address
ext_headers = {'name1': 'val1', 'name2': 'val2'}

pp = tm11.PollParameters(response_type='FULL', content_bindings=None,
                         query=None, allow_asynch=False,
                          delivery_parameters=None)
message_id = str(uuid.uuid4())
# NOTE: Collection Identified Explicitly
pr = tm11.PollRequest(message_id, in_response_to=None,
                      extended_headers=None,
                      collection_name='default',
                      exclusive_begin_timestamp_label=None,
                      inclusive_end_timestamp_label=None,
                      subscription_id=None,
                      poll_parameters=pp)

print pr
###############################################################################
# TAXII HTTP Request Binding ##################################################
###############################################################################
headers = {
    'x-taxii-content-type': TAXII_MESSAGES,
    'x-taxii-protocol': TAXII_PROTOCOL,
    'content-type': 'application/xml',
    'accept': 'application/xml',}

req = requests.Request(method='POST', url=poll_url,
                       auth=None, headers=headers,
                       data=pr.to_xml())
http_post = req.prepare()

###############################################################################
# TAXII Request Submit & Receive ##############################################
###############################################################################
http_resp = s.send(http_post,
                   verify=None,
                   cert=None,
                   timeout=None)


print http_resp
###############################################################################
# Display HTTP Response #######################################################
###############################################################################
print('HTTP Response Status: ' + str(http_resp.status_code))
print('HTTP Response Header:')
for k, v in sorted(http_resp.headers.iteritems()):
    sep = (28 - len(k)) * ' '
    print('    %s: %s %s' % (k,sep,v))

###############################################################################
# Display TAXII Response ######################################################
###############################################################################
print('HTTP Response Body (TAXII Message): ')
taxii_response = tm11.get_message_from_xml(http_resp.text)
# print etree.tostring(taxii_response.to_etree(), pretty_print=True)
print taxii_response.to_text()
print taxii_response
