# -*- coding: utf-8 -*-
"""
Created on Sat Sep 13 12:48:56 2014

@author: stkyle

Encryption
Key - Exchange Method
Cypher - Encrypting
Hash - Message Authentication

Master Secret Code

"""
import ssl
import uuid
from lxml import etree
from Crypto.Util.asn1 import DerSequence
from Crypto.PublicKey import RSA
from binascii import a2b_base64
###ssl.PEM_cert_to_DER_cert('PEM_cert_string')
# Extract subjectPublicKeyInfo field from X.509 certificate (see RFC3280)
#cert = DerSequence()
#cert.decode(der)
#tbsCertificate = DerSequence()
#tbsCertificate.decode(cert[0])
#subjectPublicKeyInfo = tbsCertificate[6]

# Initialize RSA key
#rsa_key = RSA.importKey(subjectPublicKeyInfo)
#OpenSSL.crypto.X509
#https://www.v13.gr/blog/?p=303

print("\n\n")
nameid_format_entity = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
nameid_format_unspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"

hash_alg_xml_exc = "http://www.w3.org/2001/10/xml-exc-c14n#"
hash_alg_rsa_sha1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
ns_saml = "urn:oasis:names:tc:SAML:2.0:assertion"
ns_samlp = "urn:oasis:names:tc:SAML:2.0:protocol"
ns_saml2 = "ojj"
ns_samlp2 = "opp"
ns_metadata = "urn:oasis:names:tc:SAML:2.0:metadata"
ns_sig = "http://www.w3.org/2000/09/xmldsig#"
xsi = 'http://www.host.org/2001/XMLSchema-instance'


nsmap = {
    'saml': ns_saml,
    'samlp': ns_samlp,
    'md': ns_metadata,
    'ds': ns_sig,
    'xsi': xsi,
    }

SAMLObject = etree.Element("SAMLObject", nsmap=nsmap)

SAMLResponse = etree.SubElement(SAMLObject,"{%s}Response" % ns_samlp)
SAMLResponse.set("ID", "Huhu")
SAMLResponse.set("IssueInstant", "Huhu")
SAMLResponse.set("Version", "Huhu")
if 1:
    Issuer = etree.SubElement(SAMLResponse, "{%s}Issuer" % ns_saml)
    Issuer.set("Format", "Huhu")
    Issuer.text = "Text"
    Status = etree.SubElement(SAMLResponse, "{%s}Status" % ns_samlp)
    Status.set("Format", "Huhu")
    Status.text = "Text"
    Assertion = etree.SubElement(SAMLResponse, "{%s}Assertion" % ns_saml)
    Assertion.set("ID", "Huhu")
    Assertion.set("IssueInstant", "Huhu")
    Assertion.set("Version", "2.0")
    if 2:
        Issuer = etree.SubElement(Assertion, "{%s}Issuer" % ns_saml)
        Issuer.set("Format", nameid_format_entity)
        Issuer.text = "Text"
        Signature = etree.SubElement(Assertion, "{%s}Signature" % ns_saml)
        if 3:
            SignedInfo = etree.SubElement(Signature, "{%s}SignedInfo" % ns_saml)
            if 4:
                CanonicalizationMethod = etree.SubElement(SignedInfo, "{%s}CanonicalizationMethod" % ns_saml)    
                CanonicalizationMethod.set("Algorithm",hash_alg_xml_exc )
                SignatureMethod = etree.SubElement(SignedInfo, "{%s}SignatureMethod" % ns_saml)    
                SignatureMethod.set("Algorithm",hash_alg_rsa_sha1)            
                Reference = etree.SubElement(SignedInfo, "{%s}Reference" % ns_saml) 
                Reference.set("URI","#_3c39bc0fe7b13769cab2f6f45eba801b1245264310738")
                if 5:
                    Transforms = etree.SubElement(Reference, "{%s}Transforms" % ns_saml)
                    if 6:
                        Transform = etree.SubElement(Transforms, "{%s}Transform" % ns_saml)    
                        Transform.set("Algorithm",hash_alg_rsa_sha1)                  
                        Transform = etree.SubElement(Transforms, "{%s}Transform" % ns_saml)    
                        Transform.set("Algorithm",hash_alg_rsa_sha1) 
                        
                    DigestMethod = etree.SubElement(Reference, "{%s}DigestMethod" % ns_saml)
                    DigestMethod.set("Algorithm",hash_alg_rsa_sha1) 
                    DigestValue = etree.SubElement(Reference, "{%s}DigestValue" % ns_saml)
                    DigestValue.text = str(uuid.uuid4())
            SignatureValue = etree.SubElement(Signature, "{%s}SignatureValue" % ns_saml)
            KeyInfo = etree.SubElement(Signature, "{%s}KeyInfo" % ns_saml)
            if 4:
                X509Data = etree.SubElement(KeyInfo, "{%s}X509Data" % ns_saml)
                if 5:
                    X509Certificate = etree.SubElement(X509Data, "{%s}X509Certificate" % ns_saml)                
    if 2:
        Subject = etree.SubElement(Assertion, "{%s}Subject" % ns_saml)
        if 3:
            NameID = etree.SubElement(Subject, "{%s}NameID" % ns_saml)
            NameID.set("Format", nameid_format_unspecified)
            NameID.text = "name"
    if 2:
        AttributeStatement = etree.SubElement(Assertion, "{%s}AttributeStatement" % ns_saml)
        if 3:
            Attribute = etree.SubElement(AttributeStatement, "{%s}Attribute" % ns_saml)
            Attribute.set("Name", "User Attribute #1")
            Attribute.set("FriendlyName", "User Attribute #1-FriendlyName")
            Attribute.set("NameFormat", nameid_format_unspecified)
            if 4:
                AttributeValue = etree.SubElement(Attribute, "{%s}AttributeValue" % ns_saml)
                AttributeValue.set("{%s}type" % xsi, "xs:anyType")            
                AttributeValue.text = "AAAAAAAAAAA"
                
            Attribute = etree.SubElement(AttributeStatement, "{%s}Attribute" % ns_saml)
            Attribute.set("Name", "User Attribute #2")
            if 4:
                AttributeValue = etree.SubElement(Attribute, "{%s}AttributeValue" % ns_saml)
                AttributeValue.set("{%s}type" % xsi, "xs:anyType")            
                AttributeValue.text = "BBBBBBBBBB"                

            Attribute = etree.SubElement(AttributeStatement, "{%s}Attribute" % ns_saml)
            Attribute.set("Name", "User Attribute #3")
            if 4:
                AttributeValue = etree.SubElement(Attribute, "{%s}AttributeValue" % ns_saml)
                AttributeValue.set("{%s}type" % xsi, "xs:anyType")            
                AttributeValue.text = "CCCCCCCCCCC"    
                
#<samlp:Response ID="_f97faa927f54ab2c1fef230eee27cba21245264205456" 
#      IssueInstant="2009-06-17T18:43:25.456Z" Version="2.0">
#   <saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">
#      https://www.salesforce.com</saml:Issuer>
#
#   <samlp:Status>
#      <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
#   </samlp:Status>
#
#   <saml:Assertion ID="_f690da2480a8df7fcc1cbee5dc67dbbb1245264205456"
#      IssueInstant="2009-06-17T18:45:10.738Z" Version="2.0">
#      <saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">
#         https://www.salesforce.com
#      </saml:Issuer>
#
#      <saml:Signature>
#         <saml:SignedInfo>
#            <saml:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
#            <saml:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
#            <saml:Reference URI="#_f690da2480a8df7fcc1cbee5dc67dbbb1245264205456">
#               <saml:Transforms>
#                  <saml:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
#                  <saml:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
#                     <ec:InclusiveNamespaces PrefixList="ds saml xs"/>
#                  </saml:Transform>
#               </saml:Transforms>
#               <saml:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
#               <saml:DigestValue>vzR9Hfp8d16576tEDeq/zhpmLoo=
#               </saml:DigestValue>
#            </saml:Reference>
#         </saml:SignedInfo>
#         <saml:SignatureValue>
#         
         
print etree.tostring(SAMLResponse, pretty_print=True)






from OpenSSL import crypto, SSL
from socket import gethostname
from pprint import pprint
from time import gmtime, mktime
 
CERT_FILE = "selfsigned.crt"
KEY_FILE = "private.key"
 
def create_self_signed_cert():
             
        # create a key pair
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 1024)
 
        # create a self-signed cert
        cert = crypto.X509()
        cert.get_subject().C = "US"
        cert.get_subject().ST = "DC"
        cert.get_subject().L = "Washington"
        cert.get_subject().O = "Dummy Company Ltd"
        cert.get_subject().OU = "Dummy Company Ltd"
        cert.get_subject().CN = gethostname()
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10*365*24*60*60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha1')
 
        open(CERT_FILE, "wt").write(
            crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        open(KEY_FILE, "wt").write(
            crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
 
create_self_signed_cert()



with open(CERT_FILE) as f:
    cert_buffer = f.read()


print cert_buffer

myX509cert=crypto.load_certificate(crypto.FILETYPE_PEM,cert_buffer)
public_key = myX509cert.get_pubkey()
pubk_str = crypto.dump_privatekey(crypto.FILETYPE_TEXT,public_key)



mySubjectCert=myX509cert.get_subject()
#print mySubjectCert.get_components()
print dict(mySubjectCert.get_components())
#from Crypto.PublicKey import RSA
from Crypto.Util.asn1 import DerSequence




