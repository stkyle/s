# -*- coding: utf-8 -*-
"""
Created on Sat Nov 08 14:50:03 2014

@author: stkyle
"""
#from lxml.etree import ElementTree
from lxml import etree
import datetime
import uuid

t = datetime.datetime.utcnow()
date_issuance_responce = t.isoformat()
response_id = str(uuid.uuid1())
my_signature = """
         M/CbLHbBUVT5TcxIqvsNvIFdjIGNkf1W0SBqRKZOJ6tzxCcLo
         9dXqAyAUkqDpX5+AyltwrdCPNmncUM4dtRPjI05CL1rRaGeyX
         3kkqOL8p0vjm0fazU5tCAJLbYuYgU1LivPSahWNcpvRSlCI4e
         Pn2oiVDyrcc4et12inPMTc2lGIWWWWJyHOPSiXRSkEAIwQVjf
         Qm5cpli44Pv8FCrdGWpEE0yXsPBvDkM9jIzwCYGG2fKaLBag==
         """
cert_text = """
             AzID5hhJeJlG2llUDvZswNUrlrPtR7S37QYH2W+Un1n8c6kTC
             Xr/lihEKPcA2PZt86eBntFBVDWTRlh/W3yUgGOqQBJMFOVbhK
             M/CbLHbBUVT5TcxIqvsNvIFdjIGNkf1W0SBqRKZOJ6tzxCcLo
             9dXqAyAUkqDpX5+AyltwrdCPNmncUM4dtRPjI05CL1rRaGeyX
             3kkqOL8p0vjm0fazU5tCAJLbYuYgU1LivPSahWNcpvRSlCI4e
             Pn2oiVDyrcc4et12inPMTc2lGIWWWWJyHOPSiXRSkEAIwQVjf
             Qm5cpli44Pv8FCrdGWpEE0yXsPBvDkM9jIzwCYGG2fKaLBag==
         """
NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
NS_MD = "urn:oasis:names:tc:SAML:2.0:metadata"
NS_QUERY = "urn:oasis:names:tc:SAML:metadata:ext:query"
NS_DS = "http://www.w3.org/2000/09/xmldsig#"
NS_XENC = "http://www.w3.org/2001/04/xmlenc#"
NS_XS = "http://www.w3.org/2001/XMLSchema"
NS_XSI = "http://www.w3.org/2001/XMLSchema-instance"

NAMEID_FMT_ENTITY = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
NAMEID_FMT_UNSPEC = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
NAMEID_FMT_PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
NAMEID_FMT_TRANSIENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
NAMEID_FMT_EMAIL = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
NAMEID_FMT_X509 = "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName"
NAMEID_FMT_KERBEROS = "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos"

HASH_ALG_XML_EXC = "http://www.w3.org/2001/10/xml-exc-c14n#"
HASH_ALG_RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"

nsmap = {}
nsmap['saml'] = NS_SAML
nsmap['samlp'] = NS_SAMLP
nsmap['md'] = NS_MD
nsmap['query'] = NS_QUERY
nsmap['ds'] = NS_DS
nsmap['xenc'] = NS_XENC
nsmap['xs'] = NS_XS
nsmap['xsi'] = NS_XSI

SAMLObject = etree.Element("SAMLObject", nsmap=nsmap)

SAMLResponse = etree.SubElement(SAMLObject, "{%s}Response" % NS_SAMLP)
SAMLResponse.set("ID", response_id)
SAMLResponse.set("IssueInstant", date_issuance_responce)
SAMLResponse.set("Version", str(2.0))

if(1):
    Issuer = etree.SubElement(SAMLResponse, "{%s}Issuer" % NS_SAML)
    Issuer.set("Format", "Huhu")
    Issuer.text = "Text"

    Status = etree.SubElement(SAMLResponse, "{%s}Status" % NS_SAMLP)
    Status.set("Format", "Huhu")
    Status.text = "Text"

    Assertion = etree.SubElement(SAMLResponse, "{%s}Assertion" % NS_SAML)
    Assertion.set("ID", "Unique ID given to a SAML Assertion")
    Assertion.set("IssueInstant", "Datetime of Assertion Issuance")
    Assertion.set("Version", str(2.0))

    if(2):
        Issuer = etree.SubElement(Assertion, "{%s}Issuer" % NS_SAML)
        Issuer.set("Format", NAMEID_FMT_ENTITY)
        Issuer.text = "Text"
        Signature = etree.SubElement(Assertion, "{%s}Signature" % NS_SAML)
        if(3):
            SignedInfo = etree.SubElement(Signature,
                                          "{%s}SignedInfo" % NS_SAML)
            if(4):
                CanonicalizationMethod = \
                    etree.SubElement(SignedInfo,
                                     "{%s}CanonicalizationMethod" % NS_SAML)
                CanonicalizationMethod.set("Algorithm", HASH_ALG_XML_EXC)
                SignatureMethod = \
                    etree.SubElement(SignedInfo,
                                     "{%s}SignatureMethod" % NS_SAML)
                SignatureMethod.set("Algorithm",HASH_ALG_RSA_SHA1)
                Reference = etree.SubElement(SignedInfo,
                                             "{%s}Reference" % NS_SAML)
                Reference.set("URI","#_3c39bc0fe7b145264310738")
                if(5):
                    Transforms = etree.SubElement(Reference,
                                                  "{%s}Transforms" % NS_SAML)
                    if(6):
                        Transform = etree.SubElement(Transforms, "{%s}Transform" % NS_SAML)
                        Transform.set("Algorithm", HASH_ALG_RSA_SHA1)
                        Transform = etree.SubElement(Transforms, "{%s}Transform" % NS_SAML)
                        Transform.set("Algorithm", HASH_ALG_XML_EXC)

                    DigestMethod = etree.SubElement(Reference, "{%s}DigestMethod" % NS_SAML)
                    DigestMethod.set("Algorithm", HASH_ALG_RSA_SHA1)
                    DigestValue = etree.SubElement(Reference, "{%s}DigestValue" % NS_SAML)
                    DigestValue.text = str(uuid.uuid4())
            SignatureValue = etree.SubElement(Signature, "{%s}SignatureValue" % NS_SAML)
            SignatureValue.text = my_signature
            KeyInfo = etree.SubElement(Signature, "{%s}KeyInfo" % NS_SAML)
            if 4:
                X509Data = etree.SubElement(KeyInfo, "{%s}X509Data" % NS_SAML)
                if 5:
                    X509Certificate = etree.SubElement(X509Data, "{%s}X509Certificate" % NS_SAML)
                    X509Certificate.text = cert_text
    if 2:
        Subject = etree.SubElement(Assertion, "{%s}Subject" % NS_SAML)
        if 3:
            NameID = etree.SubElement(Subject, "{%s}NameID" % NS_SAML)
            NameID.set("Format", NAMEID_FMT_UNSPEC)
            NameID.text = "name"
    if 2:
        AttributeStatement = etree.SubElement(Assertion, "{%s}AttributeStatement" % NS_SAML)
        if 3:
            Attribute = etree.SubElement(AttributeStatement, "{%s}Attribute" % NS_SAML)
            Attribute.set("Name", "User Attribute #1")
            #Attribute.set("FriendlyName", "User Attribute #1-FriendlyName")
            Attribute.set("NameFormat", NAMEID_FMT_UNSPEC)
            if 4:
                AttributeValue = etree.SubElement(Attribute, "{%s}AttributeValue" % NS_SAML)
                AttributeValue.set("{%s}type" % NS_XSI, "xs:anyType")
                AttributeValue.text = "AAAAAAAAAAA"

            Attribute = etree.SubElement(AttributeStatement, "{%s}Attribute" % NS_SAML)
            Attribute.set("Name", "User Attribute #2")
            if 4:
                AttributeValue = etree.SubElement(Attribute, "{%s}AttributeValue" % NS_SAML)
                AttributeValue.set("{%s}type" % NS_XSI, "xs:anyType")
                AttributeValue.text = "BBBBBBBBBB"

            Attribute = etree.SubElement(AttributeStatement, "{%s}Attribute" % NS_SAML)
            Attribute.set("Name", "User Attribute #3")
            if 4:
                AttributeValue = etree.SubElement(Attribute, "{%s}AttributeValue" % NS_SAML)
                AttributeValue.set("{%s}type" % NS_XSI, "xs:anyType")
                AttributeValue.text = "CCCCCCCCCCC"


print etree.tostring(SAMLResponse, pretty_print=True)


