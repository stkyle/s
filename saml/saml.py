# -*- coding: utf-8 -*-
"""
Created on Sat Nov 08 14:50:03 2014

@author: stkyle
"""


NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
NS_MD = "urn:oasis:names:tc:SAML:2.0:metadata"
NS_DS = "urn:oasis:names:tc:SAML:metadata:ext:query"
ns_ds = "http://www.w3.org/2000/09/xmldsig#"
ns_xenc = "http://www.w3.org/2001/04/xmlenc#"
ns_xs = "http://www.w3.org/2001/XMLSchema"
ns_xsi = "http://www.w3.org/2001/XMLSchema-instance"

nameid_format_entity = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
nameid_format_unspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
hash_alg_xml_exc = "http://www.w3.org/2001/10/xml-exc-c14n#"
hash_alg_rsa_sha1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"


from lxml import etree
from lxml.etree import ElementTree

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


print etree.tostring(SAMLResponse, pretty_print=True)
