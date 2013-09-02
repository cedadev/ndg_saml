ndg_saml
========
SAML 2.0 implementation for use with the Earth System Grid Federation Attribute 
and Authorisation Query interfaces.  The implementation is based on the Java 
OpenSAML libraries.  An implementation is provided with ``ElementTree`` but it can 
easily be extended to use other Python XML parsers.

 * 0.7.0 - add command line script for making attribute and authorisation decision
        query client calls.
        
 * 0.6.0 (Thanks to Richard Wilkinson for these contributions)
      - added support for SAML 2.0 profile of XACML v2.0 (http://docs.oasis-open.org/xacml/2.0/access_control-xacml-2.0-saml-profile-spec-os.pdf),
        specifically the SAML request extensions: XACMLAuthzDecisionQuery and 
        XACMLAuthzDecisionStatement.  This an alternative to the SAML defined
        AuthzDecisionQuery.  It enables a richer functionality for expressing
        queries and authorisation decisions taking advantage of the full
        capabilities of a XACML PDP.
      - fixed bug in SAML SOAP binding code: RequestBaseSOAPBinding and derived 
        classes to act as a query factory, instead of container, for thread 
        safety.
        
 * 0.5.5 - allow passing a client certificate chain in client HTTPS requests

 * 0.5.4 - fix for ndg.saml.saml2.binding.soap.server.wsgi.queryinterface.SOAPQueryInterfaceMiddleware:
bug in issuerFormat property setter - setting issuerName value

 * 0.5.3 - fix for ndg.soap.utils.etree.prettyPrint for undeclared Nss.

 * 0.5.2 - fix for applying clock skew property in queryinterface WSGI middleware,
and various minor fixes for classfactory module and m2crytpo utilities.

 * 0.5.1 - fix for date time parsing where no seconds fraction is present, fixed
error message for InResponseTo ID check for Subject Query.

 * 0.5 - adds WSGI middleware and clients for SAML SOAP binding and assertion
query/request profile.

It is not a complete implementation of SAML 2.0.  Only those components required
for the NERC DataGrid have been provided (Attribute and AuthZ Decision Query/
Response).  Where possible, stubs have been provided for other classes.

