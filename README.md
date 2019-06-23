# Getting Started

Library for Keycloak JSON Web Token validation


### Reference Documentation
To be able to use this lib following actions are required

*	To install KeyCloak IdP and configure client [https://www.keycloak.org]
*	To import IdP certificate (KeyCloak in this case) execute following command:
*	To change keycloak.properties values with regards to KeyCloak configuration

### JAVA certificate import
keytool -import -trustcacerts -keystore <path_to_cacerts> -storepass changeit -alias keycloak -file <path_to_cert>

