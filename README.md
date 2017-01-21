# Objective

This project is a prototype about usage of [JSON Web Tokens](https://jwt.io/introduction/) (JWT) in a secure way in order to prevent the following common type of issues:

* Token replay after stealing,
* Information disclosure by the token,
* *None* algorithm issue: 
    * https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
* Token storage on client side,
* Alteration of the ciphered token in order to perform cryptanalysis.

It's a research in order to create an article on OWASP Wiki.
 
# Description
 
This POC is a web application with 2 REST services:

 * One to [create](src/main/java/eu.righettod/pocjwt/service/TokenServices.java) the JWT token and [cipher](src/main/java/eu.righettod/pocjwt/crypto/TokenCipher.java) it,
 * One to [validate](src/main/java/eu.righettod/pocjwt/service/TokenServices.java) it.
 
A web page propose the creation and the validation of the token.

All classes are full documented.

The project was developed with JAX-RS + Maven under IntelliJ IDEA CE.
 
# Build or Run

Run the following command to create a WAR archive:
```
mvn clean package
```

Run the following command to run the prototype:
```
mvn tomcat7:run-war
```

# Main references

* JWT - https://jwt.io/introduction/
* GCM - https://en.wikipedia.org/wiki/Galois/Counter_Mode
* AES-GCM - https://tools.ietf.org/html/rfc5084