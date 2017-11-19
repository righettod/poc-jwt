# Introduction

It's the code repository of the OWASP cheatsheet [JSON Web Token (JWT) Cheat Sheet for Java](https://www.owasp.org/index.php/JSON_Web_Token_(JWT)_Cheat_Sheet_for_Java).

A web page propose the creation, validation and revocation of the token, see the image below:

Get a token:

![Demo1](demo1.png)

Token stored in browser session storage:

![Demo2](demo2.png)

Associated user fingerprint hardened cookie issued to tackle token sidejacking:

![Demo3](demo3.png)

Verification of the token:

![Demo4](demo4.png)

Revocation of the token (logout):

![Demo5](demo5.png)

Verification of the token indicating that the token has been revoked and is not valid anymore:

![Demo5](demo5.png)

All classes are fully documented.

The project was developed with JAX-RS + Maven under IntelliJ IDEA Community Edition.

# Build status

[![Build Status](https://travis-ci.org/righettod/poc-jwt.svg?branch=master)](https://travis-ci.org/righettod/poc-jwt)

# Build or Run

You can also use the **Run Application** running configuration from Intellij project.

Run the following command to create a WAR archive:
```
mvn clean package
```

Run the following command to run the prototype (application will be available on https://localhost:8443):
```
mvn tomcat7:run-war
```
