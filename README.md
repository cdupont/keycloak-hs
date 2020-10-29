Keycloak-hs
===========

Keycloak-hs is an Haskell library for connecting to [Keycloak](https://www.keycloak.org/).
Keycloak allows to authenticate and manage users and to protect API resources.
This library allows you to retrieve and analyse Keycloak authentication tokens, and to protect resources in your API.

Install
=======

Installation follows the standard approach to installing Stack-based projects.

1. Install the [Haskell `stack` tool](http://docs.haskellstack.org/en/stable/README).
2. Run `stack install --fast` to install this package.

Tutorial
========

In this tutorial, we'll configure Keycloak for running our [small example](./examples/Main.hs).
First you should install and run Keycloak: [follow this tutorial](https://www.keycloak.org/docs/latest/getting_started/index.html).

The example is compiled and run this way:
```
$ stack install
$ example
```

But before running it, we should create a Client in Keycloak and retrieve the adapter config file.
In Keycloak admin panel, create the following:
- a realm named "demo"
- a client named "demo".

This file is now downloadable in your Client/Installation tab (JSON format).
Place it in this folder.

Authentication
--------------

Authentication with Keycloak is based on [JWTs](https://jwt.io/).

In Keycloak, create a user named "demo" with password "demo". 
Make sure that your user is enable, email verified, and the password is not temporary.
At this point, you should be able to retrieve tokens from Keycloak, verify them using this library, and extract a User from the tokens.

Additionaly, you can add attributes to your user. In Keycloak UI, go in the User Attributes tab and add an attribute, such as "phone".
In order for this attribute to appear in the token claims, we should also add a client "mapper".
In the client "demo", click on "Mappers"/"add mappers".
Fill the name="phone", Mapper Type=User attribute, Token Claim Name="phone", Claim JSON Type=String, and save.

Authorizations
--------------

Keycloak can also manage your resources and related access policies.
The idea is that, each time a user makes a request on your application, you will ask Keycloak "Can he really do that??".

In the client "demo":
- change "Access Type" to confidential
- turn "Authorization Enabled" ON.

A new "Authorization" tab should appear.

Let's set up some authorization policies in order to demonstrate the capacity of Keycloak-hs.
We want to authorize our user "demo" to "view" any resource.
First go in the new "Authorization" tab that appeared.
Flip ON "Remote Resource Management".

Create a new Scope in the "Authorization Scopes" tab:
- Name it "view".

Create a new "User" policy in the "Policies" tab with the following settings:
- Name it "Demo user have access".
- Select user "demo" in the drop box.
- Logic should be positive.

Create a new scope-based permission in the "Permissions" tab:
- Name it "View resources".
- Select "view" in Scopes.
- Select your previous policy "Demo user have access" in "Apply Policy".

That's it for the confguration of Keycloak.
You are now able to play with the "Authorization" part of the example.
Keycloak is very complex, so you'll have fun exploring all the possibilities ;)

Enjoy!
