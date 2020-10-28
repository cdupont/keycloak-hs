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

In this tutorial we'll learn how to use Keycloak-hs with a [small example](./examples/Main.hs).
First you should install and run Keycloak: [follow this tutorial](https://www.keycloak.org/docs/latest/getting_started/index.html).

Authentication
--------------

Authentication with Keycloak is based on [JWTs](https://jwt.io/).

In Keycloak admin panel, create the following:
- a realm named "demo"
- a client named "demo".
- a user "demo" with password "demo"

In the user, add an attribute, such as "phone".
In order for this attribute to appear in the token claims, we should also add a client "mapper".
In the client "demo", click on "Mappers"/"add mappers".
Fill the name="demo", Mapper Type=User attribute, Token Claim Name="demo", Claim JSON Type=String, and save.

At this point, you should be able to retrieve tokens from Keycloak, verify them using this library, and extract a User from the tokens.

Authorizations
--------------

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

That's it for the confguration of Keycloak. Keycloak is very complex, so you'll have fun exploring all the possibilities ;)

Example code
-----------

The folder example contains an [exemple of usage](./examples/Main.hs).
You should first input your "client secret", that can be found in the demo client "Credentials" tab in Keycloak admin panel.

Then run the example:
```
stack run example
```

The example first create a "client" token, necessary to create a resource in Keycloak.
It then create a Resourse, with a name, an optional type, URIs, scopes, owner and attributes.

We can then check if our user can access this resource, according to policies.
Finally, the example shows how to retrieve all permissions for a user.

Enjoy!
