keycloak-hs
===========

keycloak-hs is a library for connecting to [Keycloak](https://www.keycloak.org/) made in Haskell.
Keycloak allows to authenticate users and protect resources.

Warning: This package is experimental and still under development.

Install
=======

Installation follows the standard approach to installing Stack-based projects.

1. Install the [Haskell `stack` tool](http://docs.haskellstack.org/en/stable/README).
2. Run `stack install --fast` to install this package.

Tutorial
========

In this tutorial we'll learn how to use Keycloak-HS with a [small example](./example/Main.hs).
First you should install and run Keycloak: [follow this tutorial](https://www.keycloak.org/docs/latest/getting_started/index.html).

In Keycloak admin panel, create the following:
- a realm named "demo"
- a user "demo" with password "demo"
- a client named "demo".

In the client:
- change "Access Type" to confidential
- turn "Authorization Enabled" ON.

A new "Authorization" tab should appear.

Authorizations
--------------

Let's set up some authorization policies in order to demonstrate the capacity os Keycloak-HS.
We want to authorize our user "demo" to "view" any resource.

Go in the new "Authorization" tab that appeared.
Create a Scope named "view" in the "Authorization Scopes" tab.

Create a new "User" policy in the "Policies" tab with the following settings:
- Name it "Demo user have access"
- Select user "demo" in the drop box.
- Logic should be positive.

Create a new scope-based permission in the "Permissions" tab:
- Name it "View resources"
- Select "view" in Scopes
- Select your previous policy "Demo user have access" in "Apply Policy".

That's it for the confguration of Keycloak. Keycloak is very complex, so you'll have fun exploring all the possibilities ;)

Example
-------

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
