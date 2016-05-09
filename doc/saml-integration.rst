============================================
Ipsilon - Web Application Integration (SAML)
============================================

Ipsilon allows web applications to consume users from existing identity
management systems, even those that it doesn't have direct access to.

Traditionally, web applications have their own user database, or they directly
interact with a centralized identity management system such as an LDAP server.
Both of these approaches put a lot of responsibility on the web application
itself.  Let's consider some of the issues around these two approaches.

Local user database:

* User management interfaces need to be developed.
* User accounts are local to the application, leading to users having
  different passwords for different applications.
* Authentication is often password based, which is not ideal from a security
  perspective.
* Scalability and replication of the database become the responsibility of the
  web application developers.

LDAP server:

* Users and credentials are centralized, but we don't get true single sign-on.
* Authentication is often password based, which is not ideal from a security
  perspective.
* The web application has to be able to handle the wide variety of LDAP schema
  that deployers may have in their environments.
* The web application needs direct access to the LDAP server.

When using Ipsilon for SAML federation, an application is relieved of the above
burdens.  Ipsilon deals with all of the authentication and lookup of user
information from the centralized identity source.

This document describes the recommended practices for integrating a web
application with Ipsilon to allow for SAML federated single sign-on.


Federated Single Sign-On Concepts
=================================

Before getting into the concepts of SAML federated single sign-on, it is
important to understand some basic terminology:

Identity Provider (IDP)
  A SAML Identity Provider is responsible for authenticating users on behalf of
  other web applications.  The IDP then provides information about
  authenticated users to web applications in the form of assertions.  Ipsilon
  is a SAML IDP.

Service Provider (SP)
  A SAML Service Provider is a web application that is using an IDP to provide
  authentication service and user information.

Assertion
  An assertion is some property about a user that the IDP claims is true.  A
  collection assertions represent a user object, which a web application can
  then use for identification and authorization purposes.

Single Sign-On (SSO)
  Single Sign-On allows a user to authenticate once within some period of time,
  and then access multiple applications without having to authenticate again.

Federated single sign-on (SSO) allows a web application to use identities
from an external identity source that it does not manage, while also having
the benefit of true SSO.

Most organizations already have some form of centralized identity management,
such as an LDAP server.  Having separate identity silos per application is a
frustrating user experience.  Tying a web application directly into a
centralized identity management system is a burden on the web application
developer for the reasons previously mentioned in this document.  SAML
federation allows a web application to be presented with data representing
an authenticated user when that user accesses the application.  This data is
crytographically proven to be from a trusted source, and is provided in an
easy to consume form.  This data can be used by the web application without the
need for the web application to reach out to a central identity management
system.  The web application does not need to know how the user authenticated,
or even where the user information is stored.  This removes a lot of complexity
from the web application itself.

In some cases, the identity management system might not even be accessible by
the web application.  Consider a company that provides a web application as a
paid-for service.  Instead of requiring customers to create users within a
database for the web application, the web application can be configured to
trust a customer's IDP.  The web application never needs to communicate
directly with the IDP or the underlying identity management system, which are
likely behind the customer's firewall.

Authentication Flow
-------------------

The following picture depicts the authentication flow that occurs when using
SAML::

    +---------------+      +---------------+
    |               |      |               |
    |  Application  |      |    Ipsilon    |
    |      (SP)     |      |     (IDP)     |
    |               |      |               |
    +--^----+----^--+      +----^-----+----+
       |    |    |              |     |
      (1)  (2)  (5)            (3)   (4)
       |    |    |              |     |
    +--+----v----+--------------+-----v----+
    |                                      |
    |             Web Browser              |
    |                                      |
    +--------------------------------------+

The steps in the authentication flow are:

  1. A user accesses a protected URL of the web application via browser.

  2. The web application returns a redirect to the user, pointing them to the
     IDP.

  3. The browser follows the redirect to the IDP, where the user is asked to
     authenticate.

  4. Upon successful authentication, the IDP returns a SAML response as a
     part of a form that is set to submit when loaded.

  5. The browser automatically sumbits the returned form, which does a POST
     of the SAML response to the web application.

At the end of the authentication flow, the assertion values contained in the
SAML response are mapped into environment variables by an Apache httpd module
on the SP.  These environment variables are made available to the web
application, where they can be used for user identification, authorization, or
any other purpose that the web application may have.

The nice thing from the web application developers viewpoint is that none of
the above steps are the responsibility of the web application itself.  All of
the work is performed by the browser, an Apache httpd module on the SP, and
the Ipsilon IDP.  The web application only needs to deal with the environment
variable data that is provided to it.


Web Application Integration
===========================

In order for a web application to use Ipsilon for federated SSO, there are a
few things that need to be done.  Its webserver needs to be configured as a
SP, and the web application needs to be able to handle the user data that is
provided to it from the SAML assertions.

Service Provider Configuration
------------------------------

Configuring a web application's webserver as a SP is comprised of a few steps:

* SP key, certificate, and metadata generation
* IDP metadata retrieval
* SP registration
* httpd configuration

A number of the above steps are handled for you by the
``ipsilon-client-install`` utility.  We will still describe the steps here to
provide a thorough understanding of each step, but it is recommended to use the
ipsilon-client-install utility to simplify the configuration procedure.

SAML relies on trusted responses that are sent between the IDP and the SP via
the user's browser.  These responses are cryptographically authenticated and
even have the capability to be encrypted.  This requires key and certificate
generation, and an establishment of trust on both the IDP and the SP.  In
addition to certificate trust, some additional information needs to be
exchanged between the IDP and SP so that each side knows how to communicate
with each other from a SAML perspective.  This information takes the form of an
XML metadata file, and both the IDP and SP need to exchange their metadata
when a SP is being configured.

Using ``ipsilon-client-install`` will generate a key, certificate, and SP
metadata.  If Ipsilon admin user credentials are supplied, it will also send
the SP metadata to Ipsilon to register it as a trusted SP.

The ``ipsilon-client-install`` utility also has the ability to create a basic
Apache httpd configuration, but that is typically only useful for a very basic
new site or experimentation.  For existing web applications, one should tell
``ipsilon-client-install`` to skip the httpd configuration and the
configuration should be performed manually.

Here is a basic example of using ``ipsilon-client-install`` to set up a SP::

    ipsilon-client-install --saml-idp-url https://ipsilon.example.test/idp \
                           --saml-sp-name mysite --saml-auth /sp \
                           --saml-no-httpd

In this example, we are providing a pointer to our Ipsilon IDP, providing a
name for our SP to be used during registration, and specifying the URI where we
want to require SAML authentication (``/sp``).  We are also skipping the httpd
configuration since we will be doing that manually.

If you use a non-standard port for your web application, of if the hostname
that is used to access your web application is not the FQDN,  you will need
to use the ``--hostname`` and ``--port`` options to ensure that the URLs are
correct in the generated metadata.  Note that ``ipsilon-client-install``
currently enforces that https is being used in the URLs it generates.

There are a few other options which may or may not be needed depending on the
exact URIs that you want to use for SAML communication.  The following are the
URIs that ``ipsilon-client-install`` will set in the SP metadata:

base
  This is the URI where SAML assertion data will be made available to the web
  application if it is present.  The default is ``/``, but it can be set with the
  ``--saml-base`` option.

auth
  This is the URI where SAML authentication is required.  This URI must be
  beneath the base URI.  Accessing this URI will trigger the authentication
  flow described above.  The browser will then return to this URI upon
  successful authentication.  This should typically be set to the "Log In" URI
  of your web application.  It defaults to ``/protected``, but it can be
  set with the ``--saml-auth`` option.

endpoint
  This is the URI where SAML communication will occur.  This URI must be
  beneath the base URI.  This is not an actual URI within your web
  application, as the httpd module will be handling communication for this URI.
  The default is ``/saml2``, but it can be set with the ``--saml-sp`` option.

logout
  This is the URI where SAML logout will be triggered.  This URI must be
  beneath the endpoint URI.  This is not an actual URI within your web
  application, as the httpd module will be handling communication for this URI.
  The default is ``/saml2/logout``, but it can be set with the
  ``--saml-sp-logout`` option.  More detail about how the logout URI is used
  are provided in the `Logout Handling`_ section below.

post
  This is the URI where SAML responses from the IDP will be posted.  This URI
  must be beneath the endpoint URI.  This is not an actual URI within your web
  application, as the httpd module will be handling communication for this URI.
  The default is ``/saml2/postResponse``, but if can be set with the
  ``--saml-sp-post`` option.

You will typically only need to specify the auth URI option above, unless you
have a reason to change the base URI (which will affect all of the other URIs
since they all must be beneath the base).

You can download the IDP metadata from Ipsilon.  Assuming that the IDP name of
Ipsilon is the default of ``idp``, the metadata can be accessed at::

    ``https://<ipsilon FQDN>/idp/saml2/metadata``

You will need to save this metadata for configuring httpd in the next step.

Apache HTTPD Config
-------------------

The handling of SAML in httpd is taken care of by the `mod_auth_mellon`_
module.  The first step in ensuring that you are loading the mod_auth_mellon
library.  This will look something like this::

    LoadModule auth_mellon_module /usr/lib64/httpd/modules/mod_auth_mellon.so

You will need to ensure that the ``Location`` directive that matches the base
URI we specified during metadata creation contains the proper Mellon
directives.  This ``Location`` directive is where we specify the key and
certificate that the SP is using, the trusted IDP metadata, and the endpoint
URI to use for SAML communication.  Here is an example of the base URI
``Location`` directive::

    <Location />
      MellonEnable "info"
      MellonSPPrivateKeyFile /etc/httpd/saml2/mysite/certificate.key
      MellonSPCertFile /etc/httpd/saml2/mysite/certificate.pem
      MellonSPMetadataFile /etc/httpd/saml2/mysite/metadata.xml
      MellonIdPMetadataFile /etc/httpd/saml2/mysite/idp-metadata.xml
      MellonEndpointPath /saml2
      MellonIdP "IDP"
    </Location>

The ``MellonEnable`` directive with a value of ``info`` means that assertion
data will be made available to the web application at this location if it is
present.  If a user has not authenticated via SAML, they will be allowed into
your site, but no assertion data will be present to provide.  Typically, this
location will encompass your entire web application and you will have an
additional protected location at your "Log In" URI that triggers the
authentication flow.

The ``MellonSP*`` directives tell mod_auth_mellon about the SP that it is
representing.  These directives point to the key, certificate, and metadata
that was generated by ``ipsilon-client-install``.

The ``MellonIdPMetadataFile`` directive points to the IDP metadata that you
downloaded from the IDP.  The IDP metadata contains the certificate of the IDP,
so it is used to validate the signature of the responses that come from the
IDP.  In effect, this is how the trust of the IDP is configured for your SP.
The IDP metadata also contains the URL of the IDP, which is used when
redirecting users to the IDP to perform authentication.

The ``MellonEndpointPath`` directive must match the endpoint URI that was used
when generating the metadata with ``ipsilon-client-install``.

The ``MellonIdP`` directive is used to expose an IDP identifier to your web
application via an environment variable.  The value of this directive is used
to indicate the name of the environment variable.

You also need to configure your auth URI to require authentication via
mod_auth_mellon.  This is done by adding the ``AuthType`` and ``MellonEnable``
directives within the ``Location`` directive that matches your auth URI.  Here
is an example of the auth URI ``Location`` directive::

    <Location /sp>
      AuthType "Mellon"
      MellonEnable "auth"
    </Location>

With these changes, you should be able to access your auth URI, which will
trigger the authentication flow that was previously described.  The browser
will be returned to the auth URI, and values contained in the SAML assertion
will be exposed to your web application as environment variables.  To do
anything useful, your application will have to know how to consume this
assertion data.

Consuming Assertion Data
------------------------
A web application will typically need changes to allow it to make use of the
environment variables that are provided by mod_auth_mellon.  Making these
changes even has value outside of Ipsilon, as it allows your web application to
support external authentication and user info as described in the
`Web App Authentication`_ page on the FreeIPA wiki.  It will ultimately make
your web application more flexible as new authentication and federation methods
emerge.

The provided environment variables fall into two main categories.  A user
identifier, and other information about the user.

If your web application only needs to know who the user is and nothing else
about the user, it's quite possible that no changes are needed in your
application.  This is because the user identifier is provided as the
``REMOTE_USER`` environment variable, which is commonly used by other httpd
authentication modules.

Quite often, the ``REMOTE_USER`` environment variable isn't enough.  It is
common for a web application to want more information about a user, such as
their e-mail address, their full name, and the groups that they are a member
of.  Depending on how the Ipsilon IDP is configured, all of this information
can be provided to a SP in the SAML assertions.  This of course assumes that
the underlying identity management system that Ipsilon is using has the
information that you need.

Every assertion that is contained in the SAML response is provided to your web
application by mod_auth_mellon.  The environment variables that expose these
values are prefixed by `MELLON_`, followed by the name of the assertion.  These
names are defined by the IDP configuration.  Your application is not forced to
use a specific set of environment variable names however.  You can configure
mod_auth_mellon to map the SAML assertions to different environment variable
names.  This is done by using the ``MellonSetEnv`` and ``MellonSetEnvNoPrefix``
directives in the ``Location`` directive for your base URI.  Consider the
following examples::

    MellonSetEnv "email" "mail"
    MellonSetEnvNoPrefix "DISPLAY_NAME" "displayName"

Both of these directives take the form ``<directive> <local name> <IDP name>``.
In the case of the above example, a ``mail`` attribute in the SAML assertion
would be expressed as the ``MELLON_email`` environment variable.  The
``MellonSetEnvNoPrefix`` directive works the same way, but it does not use the
``MELLON_`` prefix.  In this case, a ``displayName`` attribute in the SAML
assertion would be expressed as the ``DISPLAY_NAME`` environment variable.
There are some good recommendations on some common environment variables that
should be used for web application authentication in general on the FreeIPA
wiki's `Web App Authentication`_ page.

For the purposes of authorization within a web application, it is recommended
to take advantage of group membership information that is provided in the SAML
assertions.  For instance, if your web application has a concept of an
``user`` role, it can allow that role to be assigned to a group that is
defined in the identity management system that is used by the IDP.  This
allows for application access to be controlled by group assignment centrally
in the identity management system.  It is of course possible to assign the
web application roles directly to a user as well if the groups don't map
cleanly to the authorization grouping within your application.  Still, it is
best to try to keep user and group management out of the web application as
much as possible.

It is not uncommon for a web application to have a need to store information
about a user that will not be provided by an IDP or even by any identity
management system.  One of the most common cases of this is storing user
preferences that are specific to the web application.  The recommended way of
handling this is to have the web application create a record for this data in
it's own backend database when it first sees a new user.  It can associate this
data with a user identitfier from the assertion, such as ``REMOTE_USER`` or
some combination of assertion values that is guaranteed to be unique.  The
important thing is that none of the other user data from the assertion should
be duplicated in the web application's backend database.

Logout Handling
---------------
Changes may also be needed to the web application to allow logout to work
properly.  When a user succesfully authenticates and accesses a SP that uses
mod_auth_mellon, a cookie is set in the user's browser to represent their
session.  In order to terminate this session when the user logs out of the
web application, you have to make sure that your web application will send the
user to the logout URI that was defined when the SP metadata was generated.  In
addition, a required ``ReturnTo`` query parameter must be specified, which
tells mod_auth_mellon where to send the user after completing the logout
operation.  The format of this looks like::

    <logout URI>?ReturnTo=<url to redirect to after logout>

Typically, your application will either redirect or provide a direct link to
the logout URI.


References
==========
.. target-notes::

.. _mod_auth_mellon: https://github.com/UNINETT/mod_auth_mellon/wiki
.. _Web App Authentication: http://www.freeipa.org/page/Web_App_Authentication
