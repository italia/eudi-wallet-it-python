### Docker compose

Install Docker using the packages distributed from the official website and the following tools.
````
sudo pip install docker-compose
````

We can do that with the following steps:

- Execute `bash docker-prepare.sh`
- Customize the example data and settings contained in `examples-docker/` if needed (not necessary for a quick demo)


Run the stack
````
sudo docker-compose up
````

Point your web browser to `http://localhost:8080` to start your EUDI Wallet authentication to a Wordpress demo site.


## First Installation

Follow the on-screen instructions to complete the WordPress installation.
1. You will be prompted to enter some basic information to complete the initial configuration of your WordPress site. This includes:
    * Site Title: Enter a title for your WordPress site.
    * Username: Choose a username for your administrator account.
    * Password: Choose a strong password for your administrator account.
    * Your Email: Enter an email address where you can receive notifications from your WordPress site.
    * Search Engine Visibility: Choose whether or not you want search engines to index your site.
2. Click on the “Install WordPress” button to complete the initial configuration. 

## Installing the ItaliaWP2 Theme

1. Log in to the WordPress dashboard at http://localhost:8080/wp-admin (replace 8080 with the port specified in the docker-compose.yml file) using your administrator credentials.
2. In the sidebar, go to “Appearance” > “Themes” and activate the ItaliaWP2 theme that you just installed.

After following these steps, your WordPress instance should be up and running with the ItaliaWP2 theme installed and activated.

## Installing the OneLogin SAML SSO plugin

1. Log in to the WordPress dashboard at http://localhost:8080/wp-admin (replace 8080 with the port specified in the docker-compose.yml file) using your administrator credentials.
2. Under [plugins](http://localhost:8080/wp-admin/plugins.php), activate the plugin OneLogin SAML SSO.
3. Configure the plugin OneLogin SAML SSO in the [settings tab](http://localhost:8080/wp-admin/options-general.php?page=onelogin_saml_configuration).

To configure your test environment with the IAM Proxy instance, you'll need to undertake a configuration phase on the OneLogin plugin settings page. The required proxy service configuration metadata is obtainable from https://demo-it-wallet.westeurope.cloudapp.azure.com/Saml2IDP/metadata. 

Specifically, you should modify the following fields:

- **IdP Entity Id**: Enter the entityID of the IAMProxy, which can be located within the metadata.
- **Single Sign-On Service Url**: Input the Location of the SingleSignOnService you desire to connect with, as specified in the metadata file.
- **X.509 Certificate**: Include the X.509 Certificate associated with the IAMProxy, found within the metadata.
- **Create user if not exists**: Set this to `true`.
- **Update user data**: Set this to `true`.
- **Attribute Mapping - Username**: Set this to `fiscalNumber`.
- **Attribute Mapping - E-mail**: Set this to `urn:oid:1.2.840.113549.1.9.1.1`.
- **Attribute Mapping - First Name**: Set this to `Name`.
- **Attribute Mapping - Last Name**: Set this to `familyName`.
- **Service Provider Entity Id**: Enter the URL of your SP metadata as the entityID. For example: http://\<wordpress-domain\>/wp-login.php?saml_metadata
- **Encrypt nameID**: Set this to `true`.
- **Sign AuthnRequest**: Set this to `true`.
- **Reject Unsigned Assertions**: Set this to `true`.
- **NameIDFormat**: Set this to `urn:oasis:names:tc:SAML:2.0:attrname-format:uri`.
- **requestedAuthnContext**: Set this to `urn:oasis:names:tc:SAML:2.0:ac:classes:X509`.
- **Service Provider X.509 Certificate**: Insert your SP's X.509 certificate here.
- **Service Provider Private Key**: Input the private key of your SP.
- **Signature Algorithm**: Set this to `rsa-sha256`.
- **Digest Algorithm**: Set this to `sha256`.

After you've filled all the fields, save your settings and download the SP metadata for configuration on the IAM Proxy.