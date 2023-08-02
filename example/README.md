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

To configure the test environment with the IAM Proxy instance, a configuration phase is required on the OneLogin plugin settings page using the proxy service configuration metadata obtainable from https://demo-it-wallet.westeurope.cloudapp.azure.com/Saml2IDP/metadata.
Specifically, the following fields should be modified:

- **IdP Entity Id**: enter the entityID of the IAMProxy found in the metadata
- **Single Sign On Service Url**: enter the Location of the SingleSignOnService you wish to connect to found in the metadata file
- **X.509 Certificate**: insert the IAMProxy X.509 Certificate found in the metadata
- **Create user if not exists**: `true`
- **Update user data**: `true`
- **Attribute Mapping -  Username**: fiscalNumber
- **Attribute Mapping -  E-mail**: `urn:oid:1.2.840.113549.1.9.1.1`
- **Attribute Mapping -  First Name**: Name
- **Attribute Mapping -  Last Name**: familyName
- **Service Provider Entity Id**: enter the SP metadata url as entityID (e.g. http://\<wordpress-domain\>/wp-login.php?saml_metadata
- **Encrypt nameID**: `true`
- **Sign AuthnRequest**: `true`
- **Reject Unsigned Assertions**: `true`
- **NameIDFormat**: `urn:oasis:names:tc:SAML:2.0:attrname-format:uri`
- **requestedAuthnContext**: `urn:oasis:names:tc:SAML:2.0:ac:classes:X509`
- **Service Provider X.509 Certificate**: insert the X.509 certificate of your SP
- **Service Provider Private Key**: insert the private key of your SP
- **Signature Algorithm**: rsa-sha256
- **Digest Algorithm**: sha256

Once all fields are set, save the settings and download the SP metadata for its configuration on IAM Proxy.