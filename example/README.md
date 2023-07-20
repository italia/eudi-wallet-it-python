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

To configure a generic SAML connection, you will need to enter appropriate values in OneLogin SAML SSO plugin settings. These include Identity Provider URL, Assertion Consumer Service URL, Single Logout Service URL, and other parameters specific to your SAML configuration.