# Docker Compose for WordPress with ItaliaWP2

The Docker Compose file repository sets up a WordPress instance that includes a MariaDB database, phpMyAdmin for managing the database through a web interface, and the ItaliaWP2 theme pre-installed and activated.

**Note: This is just for demo purposes and MUST NOT be used in production contexts.**

## Prerequisites

- Docker and Docker Compose installed on your system
- Git installed on your system

## Installation

1. Clone this repository to your local machine using the command `git clone <repository-url>`.
2. Navigate to the root directory of the repository using the command `cd <repository-name>`.
3. Copy the `.env.example` file to a new file named `.env` using the command `cp .env.example .env`.
4. Open the `.env` file in a text editor and update the values of the environment variables with your desired values. Make sure to set the values for `MYSQL_DATABASE`, `MYSQL_USER`, `MYSQL_PASSWORD`, and `MYSQL_ROOT_PASSWORD`.
5. Run the command `docker-compose up -d` to start the containers.
6. Open a web browser and navigate to `http://localhost:8080` to access the WordPress installation page.
7. Follow the on-screen instructions to complete the WordPress installation.

## Installing the ItaliaWP2 Theme

1. Log in to the WordPress dashboard at `http://localhost:8080/wp-admin` (replace `8080` with the port specified in the `docker-compose.yml` file) using your administrator credentials.
2. In the sidebar, go to "Appearance" > "Themes" and activate the ItaliaWP2 theme that you just installed.

After following these steps, your WordPress instance should be up and running with the ItaliaWP2 theme installed and activated.

## Installing the OneLogin SAML SSO plugin

1. Download the [plugin archive](https://downloads.wordpress.org/plugin/onelogin-saml-sso.zip).
2. Extract the archive under [<root_dir>/wordpress/wp-content/plugins/](wordpress/wp-content/plugins/)
3. Log in at [http://localhost:8080/wp-admin](http://localhost:8080/wp-admin).
4. Under [plugins](http://localhost:8080/wp-admin/plugins.php), activate the plugin OneLogin SAML SSO.
5. Configure the plugin OneLogin SAML SSO in the [settings tab](http://localhost:8080/wp-admin/options-general.php?page=onelogin_saml_configuration).
