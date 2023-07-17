# eidas-it-wallet-satosa-rp
Satosa OpenID4VP based on the Italian Wallet Solution

## Satosa Installation
### Python Environment
From terminal run the following commands:

<b>Ubuntu</b>
````
sudo apt install -y libffi-dev libssl-dev python3-pip xmlsec1 procps libpcre3 libpcre3-dev
````

<b>Centos/RHEL</b>
````
sudo yum install -y libffi-devel openssl-devel python3-pip xmlsec1 procps pcre pcre-devel
sudo yum groupinstall "Development Tools"
sudo yum install -y python3-wheel python3-devel
````

<b>MacOS</b>
````
xcode-select --install
brew install libffi openssl@3 python3 procps pcre
brew edit libxmlsec1
````

At this point an editor will appear and in it change the version of the package with 1.2.37 an then:

````
brew install /opt/homebrew/Library/Taps/homebrew/homebrew-core/Formula/libxmlsec1.rb
````

### Satosa
Inside the satosa directory run the following commands for initialize the environment:

````
pip install --upgrade pip
pip install virtualenv

cd satosa
virtualenv -ppython3 satosa.env
source satosa.env/bin/activate
````

Then in both the directories satosa/ and satosa/sp/djangosaml2_sp run:
````
pip install -r requirements.txt
````

In the directory idp_proxy run to start the service:
````
export SATOSA_APP=$VIRTUAL_ENV/lib/$(python -c 'import sys; print(f"python{sys.version_info.major}.{sys.version_info.minor}")')/site-packages/satosa

# only https with satosa, because its Cookie only if "secure" would be sent
uwsgi --wsgi-file $SATOSA_APP/wsgi.py  --https 0.0.0.0:10000,./pki/cert.pem,./pki/privkey.pem --callable app -b 32768

# additional static serve for the demo Discovery Service with Spid button
uwsgi --https 0.0.0.0:9999,./pki/cert.pem,./pki/privkey.pem --check-static-docroot --check-static ./static/ --static-index disco.html
````

In the directory sp/djangosaml2_sp run:
````
python manage.py migrate
./manage.py runserver 0.0.0.0:8000
````

### Troubleshooting
- "uwsgi: unrecognized option `--https'" when the satosa.env is active run:
````
CFLAGS="-I$(brew --prefix openssl)/include" LDFLAGS="-L$(brew --prefix openssl)/lib" UWSGI_PROFILE_OVERRIDE=ssl=true pip install uwsgi -I --no-cache-dir 
````

If you reach the cache limit using the page of login use the flag "-b 32768" to the command to start the service for the statics contents 

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
