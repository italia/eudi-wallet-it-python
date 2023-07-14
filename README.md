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
