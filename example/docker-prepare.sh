#!/bin/bash

plugin_url="https://downloads.wordpress.org/plugin/onelogin-saml-sso.zip"
theme_url="https://raw.githubusercontent.com/italia/design-wordpress-theme-italiaWP2/master/italiawp2.zip"
plugin_folder="./wordpress-plugin"
theme_folder="./wordpress-theme"

mkdir -p $plugin_folder
mkdir -p $theme_folder

#download and unzip of plugin
curl -O $plugin_url
unzip onelogin-saml-sso.zip
rm onelogin-saml-sso.zip

# Move the content of the subfolder to the specified folder
mv onelogin-saml-sso $plugin_folder

# Remove the empty folder
rmdir onelogin-saml-sso/onelogin-saml-sso
rmdir onelogin-saml-sso

#download and unzip of theme
curl -O $theme_url
unzip italiawp2.zip
rm italiawp2.zip

# Move the unzipped content to the specified folder
mv italiawp2 $theme_folder