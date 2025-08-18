# Local Setup Guide

This step-by-step guide provides instruction about running Barbican with SoftHSM integration simulating multi-tenancy with Thales and 
Utimaco HSMs for local development.

## Install SoftHSMv2
```
git clone git@github.com:softhsm/SoftHSMv2.git
cd SoftHSMv2
brew install automake libtool pkg-config cppunit openssl
./autogen.sh
./configure --with-openssl=$(brew --prefix openssl)
make
sudo make install
```

Credits to [microshine](https://github.com/parallaxsecond/rust-cryptoki/issues/191#issuecomment-2590877745).

## Install pkcs11-tool

```
brew install opensc
```

Follow: https://docs.nitrokey.com/nethsm/pkcs11-tool


## Initialize a Token

Initialize the token at a free slot by setting crypto user & security officer PINs:

```
softhsm2-util --init-token --free --label <label>
```

Display all available slots:

```
softhsm2-util --show-slots
```

List tokens with slots:

```
pkcs11-tool --module /usr/local/lib/softhsm/libsofthsm2.so -T
```

## Clone Barbican

Clone the project:

```
git clone git@github.com:sapcc/barbican.git
```

Follow [this guideline](https://docs.openstack.org/barbican/latest/contributor/dev.html) to set up Barbican for local 
development.

## Run MariaDB

Create a Docker compose file `barbican.yaml` anywhere:

```
version: "3.8"

services:
  mariadb:
    image: mariadb:latest
    container_name: barbican_db
    environment:
      MYSQL_ROOT_PASSWORD: <db_root_password>
      MYSQL_DATABASE: <db_bame>
      MARIADB_USER: <db_user>
      MARIADB_PASSWORD: <db_password>
    ports:
      - "3306:3306"
    networks:
      - barbican_db_network
    volumes:
      - mariadb_data:/var/lib/mysql

networks:
  barbican_db_network:
    driver: bridge

volumes:
  mariadb_data:
    
```

Run the Docker compose file:

```
docker-compose -f barbican.yml up -d
```

## Update Barbican Config

Update the `barbican/etc/barbican/barbican.conf` with the following configurations:

```
[DEFAULT]
debug = True
verbose = True
wsgi_debug = True

[database]
connection = mysql+pymysql://<db_user>:<db_password>@localhost:3306/<db_name>

[paste_deploy]
flavor = noauth

[keystone_authtoken]
enable = False

[auth]
enable_authentication = False

[secretstore]
enable_multiple_secret_stores = True
stores_lookup_suffix = software, pkcs11, utimaco_hsm, thales_hsm

[secretstore:software]
name = Software Only Crypto
secret_store_plugin = store_crypto
crypto_plugin = simple_crypto

[secretstore:pkcs11]
name = PKCS11 HSM
secret_store_plugin = store_crypto
crypto_plugin = p11_crypto
global_default = True

[secretstore:utimaco_hsm]
name = Utimaco HSM
secret_store_plugin = store_crypto
crypto_plugin = utimaco_hsm_crypto

[secretstore:thales_hsm]
name = Thales HSM
secret_store_plugin = store_crypto
crypto_plugin = thales_hsm_crypto

[p11_crypto_plugin]
library_path = /usr/local/lib/softhsm/libsofthsm2.so
slot_id = <slot_id>
login = <crypto_user_pin>
hmac_key_length = 32
mkek_label = mkek
hmac_label = hmac
hmac_key_type = CKK_GENERIC_SECRET
hmac_keygen_mechanism = CKM_GENERIC_SECRET_KEY_GEN
hmac_mechanism = CKM_SHA256_HMAC
encryption_mechanism = CKM_AES_CBC

[hsm_partition_crypto_plugin:utimaco_hsm]
library_path = /usr/local/lib/softhsm/libsofthsm2.so
hmac_key_length = 32
mkek_label = mkek
hmac_label = hmac
hmac_key_type = CKK_GENERIC_SECRET
hmac_keygen_mechanism = CKM_GENERIC_SECRET_KEY_GEN
hmac_mechanism = CKM_SHA256_HMAC
encryption_mechanism = CKM_AES_CBC

[hsm_partition_crypto_plugin:thales_hsm]
library_path = /usr/local/lib/softhsm/libsofthsm2.so
hmac_key_length = 32
mkek_label = mkek
hmac_label = hmac
hmac_key_type = CKK_GENERIC_SECRET
hmac_keygen_mechanism = CKM_GENERIC_SECRET_KEY_GEN
hmac_mechanism = CKM_SHA256_HMAC
encryption_mechanism = CKM_AES_CBC
```

By default, the application will look for the configuration file in `/etc/barbican/barbican.conf`, so copy it there.

```
cp etc/barbican/barbican.conf /etc/barbican/barbican.conf
```

## Run DB Migration

```
barbican-db-manage upgrade
```

Read more on [DB Migration](https://docs.openstack.org/barbican/latest/contributor/database_migrations.html).

## Generate MKEK and HMAC Keys

Navigate into the Barbican project and run:

```
barbican-manage hsm gen_mkek \
  --library-path /usr/local/lib/softhsm/libsofthsm2.so \
  --slot-id <slot_id> \
  --label mkek \
  --passphrase <crypto_user_pin>
```

```
barbican-manage hsm gen_hmac \
  --library-path /usr/local/lib/softhsm/libsofthsm2.so \
  --slot-id <slot_id> \
  --label hmac \
  --passphrase <crypto_user_pin>
```

Alternatively this can also be done via the pkcs11-tool:

```
pkcs11-tool --module /usr/local/lib/softhsm/libsofthsm2.so \
  --slot <slot_id> \
  --login --login-type user --pin <crypto_user_pin> \
  --keygen --key-type AES:32 \
  --label "mkek" \
  --id 01 \
  --usage-decrypt
```

```
pkcs11-tool --module /usr/local/lib/softhsm/libsofthsm2.so \
  --slot <slot_id> \
  --login --login-type user --pin <crypto_user_pin> \
  --keygen --key-type generic:32 \
  --label "hmac" \
  --id 02 \
  --usage-sign
```

Show objects on token:

```
pkcs11-tool --module /usr/local/lib/softhsm/libsofthsm2.so -O \
  --token-label <label> \
  --pin <crypto_user_pin>
```

## Create HSM Partition Config

Create HSM partition config for the project in the DB:

```
python ./barbican/cmd/hsm_partition_create.py \
  --external-project-id <project_name> \
  --token-label <label> \
  --slot-id <slot_id> \
  --password <crypto_user_pin> \
  --library-path /usr/local/lib/softhsm/libsofthsm2.so
```

## Run Unit Tests

Run unit tests by using the sample config file:

```
cp etc/barbican/barbican.conf.sample /etc/barbican/barbican.conf
```

```
pytest --disable-warnings barbican/tests/
```

## Run Barbican

Finally run the application:

```
./bin/barbican.sh start
```

## Manage Secrets using API

List secret stores:

```
curl -s -X GET \
  http://localhost:9311/v1/secret-stores \
  -H "Content-Type: application/json" \
  -H "X-Project-ID: <project_name>" | jq .
```

Assign secret store to project:

```
curl -X POST \
  http://localhost:9311/v1/secret-stores/<store_uuid>/preferred \
  -H "X-Project-ID: <project_name>"
```

Create a secret:

```
curl -s -X POST \
  http://localhost:9311/v1/secrets \
  -H "Content-Type: application/json" \
  -H "X-Project-ID: <project_name>" \
  -d '{"name": "<name>", 
       "algorithm": "AES", 
       "bit_length": 256, 
       "mode": "CBC", 
       "payload": "<payload_in_base64>", 
       "payload_content_type": "application/octet-stream", 
       "payload_content_encoding": "base64", 
       "secret_type": "passphrase"}' | jq .
```

List secrets:

```
curl -s -X GET \
  http://localhost:9311/v1/secrets \
  -H "Content-Type: application/json" \
  -H "X-Project-ID: <project_name>" | jq .
```

Get secret payload:

```
curl -X GET \
  http://localhost:9311/v1/secrets/<uuid>/payload \
  -H "Content-Type: application/json" \
  -H "X-Project-ID: <project_name>"
```

Check [API documentation](https://docs.openstack.org/barbican/latest/api/index.html) for further details.