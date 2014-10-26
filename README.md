AIX Bitcoin Contract Middleware
===============================

The AIX contract middleware enables insurances and bets on the Bitcoin blockchain that are decentralized, oracle-driven, trust-less contacts.

     Description : Mw - AI Effect Bitcoin Contract Middleware Server
     Version     : 0.1
     File        : README.md
     Copyright   : ai effect UG, Berlin
     Author      : H. Diedrich <hd2010@eonblast.com>, G. Simonsson <gustav.simonsson@gmail.com>
     License     : All rights reserved
     Created     : 24 May 2014

![alt tag](../master/priv/blade_runner/intro.gif?raw=true)

Status
------

This is the 'Mw' stack of Cowboy, PostgreSQL and BitcoinJS. It has a minmal cowboy setup serving static pages in `priv/` and assembling dynamic pages from flat data structures and templates in `priv/blocks/`. PostgreSQL is used to persist contract state. BitcoinJS is currently sometimes used with stable 1.0.2 and at other times with the old de-facto standard 0.1.3. There are 'blocks' for all pages that are part of the usage flow.

Requirements
------------

* git
* make
* Erlang R17*
* relx
* PostgreSQL

PostgreSQL config
-----------------

This is currently in middle_server_app.erl in lieu of being extracted to a config file:

``` erlang
 application:set_env(mw, pools,
                        [
                         {pgsql_pool, [{size, 1}, {max_overflow, 1}],
                          [
                           {host, "localhost"},
                           {dbname, "mw"},
                           {user, "mw"},
                           {pass, "mw"}
                          ]}
                        ]),
```

PostgreSQL bootstrap
--------------------
As a user with rights to modify the database (this could be postgres user):

``` bash
psql mw < priv/postgres/mw_db_drop_all
psql mw < priv/postgres/mw_db_init
```

Build & Run the Stack
---------------------

To build this stack, run the following command:

``` bash
$ make
```

Due to bleeding-edge hipster combination of GNU make, erlang.mk, relx, the erlang.mk package index, git dependencies resolved using rebar and some manual build steps, you have to run make a few more times to actually get everything built the very first time:

``` bash
$ make
$ make
$ make
```

To start the server in the foreground:

``` bash
$ make run
```

Content
-------

Mw runs two http servers side by side. One for API2 serving JSON. And the web server for the main site, for information about the concept, and the functional prototype, including JS scripts.

There is a third coming as dedicated interface to Android apps.

### API2 JSON

The 'API2' is the interface between web site and Mw for communication between JS in the browser and the backend.

There are currently

     [http://localhost:8081/enter-contract/<contract_id>]
     [http://localhost:8081/clone-contract/<contract_id>]
     [http://localhost:8081/submit-t2-signature/<contract_id>]
     [http://localhost:8081/get-t3-for-signing/<contract_id>]
     [http://localhost:8081/submit-t3-signatures/<contract_id>]

The results are JSON objects. They are created in `api_handler.erl`. The matching of the URL is hard coded in the main dispatch rule, in `middle_server.erl` and matching atoms in `api_handler:response/2`.

### Web Site

Try [http://localhost:8080/](http://localhost:8080/)

This page is assembled from the template blocks in the `priv` folder: `head.html`, `foot.html`, `bet.html` etc. Note that the `priv` folder is copied into the release. You can change pages dynamically by changing these files but they are NOT the ones in the priv folder in this folder. They are somewhere under `_rel/`. When you change these, you can immediately reload in the browser.

`bet.html` is interesting as it contains uppercase, $-affixed placeholders for actual values. The actual creation of the html to be served is done in `src/page_handler.erl`.

 * [index.html](http://localhost:8080/)              - landing page showing some bets
 * [status.html](http://localhost:8080/status/1)     - status page for contract


### BitcoinJS

Test BitcoinJS with [http://localhost:8080/hello-js.html](http://localhost:8080/hello-js.html)

This will give you a page with basic BitcoinJS operations like key creation,
hasing and signing.

![alt tag](../master/priv/blade_runner/deckard_rachael.jpg?raw=true)

### Generate test keys

``` bash
openssl genrsa -out oracle_no_privkey.pem 2048
openssl rsa -in oracle_no_privkey.pem -pubout > oracle_no_pubkey.pem
```

``` bash
git clone https://github.com/matja/bitcoin-tool.git
make
sudo cp bitcoin-tool /usr/local/bin
openssl rand 32 > temp_bytes && bitcoin-tool --network bitcoin-testnet --input-type private-key --input-format raw --input-file temp_bytes --output-type private-key --output-format base58check --public-key-compression compressed > ec_privkey && bitcoin-tool --network bitcoin-testnet --input-type private-key --input-format raw --input-file temp_bytes --output-type public-key --output-format base58check --public-key-compression compressed > ec_pubkey && rm -f temp_bytes
```

### Example debug flow:

Reset database:

``` bash
psql mw < priv/postgres/mw_db_drop_all
psql mw < priv/postgres/mw_db_init
```

You will have to give all privileges again unless you're Gustav.

``` bash
psql -d mw
# granting privileges
grant all privileges on schema public to mw;
grant all privileges on oracle_keys to mw;
grant all privileges on sequence oracle_keys_id_seq to mw;
grant all privileges on events to mw;
grant all privileges on sequence events_id_seq  to mw;
grant all privileges on contracts  to mw;
grant all privileges on sequence contracts_id_seq to mw;
grant all privileges on contract_events to mw;
grant all privileges on sequence contract_events_id_seq to mw;
grant all privileges on contract_events_maps to mw;
```

Create some default events with dummy giver already entered (must do to call test pages prep/n etc):

``` erlang
mw_setup:insert_test_bets().
```

Goto http://localhost:8080/ and try entering a bet.

Manually add the event outcome in favour of taker:

``` erlang
mw_contract:add_event_outcome(1, false).
```

![alt tag](../master/priv/blade_runner/rachael2.jpg?raw=true)
