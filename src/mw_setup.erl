%%%-------------------------------------------------------------------
%%% @author Gustav Simonsom <gustav.simonson@gmail.com>
%%% @copyright (C) 2014, AI Effect Group, Berlin. All rights reserved.
%%% @doc
%%% Misc dev / test functions for bootstrapping test / demo bets.
%%% @end
%%% Created : 06 Jun 2014 by gustav <gustav.simonsson@gmail.com>
%%%-------------------------------------------------------------------
-module(mw_setup).

-compile(export_all).

-include("log.hrl").

%% ensure unique temp files for test bets
-define(SUFFIX, lists:flatten(string:tokens(pid_to_list(self()), "<>."))).

%% mw_setup:insert_test_bets().
insert_test_bets() ->
    insert_wc_bet("Manchester United beats Chelsea"),
    insert_wc_bet("Chelsea beats Manchester United"),
    ok.

insert_wc_bet(Headline) ->
    {ok, EventPriv, EventPub,
     OracleYesPriv, OracleYesPub,
     OracleNoPriv, OracleNoPub} = gen_keys(),
    {ok, OracleKeysId} =
        mw_pg:insert_oracle_keys(OracleNoPub, OracleNoPriv,
                                 OracleYesPub, OracleYesPriv),
    {ok, EventId} = mw_contract:create_event(Headline,
                                             OracleKeysId,
                                             EventPriv, EventPub),
    {ok, ContractId} = mw_contract:create_contract(EventId),
    {ok, ECPubKey0} =
        file:read_file(filename:join(code:priv_dir(middle_server),
                                     "test_keys/giver_keys5_compressed/ec_pubkey")),
    ECPubKey = binary:replace(ECPubKey0, <<"\n">>, <<>>),
    {ok, RSAPubKey} =
        file:read_file(filename:join(code:priv_dir(middle_server),
                                     "test_keys/giver_keys1/rsa_pubkey.pem")),
    mw_contract:enter_contract(ContractId,
                               ECPubKey,
                               RSAPubKey,
                               %% As these are test givers for dev, we fake
                               %% the enc privkeys (they are never used)
                               <<"">>,
                               <<"">>
                              ),
    ok.

gen_keys() ->
    %% Experiment to block for quality entropy bits from /dev/random on Linux
    %% Turned out to take WAY too long to get enough bits to generate keys for
    %% all the bets.
    %% TODO: figure out if we can generate keys with this in a timely manner by
    %% adding enough entropy to Linux:
    %% TMPRandFile = "/tmp/mw_openssl_rand_file",
    %% SetOpenSSLRandFile =
    %%    "dd if=/dev/random bs=1 count=1024 of=" ++ TMPRandFile ++ "; "
    %%    "export RANDFILE=" ++ TMPRandFile,
    %% os:cmd(SetOpenSSLRandFile),

    {ok, OracleYesPriv, OracleYesPub} = gen_rsa_keypair(),
    {ok, OracleNoPriv, OracleNoPub}   = gen_rsa_keypair(),
    {ok, EventPriv, EventPub}         = gen_ec_keypair(),

    {ok, EventPriv, EventPub,
     OracleYesPriv, OracleYesPub,
     OracleNoPriv, OracleNoPub}.

gen_ec_keypair() ->
    BitcoinTool = filename:join(code:priv_dir(middle_server), "bitcoin-tool"),
    ECTempBytes = filename:join(code:priv_dir(middle_server),
                                "ec_temp_bytes_" ++ ?SUFFIX),
    ECPrivAbsPath = filename:join(code:priv_dir(middle_server),
                                  "temp_setup_ec_privkey" ++ ?SUFFIX),
    ECPubAbsPath = filename:join(code:priv_dir(middle_server),
                                 "temp_setup_ec_pubkey" ++ ?SUFFIX),

    GenBytes = "openssl rand 32 > " ++ ECTempBytes,

    %% https://en.bitcoin.it/wiki/Private_key#Base_58_Wallet_Import_format
    %% The privkey eventually gets parsed by client-side, so we want it in
    %% standard WIF so it works with e.g. bitcoinjs lib.
    %% TODO: change network back to bitcoin-testnet? needed mainent to work with
    %% bitcoinjs Bitcoin.ECKey.decodeString in the browser
    GenECPriv = BitcoinTool ++ " "
        "--network bitcoin "
        "--input-type private-key "
        "--input-format raw "
        "--input-file " ++ ECTempBytes ++ " "
        "--output-type private-key-wif "
        "--output-format base58check "
        "--public-key-compression uncompressed > " ++ ECPrivAbsPath,

    %% Pubkey is only used in T2 output script, so we use a format that can
    %% directly be used by Bj to put it into the script binary.
    %% TODO: verify! is the above true? should we change some parameter?
    GenECPub = BitcoinTool ++ " "
        "--network bitcoin "
        "--input-type private-key "
        "--input-format raw "
        "--input-file " ++ ECTempBytes ++ " "
        "--output-type public-key "
        "--output-format base58check "
        "--public-key-compression compressed > " ++ ECPubAbsPath,

    os:cmd(GenBytes),
    os:cmd(GenECPriv),
    os:cmd(GenECPub),

    {ok, ECPrivBin} = file:read_file(ECPrivAbsPath),
    {ok, ECPubBin} = file:read_file(ECPubAbsPath),

    ok = file:delete(ECTempBytes),
    ok = file:delete(ECPrivAbsPath),
    ok = file:delete(ECPubAbsPath),
    {ok, ECPrivBin, ECPubBin}.

gen_rsa_keypair() ->
    RSAPrivAbsPath = filename:join(code:priv_dir(middle_server),
                                   "temp_setup_rsa_privkey.pem_" ++ ?SUFFIX),
    RSAPubAbsPath = filename:join(code:priv_dir(middle_server),
                                  "temp_setup_rsa_pubkey.pem_" ++ ?SUFFIX),
    GenRSAPriv = "openssl genrsa -out " ++ RSAPrivAbsPath ++ " 2048",
    GenRSAPub  = "openssl rsa -in " ++ RSAPrivAbsPath ++
        " -pubout > " ++ RSAPubAbsPath,
    os:cmd(GenRSAPriv),
    os:cmd(GenRSAPub),
    {ok, RSAPrivBin} = file:read_file(RSAPrivAbsPath),
    {ok, RSAPubBin} = file:read_file(RSAPubAbsPath),
    ok = file:delete(RSAPrivAbsPath),
    ok = file:delete(RSAPubAbsPath),
    {ok, RSAPrivBin, RSAPubBin}.
