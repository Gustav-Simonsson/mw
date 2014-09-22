%%%-------------------------------------------------------------------
%%% @author Gustav Simonsom <gustav.simonson@gmail.com>
%%% @copyright (C) 2014, AI Effect Group, Berlin
%%% @doc
%%% Contract logic.
%%%
%%% Persistent contract state is maintained in postgres contract tables.
%%% The state is read when generating the contract web page / android view.
%%% The state is modified by events such as:
%%%     * Enter a bet
%%%     * Sign a bet (T2),
%%%     * Cashing out a won bet (T3)
%%%
%%% @end
%%% Created : 05 Jun 2014 by gustav <gustav.simonsson@gmail.com>
%%%-------------------------------------------------------------------
-module(mw_contract).

-compile(export_all).
%% API
-export([]). %% TODO: remove export_all and add API exports

-include("mw.hrl").
-include("mw_contract.hrl").
-include("log.hrl").
-include("mw_api_errors.hrl").

-define(GET(PL), fun(Key) -> proplists:get_value(Key, PL, not_found) end).

%%%===========================================================================
%%% JSON API handlers (called from cowboy callbacks)
%%%===========================================================================
%% Validations throw error so JSON handler can return nice error code / msg
%% Any unhandled error (crash) will return default json error code / msg
enter_contract(ContractId,
               ECPubkey,
               RSAPubkey,
               EncECPrivkey,
               EncRSAPrivkey) ->
    ?info("Handling enter_contract with ContractId: ~p , ECPubkey: ~p"
          "RSAPubkey: ~p EncECprivkey: ~p EncRSaprivkey: ~p",
          [ContractId, ECPubkey, RSAPubkey, EncECPrivkey, EncRSAPrivkey]),
    mw_lib:api_validation(is_integer(ContractId), ?CONTRACT_ID_TYPE),

    %% https://en.bitcoin.it/wiki/Base58Check_encoding
    %% compressed EC pubkeys in base58check encoding is 50 chars
    mw_lib:api_validation(is_binary(ECPubkey) andalso
                   is_binary(catch mw_lib:dec_b58check(ECPubkey)),
                   ?EC_PUBKEY_TYPE),
    mw_lib:api_validation((byte_size(ECPubkey) == 50), ?EC_PUBKEY_LEN),

    mw_lib:api_validation(is_binary(RSAPubkey) andalso
                   %% http://erlang.org/doc/man/public_key.html#pem_decode-1
                   length(catch public_key:pem_decode(RSAPubkey)) == 1,
                   ?RSA_PUBKEY_TYPE),
    %% TODO: what lengths can PEM encoded RSA 2048 pubkeys have?
    % mw_lib:api_validation((byte_size(RSAPubkey) == 902), ?RSA_PUBKEY_LEN),

    %% TODO: validation of encrypted privkeys in hex, what is length?

    ok = do_enter_contract(ContractId,
                           ECPubkey,
                           RSAPubkey,
                           EncECPrivkey,
                           EncRSAPrivkey),
    [{<<"success-message">>, <<"ok">>}].

submit_t2_signature(ContractId, ECPubkey, T2Signature) ->
    ?info("Handling submit_signed_t2_hash with ContractId: ~p , ECPubkey: ~p, "
          "T2Signature: ~p",
          [ContractId, ECPubkey, T2Signature]),
    mw_lib:api_validation(is_integer(ContractId), ?CONTRACT_ID_TYPE),

    mw_lib:api_validation(is_binary(ECPubkey) andalso
                   is_binary(catch mw_lib:dec_b58check(ECPubkey)),
                   ?EC_PUBKEY_TYPE),
    mw_lib:api_validation((byte_size(ECPubkey) == 50), ?EC_PUBKEY_LEN),

    mw_lib:api_validation(is_binary(catch mw_lib:hex_to_bin(T2Signature)),
                   ?SIGNATURE_TYPE),
    mw_lib:api_validation(mw_btc:bitcoin_signature_der(mw_lib:hex_to_bin(T2Signature)),
                   ?SIGNATURE_TYPE),

    ok = do_submit_t2_signature(ContractId, ECPubkey, T2Signature),
    [{<<"success-message">>, <<"ok">>}].

get_t3_for_signing(ContractId, ToAddress) ->
    ?info("Handling get_t3_for_signing with ContractId: ~p , ToAddress: ~p ",
          [ContractId, ToAddress]),
    mw_lib:api_validation(is_integer(ContractId), ?CONTRACT_ID_TYPE),

    mw_lib:api_validation(is_binary(ToAddress) andalso
                   is_binary(catch mw_lib:dec_b58check(ToAddress)),
                   ?ADDRESS_TYPE),
    mw_lib:api_validation((byte_size(ToAddress) >= 27) andalso
                   (byte_size(ToAddress) =< 34),
                   ?ADDRESS_LEN),

    ResultProps = do_get_t3_for_signing(ContractId, ToAddress),
    [{<<"success-message">>, <<"ok">>}] ++ ResultProps.

submit_t3_signatures(ContractId, T3Raw, T3Signature1, T3Signature2) ->
    ?info("Handling submit_t3_signatures with ContractId: ~p "
          ", T3Signature1: ~p, T3Signature2: ~p",
          [ContractId, T3Signature1, T3Signature2]),
    mw_lib:api_validation(is_integer(ContractId), ?CONTRACT_ID_TYPE),

    mw_lib:api_validation(is_binary(catch mw_lib:hex_to_bin(T3Signature1)),
                          ?SIGNATURE_TYPE),
    mw_lib:api_validation(
      mw_btc:bitcoin_signature_der(mw_lib:hex_to_bin(T3Signature1)),
      ?SIGNATURE_TYPE),

    mw_lib:api_validation(is_binary(catch mw_lib:hex_to_bin(T3Signature2)),
                          ?SIGNATURE_TYPE),
    mw_lib:api_validation(
      mw_btc:bitcoin_signature_der(mw_lib:hex_to_bin(T3Signature2)),
      ?SIGNATURE_TYPE),

    %% TODO: return more stuff in JSON response?
    _JSONRes = do_submit_t3_signatures(ContractId,
                                       T3Raw, T3Signature1, T3Signature2),
    [{<<"success-message">>, <<"ok">>}].

%%%===========================================================================
%%% Internal Erlang API (e.g. called by cron jobs / internal Mw services) but
%%% which may be exposed as JSON API later on
%%%===========================================================================
%% For MVP #2 this can be used for pages: prep, pend, sign and status
get_contract_t2_state(Id) ->
    {ok, Info}  = get_contract_info(Id),
    GetInfo     = ?GET(Info),
    History     = GetInfo("history"),
    EventPubkey = GetInfo("event_pubkey"),
    GiverPubkey = GetInfo("giver_ec_pubkey"),
    TakerPubkey = GetInfo("taker_ec_pubkey"),
    Value       = <<"70000">>,

    %% TODO: only return the strictly needed encrypted
    %% privkeys instead of all of them
    %% TODO: for now we simplify flow and assume both have sent T1
    %% when we get first T2 from Bj
    case {contract_event_happened(History, ?STATE_DESC_GIVER_ENTERED),
          contract_event_happened(History, ?STATE_DESC_TAKER_ENTERED),
          contract_event_happened(History, ?STATE_DESC_GIVER_T1),
          contract_event_happened(History, ?STATE_DESC_TAKER_T1)} of
        {true, true, false, false} ->
            %% call Bj to see if t1 outputs are available as t2 inputs
            case mw_btc:get_unsigned_t2(GiverPubkey, TakerPubkey,
                                        EventPubkey, Value) of
                {error, _} ->
                    %% no T1 outputs available; unchanged state
                    {ok, Info};
                {T2SigHashInput0, T2SigHashInput1, UnsignedT2} ->
                    T2SigHashInput0Hex = mw_lib:bin_to_hex(T2SigHashInput0),
                    T2SigHashInput1Hex = mw_lib:bin_to_hex(T2SigHashInput1),
                    UnsignedT2Hex = mw_lib:bin_to_hex(UnsignedT2),
                    ok = mw_pg:update_contract_t2(Id,
                                                  T2SigHashInput0Hex,
                                                  T2SigHashInput1Hex,
                                                  UnsignedT2Hex,
                                                  %% TODO: remove hash?
                                                  <<"">>),
                    ok = mw_pg:insert_contract_event(Id, ?STATE_DESC_GIVER_T1),
                    ok = mw_pg:insert_contract_event(Id, ?STATE_DESC_TAKER_T1),
                    {ok, NewInfo} = get_contract_info(Id),
                    {ok, NewInfo}
            end;
        {true, false, false, false} ->
            %% MVP #2 state: only default giver has entered, taker has not
            {ok, Info};
        {true, true, true, true} ->
            %% waiting for signatures; unchanged state
            {ok, Info}
    end.

get_contract_info(Id) ->
    {ok, MatchNo, Headline, Desc, Outcome,
     EventPubkey, GiverECPubkey, TakerECPubkey,
     GiverEncECPrivkey, TakerEncECPrivkey,
     GiverEncRSAPrivkey, TakerEncRSAPrivkey,
     EncEventKeyYes, EncEventKeyNo,
     T2SigHashInput0, T2SigHashInput1, T2Raw, T2Hash,
     FormatedEvents} =
        mw_pg:select_contract_info(Id),
    %% Some of these fields have same name as Postgres column names, but we
    %% avoid the temptation of using them directly to have separation between
    %% postgres schema and JSON API schema
    {ok, [
          {"match_no", MatchNo},
          {"headline", Headline},
          {"desc", Desc},
          {"outcome", Outcome},
          {"event_pubkey", EventPubkey},
          {"giver_ec_pubkey", GiverECPubkey},
          {"taker_ec_pubkey", TakerECPubkey},
          {"giver_enc_ec_privkey", GiverEncECPrivkey},
          {"taker_enc_ec_privkey", TakerEncECPrivkey},
          {"giver_enc_rsa_privkey", GiverEncRSAPrivkey},
          {"taker_enc_rsa_privkey", TakerEncRSAPrivkey},
          {"event_key_enc_with_oracle_yes_and_giver_keys", EncEventKeyYes},
          {"event_key_enc_with_oracle_no_and_taker_keys", EncEventKeyNo},
          {"t2_sighash_input_0", T2SigHashInput0},
          {"t2_sighash_input_1", T2SigHashInput1},
          {"t2_hash", T2Hash},
          {"t2_raw", T2Raw},
          {"history", lists:map(fun({Timestamp, Event}) ->
                                        [{"timestamp", Timestamp},
                                         {"event", Event}]
                                end, FormatedEvents)}
         ]}.

create_contract(EventId) ->
    {ok, ContractId} = mw_pg:insert_contract(EventId),
    ok = mw_pg:insert_contract_event(ContractId, ?STATE_DESC_CREATED),
    {ok, ContractId}.

clone_contract(Id) ->
    {ok, NewId} = mw_pg:clone_contract(Id),
    ok = mw_pg:insert_contract_event(NewId, ?STATE_DESC_CLONED),
    [{"new_contract_id", NewId}].

create_oracle_keys(NoPubkey, NoPrivkey, YesPubkey, YesPrivkey) ->
    %% Validations for EC keys
    %%mw_lib:api_validation(is_binary(NOPubkey), ?EC_PUBKEY_TYPE),
    %%mw_lib:api_validation(is_binary(YESPubkey), ?EC_PUBKEY_TYPE),
    %%mw_lib:api_validation((byte_size(NOPubkey) == 130), ?PUBKEY_LEN),
    %%mw_lib:api_validation((byte_size(YESPubkey) == 130), ?PUBKEY_LEN),
    {ok, Id} = mw_pg:insert_oracle_keys(NoPubkey, NoPrivkey,
                                        YesPubkey, YesPrivkey),
    {ok, Id}.

create_event(MatchNum, Headline, Desc, OracleKeysId,
             EventPrivkey, EventPubkey) ->
    {ok, NoPubkeyPEM, YesPubkeyPEM} = mw_pg:select_oracle_keys(OracleKeysId),
    {ok, NoPubkey}  = mw_lib:pem_decode_bin(NoPubkeyPEM),
    {ok, YesPubkey} = mw_lib:pem_decode_bin(YesPubkeyPEM),
    EventPrivkeyEncWithOracleNoKey =
        mw_lib:hybrid_aes_rsa_enc(EventPrivkey, NoPubkey),
    EventPrivkeyEncWithOracleYesKey =
        mw_lib:hybrid_aes_rsa_enc(EventPrivkey, YesPubkey),
    {ok, EventId} =
        mw_pg:insert_event(MatchNum, Headline, Desc, OracleKeysId, EventPubkey,
                           EventPrivkeyEncWithOracleNoKey,
                           EventPrivkeyEncWithOracleYesKey),
    {ok, EventId}.


add_event_outcome(EventId, Outcome) when (Outcome =:= true) orelse
                                         (Outcome =:= false) ->
    ok = mw_pg:update_event(EventId, Outcome),
    {ok, ContractIds} = mw_pg:select_contracts_of_event(EventId),
    Event = ?STATE_DESC_EVENT_OUTCOME_HAPPENED,
    [ok = mw_pg:insert_contract_event(Id, Event) || Id <- ContractIds],
    ok.

add_contract_outcome(ContractId, Outcome) when (Outcome =:= true) orelse
                                               (Outcome =:= false) ->
    {ok, EventId} = mw_pg:select_event_id(ContractId),
    ok = mw_pg:update_event(EventId, Outcome),
    {ok, ContractIds} = mw_pg:select_contracts_of_event(EventId),
    Event = ?STATE_DESC_EVENT_OUTCOME_HAPPENED,
    [ok = mw_pg:insert_contract_event(Id, Event) || Id <- ContractIds],
    ok.

%%%===========================================================================
%%% Internal functions
%%%===========================================================================
create_contract_event(Event) ->
    ok = mw_pg:insert_contract_event(Event),
    ok.

%% TODO: think about abstraction concerns regarding matching on postgres 'null'
%% TODO: this assumes giver always enters first
%% TODO: generalize
do_enter_contract(ContractId,
                  ECPubkey,
                  RSAPubkeyPEM,
                  EncECPrivkey,
                  EncRSAPrivkey) ->
    {ok, RSAPubkey} = mw_lib:pem_decode_bin(RSAPubkeyPEM),
    {YesOrNo, GiverOrTaker, _GiverKey} =
        case mw_pg:select_contract_ec_pubkeys(ContractId) of
            {ok, null, null}          -> {yes, giver, nope};
            {ok, GiverECPubkey, null} -> {no, taker, GiverECPubkey};
            {ok, _GiverECPubkey, _TakerECPubkey} ->
                ?API_ERROR(?CONTRACT_FULL);
            {error,{ok,[]}} ->
                ?API_ERROR(?CONTRACT_NOT_FOUND)
        end,
    {ok, EncEventKey} =
        mw_pg:select_enc_event_privkey(ContractId, YesOrNo),
    DoubleEncEventKey = mw_lib:hybrid_aes_rsa_enc(EncEventKey, RSAPubkey),
    ok = mw_pg:update_contract_enter(ContractId,
                                     GiverOrTaker,
                                     ECPubkey,
                                     RSAPubkeyPEM,
                                     EncECPrivkey,
                                     EncRSAPrivkey,
                                     DoubleEncEventKey),
    EnteredEvent = case GiverOrTaker of
                       giver -> ?STATE_DESC_GIVER_ENTERED;
                       taker -> ?STATE_DESC_TAKER_ENTERED
                   end,
    ok = mw_pg:insert_contract_event(ContractId, EnteredEvent),
    ok.

do_submit_t2_signature(ContractId, ECPubkey, TakerT2Signature) ->
    {ok, Info}      = get_contract_info(ContractId),
    GetInfo         = ?GET(Info),
    TakerECPubkey   = GetInfo("taker_ec_pubkey"),
    case ECPubkey =:= TakerECPubkey of
        false -> ?API_ERROR(?EC_PUBKEY_MISMATCH);
        true -> continue
    end,
    GiverECPubkey   = GetInfo("giver_ec_pubkey"),
    UnsignedT2      = GetInfo("t2_raw"),
    T2SigHashInput0 = GetInfo("t2_sighash_input_0"),
    {ok, ECPrivkey0} =
        file:read_file(filename:join(code:priv_dir(middle_server),
                                     "test_keys/giver_keys5_compressed/ec_privkey")),
    GiverECPrivkey = binary:replace(ECPrivkey0, <<"\n">>, <<>>),

    {ok, FinalT2, FinalT2TxHash} =
        mw_btc:sign_and_submit_t2_signatures(TakerECPubkey,
                                             GiverECPrivkey,
                                             GiverECPubkey,
                                             TakerT2Signature,
                                             T2SigHashInput0,
                                             UnsignedT2),
    ok = mw_pg:update_contract_t2(ContractId, FinalT2, FinalT2TxHash),
    ok = mw_pg:insert_contract_event(ContractId, ?STATE_DESC_TAKER_SIGNED_T2),
    ok = mw_pg:insert_contract_event(ContractId, ?STATE_DESC_GIVER_SIGNED_T2),
    ok = mw_pg:insert_contract_event(ContractId, ?STATE_DESC_T2_BROADCASTED),
    ok.

do_get_t3_for_signing(ContractId, ToAddress) ->
    {ok, Info}  = get_contract_info(ContractId),
    GetInfo     = ?GET(Info),
    History     = GetInfo("history"),
    %% TODO: only return the strictly needed encrypted
    %% privkeys instead of all of them
    case {contract_event_happened(History, ?STATE_DESC_T2_BROADCASTED),
          contract_event_happened(History, ?STATE_DESC_EVENT_OUTCOME_HAPPENED),
          contract_event_happened(History, ?STATE_DESC_T3_BROADCASTED)} of
        {false, false, false} ->
            %% If called before T3 can be created
            ?API_ERROR(?CONTRACT_T2_NOT_COMPLETE);
        {true, false, false} ->
            %% Event outcome has not happened yet
            ?API_ERROR(?NO_EVENT_OUTCOME);
        {true, true, false} ->
            %% T2 broadcasted, event outcome happened, time to grab T3 from Bj.
            FinalT2Hash = GetInfo("t2_hash"),
            FinalT2     = GetInfo("t2_raw"),
            %% TODO: fucking encoding consistency
            {T3Sighash, UnsignedT3} =
                mw_btc:get_unsigned_t3(FinalT2,
                                       mw_lib:hex_to_bin(FinalT2Hash),
                                       ToAddress),
            %% TODO: here we act as oracle, sending oracle yes/no privkey
            %% depending on event outcome. In future, this could be done by
            %% external oracle(s) and we would instead grab it from e.g. their
            %% website or somesuch
            {YesOrNo, EventKeyName} =
                case GetInfo("outcome") of
                    true ->
                        {yes, "event_key_enc_with_oracle_yes_and_giver_keys"};
                    false ->
                        {no, "event_key_enc_with_oracle_no_and_taker_keys"}
                end,
            {ok, OPK} = mw_pg:select_oracle_privkey(ContractId, YesOrNo),
            EncEventKey = mw_lib:bin_to_hex(GetInfo(EventKeyName)),
            [
             %% TODO: improve this mapping and also what enc keys are returned
             {"giver_enc_ec_privkey", GetInfo("giver_enc_ec_privkey")},
             {"taker_enc_ec_privkey", GetInfo("taker_enc_ec_privkey")},
             {"giver_enc_rsa_privkey", GetInfo("giver_enc_rsa_privkey")},
             {"taker_enc_rsa_privkey", GetInfo("taker_enc_rsa_privkey")},
             {"oracle_privkey", base64:encode(OPK)}, %% Avoids line breaks in JS
             {"enc_event_privkey", EncEventKey},
             {"t3-sighash", mw_lib:bin_to_hex(T3Sighash)},
             {"t3-hash", mw_lib:bin_to_hex(T3Sighash)},
             {"t3-raw", mw_lib:bin_to_hex(UnsignedT3)}
            ];
        {true, true, true} ->
            %% T3 broadcasted: end state of contract.
            ?API_ERROR(?CONTRACT_FINISHED)
    end.

do_submit_t3_signatures(ContractId, T3RawHex, T3Signature1Hex, T3Signature2Hex) ->
    T3Raw        = mw_lib:hex_to_bin(T3RawHex),
    T3Signature1 = mw_lib:hex_to_bin(T3Signature1Hex),
    T3Signature2 = mw_lib:hex_to_bin(T3Signature2Hex),
    {ok, FinalT3, FinalT3TxHash} =
        mw_btc:submit_t3_signatures(T3Raw, T3Signature1, T3Signature2),
    ok = mw_pg:insert_contract_event(ContractId, ?STATE_DESC_SIGNED_T3),
    [
     {"new-t3-hash", FinalT3TxHash},
     {"new-t3-raw", FinalT3}
    ].

contract_event_happened(History, Event) ->
    %% contract history is list of list of two two tuples; timestamp and event
    case lists:filter(fun([_,{_, E}]) when E =:= Event -> true;
                         (_) -> false end,
                      History) of
        %% TODO: re-enable check for duplicated events once Bj mocks do not
        %% create duplicated events
        %% Explicit match instead of e.g. lists:any/2
        %% to enforce no duplicated events
        []  -> false;
        [_] -> true;
        _   -> true
    end.

rsa_key_from_file(PrivPath) ->
    AbsPath = filename:join(code:priv_dir(middle_server), PrivPath),
    {ok, Bin} = file:read_file(AbsPath),
    %%{ok, Key} = mw_lib:pem_decode_bin(Bin),
    Bin.
