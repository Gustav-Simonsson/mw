%%%-------------------------------------------------------------------
%%% @author Gustav Simonsom <gustav.simonson@gmail.com>
%%% @copyright (C) 2014, AI Effect Group, Berlin. All rights reserved.
%%% @doc
%%% Contract logic. New iteration for new android API.
%%%
%%% Persistent contract state is maintained in postgres contract tables.
%%% The state is modified by events such as:
%%%     * Enter a bet
%%%     * Sign a bet (T2),
%%%     * Cashing out a won bet (T3)
%%%
%%% @end
%%% Created : 25 Sep 2014 by gustav <gustav.simonsson@gmail.com>
%%%-------------------------------------------------------------------
-module(mw_contract2).

-compile(export_all).
%% API
-export([]). %% TODO: remove export_all and add API exports

-include("mw.hrl").
-include("btc.hrl").
-include("mw_contract.hrl").
-include("log.hrl").
-include("mw_api_errors.hrl").

-define(GET(PL), fun(Key) -> proplists:get_value(Key, PL, not_found) end).

%%%===========================================================================
%%% API (called from cowboy JSON handler callbacks)
%%%===========================================================================
get_contract_state(Id) ->
    ?info("get_contract_state: ContractId: ~p", [Id]),
    mw_lib:api_validation(is_integer(Id), ?CONTRACT_ID_TYPE),
        {ok, Info}  = get_contract_info(Id),
    GetInfo     = ?GET(Info),
    History     = GetInfo(<<"history">>),
    EventPubkey = GetInfo(<<"event_pubkey">>),
    GiverPubkey = GetInfo(<<"giver_ec_pubkey">>),
    TakerPubkey = GetInfo(<<"taker_ec_pubkey">>),
    Value       = list_to_binary(
                    integer_to_list((?T1_AMOUNT_INT * 2) - ?BITCOIN_MIN_FEE)),

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
            {ok, Info};
        {false, false, false, false} ->
            %% Fresh contract without anyone entered
            {ok, Info}
    end.

clone_contract(Id) ->
    ?info("clone_contract: ContractId: ~p", [Id]),
    mw_lib:api_validation(is_integer(Id), ?CONTRACT_ID_TYPE),
    {ok, NewId} = mw_pg:clone_contract(Id),
    ok = mw_pg:insert_contract_event(NewId, ?STATE_DESC_CLONED),
    {NewId}.

enter_contract(ContractId, ECPubkey, RSAPubkey) ->
    ?info("enter_contract: ContractId: ~p , ECPubkey: ~p, RSAPubkey: ~p",
          [ContractId, ECPubkey, RSAPubkey]),
    mw_lib:api_validation(is_integer(ContractId), ?CONTRACT_ID_TYPE),
    %% https://en.bitcoin.it/wiki/Base58Check_encoding
    %% compressed EC pubkeys in base58check encoding is 50 chars
    mw_lib:api_validation(is_binary(ECPubkey) andalso
                   is_binary(catch mw_lib:dec_b58check(ECPubkey)),
                   ?EC_PUBKEY_TYPE),
    mw_lib:api_validation((byte_size(ECPubkey) == 50), ?EC_PUBKEY_LEN),
    mw_lib:api_validation(
      is_binary(RSAPubkey) andalso
      %% http://erlang.org/doc/man/public_key.html#pem_decode-1
      (catch length(public_key:pem_decode(base64:decode(RSAPubkey)))) == 1,
      ?RSA_PUBKEY_TYPE),

    {ok, DecodedRSAPubkey} =
        mw_lib:pem_decode_bin(RSAPubkeyPEM = base64:decode(RSAPubkey)),
    {ok, EncEventKey} = mw_pg:select_enc_event_privkey(ContractId, no),
    DoubleEncEventKey = mw_lib:hybrid_aes_rsa_enc(EncEventKey, DecodedRSAPubkey),
    ok = mw_pg:update_contract_enter(ContractId,
                                     taker,
                                     ECPubkey,
                                     RSAPubkeyPEM,
                                     <<"">>,
                                     <<"">>,
                                     DoubleEncEventKey),
    ok = mw_pg:insert_contract_event(ContractId, ?STATE_DESC_TAKER_ENTERED),
    ok.

submit_t2_signature(ContractId, ECPubkey, TakerT2Signature) ->
    ?info("submit_t2_signature: ContractId: ~p , "
          "ECPubkey: ~p, TakerT2Signature: ~p",
          [ContractId, ECPubkey, TakerT2Signature]),
    mw_lib:api_validation(is_integer(ContractId), ?CONTRACT_ID_TYPE),
    mw_lib:api_validation(is_binary(ECPubkey) andalso
                   is_binary(catch mw_lib:dec_b58check(ECPubkey)),
                   ?EC_PUBKEY_TYPE),
    mw_lib:api_validation((byte_size(ECPubkey) == 50), ?EC_PUBKEY_LEN),
    mw_lib:api_validation(is_binary(catch mw_lib:hex_to_bin(TakerT2Signature)),
                   ?SIGNATURE_TYPE),
    mw_lib:api_validation(
      mw_btc:bitcoin_signature_der(mw_lib:hex_to_bin(TakerT2Signature)),
      ?SIGNATURE_TYPE),

    {ok, Info}      = get_contract_info(ContractId),
    GetInfo         = ?GET(Info),
    TakerECPubkey   = GetInfo(<<"taker_ec_pubkey">>),
    case ECPubkey =:= TakerECPubkey of
        false -> ?API_ERROR(?EC_PUBKEY_MISMATCH);
        true -> continue
    end,
    GiverECPubkey   = GetInfo(<<"giver_ec_pubkey">>),
    UnsignedT2      = GetInfo(<<"t2_raw">>),
    T2SigHashInput0 = GetInfo(<<"t2_sighash_input_0">>),
    Dir = "test_keys/giver_keys5_compressed/ec_privkey",
    {ok, ECPrivkey0} = file:read_file(filename:join(
                                        code:priv_dir(middle_server), Dir)),

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
    {FinalT2, FinalT2TxHash}.

get_t3_for_signing(ContractId, ToAddress) ->
    ?info("get_t3_for_signing: ContractId: ~p , ToAddress: ~p ",
          [ContractId, ToAddress]),
    mw_lib:api_validation(is_integer(ContractId), ?CONTRACT_ID_TYPE),
    mw_lib:api_validation(is_binary(ToAddress) andalso
                   is_binary(catch mw_lib:dec_b58check(ToAddress)),
                   ?ADDRESS_TYPE),
    mw_lib:api_validation((byte_size(ToAddress) >= 27) andalso
                   (byte_size(ToAddress) =< 34),
                   ?ADDRESS_LEN),
    {ok, Info}  = get_contract_info(ContractId),
    GetInfo     = ?GET(Info),
    History     = GetInfo(<<"history">>),
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
            %% T2 broadcasted, event outcome happened; T3 can be constructed
            FinalT2Hash = GetInfo(<<"t2_hash">>),
            FinalT2     = GetInfo(<<"t2_raw">>),
            %% TODO: fucking encoding consistency
            {T3Sighash, UnsignedT3} =
                mw_btc:get_unsigned_t3(FinalT2,
                                       mw_lib:hex_to_bin(FinalT2Hash),
                                       ToAddress),
            ok = mw_pg:update_contract_t3(ContractId, UnsignedT3),
            %% TODO: here we act as oracle, sending oracle yes/no privkey
            %% depending on event outcome. In future, this could be done by
            %% external oracle(s) such as reality keys
            {YesOrNo, EventKeyName} =
                case GetInfo(<<"outcome">>) of
                    true ->
                        {yes, "event_key_enc_with_oracle_yes_and_giver_keys"};
                    false ->
                        {no, "event_key_enc_with_oracle_no_and_taker_keys"}
                end,
            {ok, OPK} = mw_pg:select_oracle_privkey(ContractId, YesOrNo),
            EncEventKey = mw_lib:bin_to_hex(GetInfo(EventKeyName)),
            {mw_lib:bin_to_hex(T3Sighash),
             mw_lib:bin_to_hex(UnsignedT3),
             base64:encode(OPK), %% Avoid PEM line breaks issues on the wire
             EncEventKey};
        {true, true, true} ->
            %% T3 broadcasted: end state of contract.
            ?API_ERROR(?CONTRACT_FINISHED)
    end.

submit_t3_signatures(ContractId, T3Signature1Hex, T3Signature2Hex) ->
    ?info("submit_t3_signatures: ContractId: ~p , "
          "T3Signature: ~p , T3Signature2: ~p",
          [ContractId, T3Signature1Hex, T3Signature2Hex]),
    mw_lib:api_validation(is_integer(ContractId), ?CONTRACT_ID_TYPE),
    mw_lib:api_validation(is_binary(catch mw_lib:hex_to_bin(T3Signature1Hex)),
                   ?SIGNATURE_TYPE),
    mw_lib:api_validation(
      mw_btc:bitcoin_signature_der(mw_lib:hex_to_bin(T3Signature1Hex)),
      ?SIGNATURE_TYPE),
    mw_lib:api_validation(
      is_binary(catch mw_lib:hex_to_bin(T3Signature2Hex)),
      ?SIGNATURE_TYPE),
    mw_lib:api_validation(
      mw_btc:bitcoin_signature_der(mw_lib:hex_to_bin(T3Signature2Hex)),
      ?SIGNATURE_TYPE),

    {ok, Info}      = get_contract_info(ContractId),
    GetInfo         = ?GET(Info),
    UnsignedT3Hex = GetInfo(<<"t3_raw">>),
    UnsignedT3   = mw_lib:hex_to_bin(UnsignedT3Hex),
    T3Signature1 = mw_lib:hex_to_bin(T3Signature1Hex),
    T3Signature2 = mw_lib:hex_to_bin(T3Signature2Hex),
    {ok, FinalT3, FinalT3TxHash} =
        mw_btc:submit_t3_signatures(UnsignedT3, T3Signature1, T3Signature2),
    ok = mw_pg:insert_contract_event(ContractId, ?STATE_DESC_SIGNED_T3),
    {FinalT3TxHash, FinalT3}.

%%%===========================================================================
%%% Internal functions
%%%===========================================================================
get_contract_info(Id) ->
    {ok, Headline, Outcome,
     EventPubkey, GiverECPubkey, TakerECPubkey,
     GiverEncECPrivkey, TakerEncECPrivkey,
     GiverEncRSAPrivkey, TakerEncRSAPrivkey,
     EncEventKeyYes0, EncEventKeyNo0,
     T2SigHashInput0, T2SigHashInput1, T2Raw, T2Hash, T3Raw, T3Hash,
     FormatedEvents} =
        mw_pg:select_contract_info(Id),
    HexOrEmpty = fun(null) -> <<"">>;
                    (B) when is_binary(B) -> mw_lib:bin_to_hex(B)
                 end,
    EncEventKeyYes = HexOrEmpty(EncEventKeyYes0),
    EncEventKeyNo = HexOrEmpty(EncEventKeyNo0),
    %% Some of these fields have same name as Postgres column names, but we
    %% avoid the temptation of using them directly to have separation between
    %% postgres schema and JSON API schema
    {ok, [
          {<<"headline">>, Headline},
          {<<"outcome">>, Outcome},
          {<<"event_pubkey">>, EventPubkey},
          {<<"giver_ec_pubkey">>, GiverECPubkey},
          {<<"taker_ec_pubkey">>, TakerECPubkey},
          {<<"giver_enc_ec_privkey">>, GiverEncECPrivkey},
          {<<"taker_enc_ec_privkey">>, TakerEncECPrivkey},
          {<<"giver_enc_rsa_privkey">>, GiverEncRSAPrivkey},
          {<<"taker_enc_rsa_privkey">>, TakerEncRSAPrivkey},
          {<<"event_key_enc_with_oracle_yes_and_giver_keys">>,
           mw_lib:bin_to_hex(EncEventKeyYes)},
          {<<"event_key_enc_with_oracle_no_and_taker_keys">>,
           mw_lib:bin_to_hex(EncEventKeyNo)},
          {<<"t2_sighash_input_0">>, T2SigHashInput0},
          {<<"t2_sighash_input_1">>, T2SigHashInput1},
          {<<"t2_hash">>, T2Hash},
          {<<"t2_raw">>, T2Raw},
          {<<"t3_hash">>, T3Hash},
          {<<"t3_raw">>, T3Raw},
          {<<"history">>, lists:map(fun({Timestamp, Event}) ->
                                        [{<<"timestamp">>, Timestamp},
                                         {<<"event">>, Event}]
                                end, FormatedEvents)}
         ]}.

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
