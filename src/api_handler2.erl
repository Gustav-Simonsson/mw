%%%-------------------------------------------------------------------
%%% @author Gustav Simonsom <gustav.simonson@gmail.com>
%%% @copyright (C) 2014, AI Effect Group, Berlin. All rights reserved.
%%% @doc
%%% New backend API for android client.
%%%
%%% References:
%%% 1. http://docs.gustavsimonsson.apiary.io/
%%%
%%% @end
%%% Created : 22 Sep 2014 by gustav <gustav.simonsson@gmail.com>
%%%-------------------------------------------------------------------
-module(api_handler2).

%% REST Callbacks
-export([init/2]).
-export([rest_init/2]).
-export([allowed_methods/2]).
-export([resource_exists/2]).
-export([content_types_provided/2]).

%% Callback Callbacks
-export([response/2]).

-include("log.hrl").

%% ----------------------------------------------------------------------------
%% Cowboy Callbacks
%% ----------------------------------------------------------------------------
init(Req, Opts) ->
    {cowboy_rest, Req, Opts}.

rest_init(Req, Paths) ->
    {ok, Req, Paths}.

allowed_methods(Req, State) ->
    {[<<"GET">>], Req, State}.

resource_exists(Req, State) ->
    {true, Req, State}.

content_types_accepted(Req, State) ->
        {[{{<<"application">>, <<"json">>, '*'}, handle_post}
    ], Req, State}.

content_types_provided(Req, State) ->
    {[
      {{<<"application">>, <<"json">>, '*'}, response},
      {{<<"text">>, <<"plain">>, '*'}, response},
      {{<<"text">>, <<"html">>, '*'}, response}
     ], Req, State}.

handle_post(Req, State) ->
    Body = <<"<h1>Hacking and cold women at room 77.</h1>">>,
    {ok, Req2} = cowboy_req:reply(200, [], Body, Req),
    {true, Req2, State}.

%% ----------------------------------------------------------------------------
%% Responses
%% ----------------------------------------------------------------------------
%% The second parameter here is the third in the dispatch tuples of the hosts.
response(Req, 'get-contract-state'=State) ->
    HandleFun =
        fun() ->
                ?info("Req: ~p State:~p", [Req, State]),
                [{contractid, Id0}] = cowboy_req:bindings(Req),
                ContractId = erlang:list_to_integer(binary:bin_to_list(Id0)),
                {ok, Response} = mw_contract2:get_contract_state(ContractId),
                ?info("Response: ~p", [Response]),
                Response
        end,
    JSON = mw_lib:json_try_catch_handler(HandleFun),
    ?info("Response JSON: ~p", [JSON]),
    {JSON, Req, State};

response(Req, 'clone-contract'=State) ->
    HandleFun =
        fun() ->
                ?info("Req: ~p State:~p", [Req, State]),
                [{contractid, Id0}] = cowboy_req:bindings(Req),
                ContractId = erlang:list_to_integer(binary:bin_to_list(Id0)),
                {NewId} = mw_contract2:clone_contract(ContractId),
                Response = [{<<"new_contract_id">>, NewId}],
                ?info("Response: ~p", [Response]),
                Response
        end,
    JSON = mw_lib:json_try_catch_handler(HandleFun),
    ?info("Response JSON: ~p", [JSON]),
    {JSON, Req, State};

response(Req, 'enter-contract'=State) ->
    HandleFun =
        fun() ->
                ?info("Req: ~p State:~p", [Req, State]),
                [{contractid, Id0}] = cowboy_req:bindings(Req),
                ContractId = erlang:list_to_integer(binary:bin_to_list(Id0)),
                #{ec_pubkey := ECPubkey, rsa_pubkey := RSAPubkey} =
                    cowboy_req:match_qs([ec_pubkey, rsa_pubkey], Req),
                ok = mw_contract2:enter_contract(ContractId, ECPubkey, RSAPubkey),
                Response = [{<<"success_message">>, <<"ok">>}],
                ?info("Response: ~p", [Response]),
                Response
        end,
    JSON = mw_lib:json_try_catch_handler(HandleFun),
    ?info("Response JSON: ~p", [JSON]),
    {JSON, Req, State};

response(Req, 'submit-t2-signature'=State) ->
    HandleFun =
        fun() ->
                ?info("Req: ~p State:~p", [Req, State]),
                [{contractid, Id0}] = cowboy_req:bindings(Req),
                ContractId = erlang:list_to_integer(binary:bin_to_list(Id0)),
                #{ec_pubkey := ECPubkey, t2_signature := T2Signature} =
                    cowboy_req:match_qs([ec_pubkey, t2_signature], Req),
                {FinalT2Raw, FinalT2Hash} =
                    mw_contract2:submit_t2_signature(ContractId,
                                                     ECPubkey, T2Signature),
                Response = [{<<"success_message">>, <<"ok">>},
                            {<<"final_t2_raw">>, FinalT2Raw},
                            {<<"final_t2_hash">>, FinalT2Hash}
                           ],
                ?info("Response: ~p", [Response]),
                Response
        end,
    JSON = mw_lib:json_try_catch_handler(HandleFun),
    ?info("Response JSON: ~p", [JSON]),
    {JSON, Req, State};

response(Req, 'get-t3-for-signing'=State) ->
    HandleFun =
        fun() ->
                ?info("Req: ~p State:~p", [Req, State]),
                [{contractid, Id0}] = cowboy_req:bindings(Req),
                ContractId = erlang:list_to_integer(binary:bin_to_list(Id0)),
                #{to_address := ToAddress} =
                    cowboy_req:match_qs([to_address], Req),
                {T3Sighash, T3Raw, OraclePrivkey, EncEventPrivkey} =
                    mw_contract2:get_t3_for_signing(ContractId, ToAddress),
                Response = [{<<"success_message">>, <<"ok">>},
                            {<<"t3_sighash">>, T3Sighash},
                            {<<"t3_raw">>, T3Raw},
                            {<<"oracle_privkey">>, OraclePrivkey},
                            {<<"enc_event_privkey">>, EncEventPrivkey}
                           ],
                ?info("Response: ~p", [Response]),
                Response
        end,
    JSON = mw_lib:json_try_catch_handler(HandleFun),
    ?info("Response JSON: ~p", [JSON]),
    {JSON, Req, State};

response(Req, 'submit-t3-signatures'=State) ->
    HandleFun =
        fun() ->
                ?info("Req: ~p State:~p", [Req, State]),
                [{contractid, Id0}] = cowboy_req:bindings(Req),
                ContractId = erlang:list_to_integer(binary:bin_to_list(Id0)),
                #{t3_signature1 := T3Signature1,
                  t3_signature2 := T3Signature2} =
                    cowboy_req:match_qs([t3_signature1, t3_signature2], Req),
                {FinalT3Hash, FinalT3Raw} =
                    mw_contract2:submit_t3_signatures(ContractId,
                                                      T3Signature1,
                                                      T3Signature2),
                Response = [{<<"success_message">>, <<"ok">>},
                            {<<"final_t3_raw">>, FinalT3Raw},
                            {<<"final_t3_hash">>, FinalT3Hash}
                           ],
                ?info("Response: ~p", [Response]),
                Response
        end,
    JSON = mw_lib:json_try_catch_handler(HandleFun),
    ?info("Response JSON: ~p", [JSON]),
    {JSON, Req, State}.

%%%===========================================================================
%%% Internal functions
%%%===========================================================================
