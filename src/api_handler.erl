%%%-------------------------------------------------------------------------%%%
%%% Description : Mw - AI Effect World Cup 2014 - Middle Server             %%%
%%% Version     : 0.6.x/json calls                                          %%%
%%% File        : api_handler.erl                                           %%%
%%% Description : json response generation, as a handler for Cowboy         %%%
%%% Copyright   : AI Effect Group, Berlin. All rights reserved.             %%%
%%% Author      : H. Diedrich <hd2010@eonblast.com>                         %%%
%%% Created     : 29 May 2014                                               %%%
%%% Changed     : 22 Jun 2014                                               %%%
%%%-------------------------------------------------------------------------%%%
-module(api_handler).

%% REST Callbacks
-export([init/3]).
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
init(_Transport, _Req, _Paths) ->
    {upgrade, protocol, cowboy_rest}.

rest_init(Req, Paths) ->
    {ok, Req, Paths}.

allowed_methods(Req, State) ->
    {[<<"GET">>, <<"POST">>], Req, State}.

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
    Body = <<"<h1>Football, hacking and beautiful women at room 77.</h1>">>,
    {ok, Req2} = cowboy_req:reply(200, [], Body, Req),
    {true, Req2, State}.

%% ----------------------------------------------------------------------------
%% Responses
%% ----------------------------------------------------------------------------
response(Req, 'enter-contract'=State) ->
    HandleFun =
        fun() ->
                ?info("Req: ~p State:~p", [Req, State]),
                JSON = cowboy_req:binding('json', Req),
                ?info("JSON: ~p", [JSON]),
                {[{<<"contract_id">>, ContractId0},
                  {<<"ec_pubkey">>, ECPubKey},
                  {<<"rsa_pubkey">>, RSAPubKey},
                  {<<"enc_ec_privkey">>, EncECPrivkey},
                  {<<"enc_rsa_privkey">>, EncRSAPrivkey}
                 ]} = jiffy:decode(JSON),
                ContractId = erlang:list_to_integer(
                               binary:bin_to_list(ContractId0)),
                Response = mw_contract:enter_contract(ContractId,
                                                      ECPubKey,
                                                      RSAPubKey,
                                                      EncECPrivkey,
                                                      EncRSAPrivkey),
                ?info("Response: ~p", [Response]),
                Response
        end,
    JSON = handle_response(HandleFun),
    ?info("Response JSON: ~p", [JSON]),

    %% Enable browser CORS
    Req1 = mw_lib:cowboy_req_enable_cors(Req),
    {JSON, Req1, State};

response(Req, 'clone-contract'=State) ->
    HandleFun =
        fun() ->
                ?info("Req: ~p State:~p", [Req, State]),
                JSON = cowboy_req:binding('json', Req),
                {[{<<"contract_id">>, ContractId0}]} = jiffy:decode(JSON),
                ContractId = erlang:list_to_integer(
                               binary:bin_to_list(ContractId0)),
                Response = mw_contract:clone_contract(ContractId),
                ?info("Response: ~p", [Response]),
                Response
        end,
    JSON = handle_response(HandleFun),
    ?info("Response JSON: ~p", [JSON]),
    {JSON, Req, State};

response(Req, 'submit-t2-signature'=State) ->
    HandleFun =
        fun() ->
                ?info("Req: ~p State:~p", [Req, State]),
                JSON = cowboy_req:binding('json', Req),
                {[{<<"contract_id">>, ContractId0},
                  {<<"ec_pubkey">>, ECPubKey},
                  {<<"t2_signature">>, T2Signature}]} = jiffy:decode(JSON),
                ContractId = erlang:list_to_integer(
                               binary:bin_to_list(ContractId0)),
                Response = mw_contract:submit_t2_signature(ContractId, ECPubKey,
                                                           T2Signature),
                ?info("Response: ~p", [Response]),
                Response
        end,
    JSON = handle_response(HandleFun),
    ?info("Response JSON: ~p", [JSON]),
    {JSON, Req, State};

response(Req, 'get-t3-for-signing'=State) ->
    HandleFun =
        fun() ->
                ?info("Req: ~p State:~p", [Req, State]),
                %% {ContractId0, _} = cowboy_req:qs_val(<<"contract_id">>, Req),
                %% {ToAddress, _} = cowboy_req:qs_val(<<"to_address">>, Req),
                JSON = cowboy_req:binding('json', Req),
                {[{<<"contract_id">>, ContractId0},
                  {<<"to_address">>, ToAddress}]} = jiffy:decode(JSON),
                ContractId = erlang:list_to_integer(
                               binary:bin_to_list(ContractId0)),
                Response =
                    mw_contract:get_t3_for_signing(ContractId, ToAddress),
                ?info("Response: ~p", [Response]),
                Response
        end,
    JSON = handle_response(HandleFun),
    ?info("Response JSON: ~p", [JSON]),
    {JSON, Req, State};

response(Req, 'submit-t3-signatures'=State) ->
    HandleFun =
        fun() ->
                ?info("Req: ~p State:~p", [Req, State]),
                JSON = cowboy_req:binding('json', Req),
                ?info("HURR JSON: ~p", [JSON]),
                {[{<<"contract_id">>, ContractId0},
                  {<<"t3_raw">>, T3Raw},
                  {<<"t3_signature1">>, T3Signature1},
                  {<<"t3_signature2">>, T3Signature2}
                 ]} = jiffy:decode(JSON),
                ContractId = erlang:list_to_integer(
                               binary:bin_to_list(ContractId0)),
                Response = mw_contract:submit_t3_signatures(ContractId,
                                                            T3Raw,
                                                            T3Signature1,
                                                            T3Signature2),
                ?info("Response: ~p", [Response]),
                Response
        end,
    JSON = handle_response(HandleFun),
    ?info("Response JSON: ~p", [JSON]),
    {JSON, Req, State}.

%% Single, top-level try catch to ensure we return correct JSON error code / msg
%% for all handled errors, with a default for any unhandled error (crash).
%% This allows code deeper in the stack to be written in idiomatic Erlang style
%% for the correct case, without defensive coding.
handle_response(HandleFun) ->
    try
        Response = HandleFun(),
        %% ?info("Response: ~p", [Response]),
        jiffy:encode({Response})
    catch throw:{api_error, {ErrorCode, ErrorMsg}} ->
            ?error("Handled API Error Code: ~p : ~p", [ErrorCode, ErrorMsg]),
            jiffy:encode({[{<<"error-code">>, ErrorCode}, {<<"error-message">>, ErrorMsg}]});
          Error:Reason ->
            Stack = erlang:get_stacktrace(),
            ?error("Unhandled Error: ~p Reason: ~p Stack: ~p",
                   [Error, Reason, Stack]),
            jiffy:encode({[{<<"error-code">>, 0},
                           {<<"error-message">>,
                            <<"Something is on fire. Don't panic. "
                              "Blame Gustav.">>}]})
    end.
