%%%-------------------------------------------------------------------------%%%
%%% Description : Mw - AI Effect World Cup 2014 - Middle Server             %%%
%%% Version     : 0.5.x/first round trip                                    %%%
%%% File        : middle_server_app.erl                                     %%%
%%% Description : main module, starting the Cowboy host                     %%%
%%% Copyright   : AI Effect Group, Berlin. All rights reserved.             %%%
%%% Author      : H. Diedrich <hd2010@eonblast.com>                         %%%
%%% Created     : 24 May 2014                                               %%%
%%% Changed     : 22 June 2014                                              %%%
%%%-------------------------------------------------------------------------%%%
%%%                                                                         %%%
%%%  The AIX WC14 concept enables football bets on the Bitcoin blockchain   %%%
%%%  that are decentralized, oracle-driven contracts, requiring less trust. %%%
%%%                                                                         %%%
%%%-------------------------------------------------------------------------%%%

-module(middle_server_app).
-behaviour(application).

-export([start/2]).
-export([stop/1]).

-include("log.hrl").

start(_Type, _Args) ->
    %% TODO: extract to node config file
    application:load(lager),
    application:load(mw),
    %% TODO: application:ensure_all_started
    application:set_env(lager, error_logger_hwm, 500),
    application:start(lager),
    try
        MwPriv = code:priv_dir(middle_server),
        ConfigFile = filename:join([MwPriv, "config/node_config"]),
        {ok, [Configs]} = file:consult(ConfigFile),
        lists:map(fun({App, Param, Value}) ->
                          ok = application:set_env(App, Param, Value)
                  end, Configs)
    catch E:R ->
            ?error("Mw node config error: ~p", [{E,R,erlang:get_stacktrace()}]),
            exit(mw_config_error)
    end,
    application:start(jiffy),

    %% -------------------------------------------------------------------
    %% API
    %% -------------------------------------------------------------------
    %% define json hosts, pathes, their patterns and handlers
    JSONDispatch =
        cowboy_router:compile(
          [
           {'_',
            [{"/hello", api_handler, hello},
             {"/sample", api_handler, sample},
             {"/bet-list", api_handler, 'bet-list'},
             {"/enter-contract/:json", api_handler, 'enter-contract'},
             {"/clone-contract/:json", api_handler, 'clone-contract'},
             {"/submit-t2-signature/:json", api_handler, 'submit-t2-signature'},
             {"/get-t3-for-signing/:json", api_handler, 'get-t3-for-signing'},
             {"/submit-t3-signatures/:json", api_handler, 'submit-t3-signatures'}
            ]
           }
          ]),

    %% start cowboy json server
    {ok, _} = cowboy:start_http(json, 100, [{port, 8081}],
                                [
                                 {env, [{dispatch, JSONDispatch}]},
                                 {middlewares, [cowboy_router, cowboy_handler]}
                                ]),

    %% -------------------------------------------------------------------
    %% New API for android client
    %% -------------------------------------------------------------------
    %% define json hosts, pathes, their patterns and handlers
    Routes =
        [
         {'_',
          [
           {"/get-contract-state/:contractid", api_handler2, 'get-contract-state'},
           {"/clone-contract/:contractid", api_handler2, 'clone-contract'},
           {"/enter-contract/:contractid", api_handler2, 'enter-contract'},
           {"/submit-t2-signature/:contractid", api_handler2, 'submit-t2-signature'},
           {"/get-t3-for-signing/:contractid", api_handler2, 'get-t3-for-signing'},
           {"/submit-t3-signatures/:contractid", api_handler2, 'submit-t3-signatures'}
          ]
         }
        ],
    JSONDispatch2 = cowboy_router:compile(Routes),

    %% start cowboy json server
    {ok, _} = cowboy:start_http(json2, 100, [{port, 8082}],
                                [
                                 {env, [{dispatch, JSONDispatch2}]},
                                 {middlewares, [cowboy_router, cowboy_handler]}
                                ]),

    %% -------------------------------------------------------------------
    %% Web Site
    %% -------------------------------------------------------------------
    %% define http hosts, pathes, their patterns and handlers
    HTMLDispatch = cowboy_router:compile(
                     [
                      {'_', [
                             {"/",              page_handler, {bets}},
                             {"/prep/:id",      page_handler, {prep}},
                             {"/pend.html",     page_handler, {pend}},
                             {"/sign/:id",      page_handler, {sign}},
                             {"/followup.html", page_handler, {followup}},
                             {"/status/:id",    page_handler, {status}},
                             {"/cashout/:id",   page_handler, {cashout}},
                             {"/cashout2/:id",  page_handler, {cashout2}},
                             {"/wrapup.html",   page_handler, {wrapup}},
                             {"/[...]", cowboy_static,
                              {priv_dir, middle_server, "",
                               [{mimetypes, cow_mimetypes, all}]}}
                            ]}
                     ]),

    %% start cowboy http server
    {ok, _} = cowboy:start_http(http, 100, [{port, 8080}],
                                [
                                 {env, [{dispatch, HTMLDispatch}]},
                                 {middlewares, [cowboy_router, cowboy_handler]}
                                ]),

    %% start request-handling middleware
    middle_server_sup:start_link().

stop(_State) ->
    ok.
