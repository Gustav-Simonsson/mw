%%%-------------------------------------------------------------------------%%%
%%% Description : Mw - AI Effect World Cup 2014 - Middle Server             %%%
%%% Version     : 0.6.x/json flow                                           %%%
%%% File        : page_handler.erl                                          %%%
%%% Description : web site page creation, as a handler for Cowboy           %%%
%%% Copyright   : AI Effect Group, Berlin. All rights reserved.             %%%
%%% Author      : H. Diedrich <hd2010@eonblast.com>                         %%%
%%% Created     : 24 May 2014                                               %%%
%%% Changed     : 22 June 2014                                              %%%
%%%-------------------------------------------------------------------------%%%
-module(page_handler).

-include("log.hrl").
-include("mw_contract.hrl").

%% REST Callbacks
-export([init/3]).
-export([rest_init/2]).
-export([allowed_methods/2]).
-export([resource_exists/2]).
-export([content_types_provided/2]).

%% Callback Callbacks
-export([page/2]).

%% ----------------------------------------------------------------------------
%% Cowboy Callbacks
%% ----------------------------------------------------------------------------
init(_Transport, _Req, _Paths) ->
    {upgrade, protocol, cowboy_rest}.

rest_init(Req, Paths) ->
    {ok, Req, Paths}.

allowed_methods(Req, State) ->
    {[<<"GET">>], Req, State}.

resource_exists(Req, State) ->
    {true, Req, State}.

content_types_provided(Req, State) ->
    {[
      {{<<"text">>, <<"html">>, []}, page}
     ], Req, State}.

%% ----------------------------------------------------------------------------
%% Page Creation
%% ----------------------------------------------------------------------------
%% assemble a page, generically: title, meta, header, footer
page(Req, State) ->
    {Block} = State,
    Title = erlang:iolist_to_binary("Betwarp " ++ atom_to_list(Block)),
    %% TODO should be {Req, Middle, State} = html(Req, State) to not loose ReqN
    Middle =
        try
            html(Req, State)
        catch throw:{api_error, {ErrorCode, ErrorMsg}} ->
                "<br> Error code: " ++ integer_to_list(ErrorCode) ++ " : " ++
                    binary:bin_to_list(ErrorMsg) ++ "</br>";
              E:R ->
                ?error("Page request handling fucked up: ~p",
                       [{E,R,erlang:get_stacktrace()}]),
                "<br> Unknown Error. Something is on fire. Blame Gustav. </br>"
        end,
    Body  = erlang:iolist_to_binary([
                                     block("head.html"),
                                     Middle,
                                     block("foot.html")]),
    HTML = [<<"<!DOCTYPE html><html><head><title>">>,
            Title,
            <<"</title></head><body>">>,
            Body,
            <<"</body></html>\n">>],
    Req2 = mw_lib:cowboy_req_enable_cors(Req),
    %% ?info("Page outgoing Req: ~p", [Req2]),
    {HTML, Req2, somepath}. %% TODO somepath?

%% bet list inner html
html(_Req, {bets}=_State) ->
    Bin = block(bets),
    {ok, Data} = mw_pg:select_contract_infos(),
    Merged = merge(Bin, [{betlist, bets_html(Data)}]),
    Merged;

%% first contract step, create keys, support T1; inner html
html(Req, {prep}=_State) ->
    Id = cowboy_req:binding(id, Req, none),
    case Id of
      none ->
        "ID error";
      _ ->
            {ok, Props0} = mw_contract:get_contract_info(binary_to_integer(Id)),
            {ok, ServerHost} = application:get_env(mw, server_host),
            ?info("HURR: ~p", [ServerHost]),
            Props = Props0 ++ [{server_host, ServerHost}],
            History = proplists:get_value("history", Props),
            HTML =
                case {mw_contract:contract_event_happened(
                        History, ?STATE_DESC_GIVER_ENTERED),
                      mw_contract:contract_event_happened(
                        History, ?STATE_DESC_TAKER_ENTERED)} of
                    {true, true} ->
                        <<"<h4>Contract full. "
                          "Please clone or use another contract.</h4>">>;
                    _ ->
                        block(prep)
                end,
            Headline = proplists:get_value("headline", Props, <<"?">>),
            HistoryHTML = events_to_html(proplists:get_value("history", Props)),
            merge(HTML,
                  [{headline, Headline},
                   {status, HistoryHTML},
                   {contract_id, Id},
                   {server_host, ServerHost}
                  ])
    end;

html(_Req, {pend}=State) ->
    {Block} = State,
    block(Block);

%% wait for T1 arriving, or offer to sign T2
html(Req, {sign}=_State) ->
    Id = cowboy_req:binding(id, Req, none),
    case Id of
      none ->
        "ID error";
      _ ->
            IdN = list_to_integer(binary_to_list(Id)),
            {ok, Props} = mw_contract:get_contract_t2_state(IdN),
            {ok, ServerHost} = application:get_env(mw, server_host),
            T2Raw = proplists:get_value("t2_raw", Props),
            T2SigHashInput0 = proplists:get_value("t2_sighash_input_0", Props),
            T2SigHashInput1 = proplists:get_value("t2_sighash_input_1", Props),
            GiverPubkey = proplists:get_value("giver_ec_pubkey", Props),
            TakerPubkey = proplists:get_value("taker_ec_pubkey", Props),
            TakerEncPrivkey =
                proplists:get_value("taker_enc_ec_privkey", Props),
            History = proplists:get_value("history", Props),
            case {mw_contract:contract_event_happened(
                    History, ?STATE_DESC_GIVER_T1),
                  mw_contract:contract_event_happened(
                    History, ?STATE_DESC_TAKER_T1)} of
                {true, true} ->
                    %% TODO: only send out the strictly needed encrypted
                    %% privkeys instead of all of them
                    merge(block(sign),
                          [{contract_id, Id},
                           {server_host, ServerHost},
                           {t2_raw, T2Raw},
                           {t2_sighash_input_0, T2SigHashInput0},
                           {t2_sighash_input_1, T2SigHashInput1},
                           {giver_ec_pubkey, GiverPubkey},
                           {taker_ec_pubkey, TakerPubkey},
                           {taker_enc_ec_privkey, TakerEncPrivkey}
                          ]);
                _ ->
                    merge(block(wait), [{contract_id, Id}])
            end
    end;

html(Req, {status}=_State) ->
    Id = cowboy_req:binding(id, Req, none),
    case Id of
      none ->
        "Enter ID ... ";
      _ ->
        case mw_contract:get_contract_info(binary_to_integer(Id)) of
          {ok, Props} ->
            Headline = proplists:get_value("headline", Props),
            Outcome = proplists:get_value("outcome", Props),
            EventPubkey = proplists:get_value("event_pubkey", Props),
            GiverPubkey = proplists:get_value("giver_ec_pubkey", Props),
            TakerPubkey = proplists:get_value("taker_ec_pubkey", Props),
            TakerAddr   = case TakerPubkey of
                              null -> null;
                              _ -> mw_btc:ecpubkey_to_addr(
                                     mw_lib:dec_b58check(TakerPubkey))
                          end,
            T2Hash = proplists:get_value("t2_hash", Props),
            T3Hash = proplists:get_value("t3_hash", Props),
            History = events_to_html(proplists:get_value("history", Props)),
            merge(block(status),
              [{contract_id, Id},
               {headline, Headline},
               {status, History},
               {outcome, Outcome},
               {event_pubkey, EventPubkey},
               {giver_pubkey, GiverPubkey},
               {taker_pubkey, TakerPubkey},
               {taker_address, TakerAddr},
               {t2_hash, T2Hash},
               {t3_hash, T3Hash}
             ])
        end
    end;

%% enter to-address for payout
html(Req, {cashout}=_State) ->
    Id = cowboy_req:binding(id, Req, none),
    merge(block(cashout), [{contract_id, Id}]);

%% enter keys for payout
html(Req, {cashout2}=_State) ->
    Id0 = cowboy_req:binding(id, Req, none),
    Id = binary_to_integer(Id0),
    [{_, ToAddress}] = cowboy_req:parse_qs(Req),
    Props0 = mw_contract:get_t3_for_signing(Id, ToAddress),
    {ok, ServerHost} = application:get_env(mw, server_host),
    Props = Props0 ++ [{server_host, ServerHost},
                       {contract_id, Id},
                       {to_address, ToAddress}],
    merge(block(cashout2), Props).

%% ----------------------------------------------------------------------------
%% Bets Lists
%% ----------------------------------------------------------------------------
%% Create HTML that displays bet offerings.
bets_html(DataList) ->
    Template = block("bet.html"),
    [bet_html(Template, Data ++ [{<<"amount">>, <<"0.0004 BTC">>}]) ||
                 Data <- DataList].

bet_html(Template, Data) ->
    merge(Template, Data).

%% ----------------------------------------------------------------------------
%% Dynamic Pages
%% ----------------------------------------------------------------------------
%% load the HTML from a template block
block(Name) when is_atom(Name)->
    File = atom_to_list(Name) ++ ".html",
    block(File);

block(Name) ->
    %% io:format("file path: ~p~n", [full_path(Name)]),
    {ok, Bin} = file:read_file(full_path(Name)),
    Bin.

%% create path to the HTML templates in the app's private folder
%% Note that this folder is under _rel and you CAN change HTML dynamically
%% to see changes right away, if you find the right folder.
full_path(Name) ->
    %% io:format("file dir: ~p~n", [code:priv_dir(middle_server)]),
    filename:join([code:priv_dir(middle_server), "blocks/" ++ Name]).

%% Join a flat data structure and a HTML template.
%% E.g. merge(<<"<a href=hello.html>$HELLO</a>">>, [{hello, "Hej!"}])
%% results into <<"<a href=hello.html>Hej!</a>">>
merge(Template, []) ->
    Template;

merge(Template, [{Tag0, Value0} | Data]) ->
    Tag = to_binary(Tag0),
    RE = binary:list_to_bin(
           "\\$" ++ string:to_upper(binary:bin_to_list(Tag))),
    Replacement = to_binary(Value0),
    Replaced = re:replace(Template, RE, Replacement,
                          [global, {return, binary}]),
    merge(Replaced, Data).

to_binary(X) when is_list(X)        -> list_to_binary(X);
to_binary(X) when is_integer(X)     -> list_to_binary(integer_to_list(X));
to_binary(X) when is_atom(X)        -> list_to_binary(atom_to_list(X));
to_binary(X) when is_binary(X)      -> X.

%% dump a prop list
prop_to_html(Prop) ->
    io_lib:format("<pre>~p</pre>", [Prop]).

%% make a html list from the contract events as they come from the DB
events_to_html([]) -> [];

events_to_html([P | L]) ->
    [<<"<p> ">>,
     proplists:get_value("timestamp", P, <<"">>),
     <<": ">>,
     proplists:get_value("event", P, <<"">>),
     <<" <\p>">>] ++
     events_to_html(L).
