%%%-------------------------------------------------------------------
%%% @author Gustav Simonsom <gustav.simonson@gmail.com>
%%% @copyright (C) 2014, AI Effect Group, Berlin
%%% @doc
%%% Bitcoin protocol / blockchain.
%%%
%%% @end
%%% Created : 24 Aug 2014 by gustav <gustav.simonsson@gmail.com>
%%%-------------------------------------------------------------------
-module(mw_btc).

-compile(export_all).
%% API
-export([]). %% TODO: remove export_all and add API exports

-include("mw.hrl").
-include("log.hrl").
-include("mw_api_errors.hrl").

-define(ENABLE_PROFILING, true).
-define(BITCOIND_DIR, "/home/gustav/.bitcoin").
-define(BLOCK_TIMESTAMP_PARSE_LIMIT, 1408876332 - (86400 * 60)).

%%%===========================================================================
%%% API
%%%===========================================================================
%%%===========================================================================
%%% Internal functions
%%%===========================================================================

%%?info("BlockFiles: ~p", [BlockFiles]),
%% mw_btc:t().
t() ->
    case ?ENABLE_PROFILING of
        false -> parse();
        true ->
            {Time, _Value} =
                timer:tc(fun() -> parse() end),
            ?info("Parse time (microseconds): ~p", [Time])
    end,
    ok.

parse() ->
    {ok, FileNames} = file:list_dir(filename:join([?BITCOIND_DIR, "blocks"])),
    IsBlockFile = fun([$b, $l, $k | _]) -> true; (_) -> false end,
    BlockFiles0 =
        lists:reverse(lists:sort(lists:filter(IsBlockFile, FileNames))),
    AbsPath = fun(FN) -> filename:join([?BITCOIND_DIR, "blocks", FN]) end,
    BlockFiles = lists:map(AbsPath, BlockFiles0),
    parse_block_files(BlockFiles, []).

parse_block_files([BlockFile | BlockFiles], Acc) ->
    {ok, FileBin} = file:read_file(BlockFile),
    <<MagicID:4/bytes, Blocks/binary>> = FileBin,
    NewAcc = parse_blocks(Blocks, Acc),
    parse_block_files(BlockFiles, NewAcc).

parse_blocks(<<>>, Acc) -> Acc;
parse_blocks(Blocks, Acc) ->
    {BlockTime, BlockContent} = parse_block_header(Blocks),
    case BlockTime < ?BLOCK_TIMESTAMP_PARSE_LIMIT of
        true ->
            Acc;
        false ->
            {Rest, TxsAcc} = parse_txs(BlockContent),
            parse_blocks(Rest, TxsAcc)
    end.

parse_txs(<<TxnCountPrefix, Rest/binary>>) ->
    {LenLen, Rest2} = var_int(TxnCountPrefix, Rest),
    <<TxnCount:LenLen/little, Rest3/binary>> = Rest2,
    ?info("TxnCount: ~p", [TxnCount]),
    parse_txs(Rest3, TxnCount, []).

parse_txs(Rest, 0, Acc) -> {Rest, Acc};
parse_txs(Txs, TxCount, Acc) ->
    ?info("TxCount: ~p", [TxCount]),
    <<Version:4/bytes, TxInCountPrefix, Rest/binary>> = Txs,
    {TxInCountLenLen, Rest2} = var_int(TxInCountPrefix, Rest),
    <<TxInCount:TxInCountLenLen/little, Rest3/binary>> = Rest2,
    {<<TxOutCountPrefix, Rest4/binary>>, TxInAcc} =
        parse_tx_ins(Rest3, TxInCount, []),
    {TxOutCountLenLen, Rest5} = var_int(TxOutCountPrefix, Rest4),
    <<TxOutCount:TxOutCountLenLen/little, Rest6/binary>> = Rest5,
    {Rest7, TxOutAcc} =
        parse_tx_outs(Rest6, TxOutCount, []),
    <<LockTime:4/bytes, Rest8/binary>> = Rest7,
    parse_txs(Rest8, TxCount - 1, Acc).

parse_tx_ins(Rest, 0, Acc) -> {Rest, Acc};
parse_tx_ins(TxIns, TxInCount, Acc) -> 
    <<PrevOutPutTxHash:32/bytes,
      Index:4/bytes,
      ScriptLenPrefix,
      Rest/binary>> = TxIns,
    {ScriptSig, Rest2} = var_len(var_int(ScriptLenPrefix, Rest)),
    <<Sequence:4/bytes,
      Rest3/binary>> = Rest2,
    ?info("HURR: ~p", [mw_lib:bin_to_hex(ScriptSig)]),
    ?info("HURR: ~p", [mw_lib:bin_to_hex(Sequence)]),
    parse_tx_ins(Rest3, TxInCount - 1, Acc).

parse_tx_outs(Rest, 0, Acc) -> {Rest, Acc};
parse_tx_outs(TxOuts, TxOutCount, Acc) ->
    <<Value:8/bytes,
      ScriptLenPrefix,
      Rest/binary>> = TxOuts,
    %% ?info("Value: ~p", [Value]),
    {ScriptPubKey, Rest2} = var_len(var_int(ScriptLenPrefix, Rest)),
    parse_tx_outs(Rest2, TxOutCount - 1, Acc).

var_int(16#FD, Bin) -> {16, Bin};
var_int(16#FE, Bin) -> {32, Bin};
var_int(16#FF, Bin) -> {64, Bin};
var_int(Other, Bin) -> {8, <<Other, Bin/binary>>}.

var_len({LenLen, Bin}) ->
    ?info("LenLen: ~p", [LenLen]),
    ?info("Bin: ~p", [mw_lib:bin_to_hex(binary:part(Bin, {0, 8}))]),
    <<Len:LenLen/little, Rest/binary>> = Bin,
    ?info("Len: ~p", [Len]),
    <<Field:Len/bytes, Rest2/binary>> = Rest,
    {Field, Rest2}.

parse_block_header(<<_HeaderLength:32/integer-little,
                     Version:32/integer-little,
                     _HashPrevBlock:32/bytes,
                     _HashMerkleRoot:32/bytes,
                     Time:32/integer-little,
                     _TargetDifficulty:32/bits,
                     _Nonce:32/integer-little,
                     Rest/binary>>) ->
    ?info("Version: ~p", [Version]),
    ?info("BlockTime: ~p", [Time]),
    {Time, Rest}.

%%%===========================================================================
%%% Tests
%%%===========================================================================
