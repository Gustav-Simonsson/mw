%%%-------------------------------------------------------------------
%%% @author Gustav Simonsom <gustav.simonson@gmail.com>
%%% @copyright (C) 2014, AI Effect Group, Berlin
%%% @doc
%%% Bitcoin protocol / blockchain. In memory of Julia, summer 2014, Berlin.
%%%
%%% References:
%%% 1. https://en.bitcoin.it/wiki/Protocol_specification
%%% 2. https://en.bitcoin.it/wiki/Script
%%% 3. https://github.com/r-willis/biten
%%% 4. http://codesuppository.blogspot.de/2014/01/how-to-parse-bitcoin-blockchain.html
%%% 5. http://www.righto.com/2014/02/bitcoins-hard-way-using-raw-bitcoin.html
%%% 6. http://bitcoin.stackexchange.com/questions/3374/how-to-redeem-a-basic-tx
%%% 7. https://bitcoin.org/en/developer-guide#term-multisig
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
-include("btc.hrl").

-define(ENABLE_PROFILING, true).
-define(BITCOIND_DIR, "/home/gustav/.bitcoin/").
-define(BLOCK_TIMESTAMP_PARSE_LIMIT, mw_lib:now_unix_timestamp() - (86400 * 3)).
-define(BITCOIND_URL, "http://127.0.0.1:8332").
-define(BITCOIND_JSON_RPC_USER, "generated_by_armory").
-define(BITCOIND_JSON_RPC_PASS, "FAh1Nf2K1TddAus5VfMWGwHSrd7usPqqjBdVzsjtUWyQ").

%%%===========================================================================
%%% API
%%%===========================================================================
get_unsigned_t2(GiverPubkey0, TakerPubkey0, EventPubkey0, OutputAmount0) ->
    OutputAmount = erlang:list_to_integer(binary:bin_to_list(OutputAmount0)),
    GiverPubkey = mw_lib:dec_b58check(GiverPubkey0),
    TakerPubkey = mw_lib:dec_b58check(TakerPubkey0),
    EventPubkey = mw_lib:dec_b58check(EventPubkey0),
    %% TODO: support any open output combination where there is enough total
    %% amount available for joining T2 tx.
    %% For now, support only that last open output has demo amount (0.002 BTC).
    {TakerOpenOutput, GiverOpenOutput} =
        try
            {get_address_utxo(ecpubkey_to_addr(TakerPubkey)),
             get_address_utxo(ecpubkey_to_addr(GiverPubkey))}
        catch E:R ->
                ?error("Open output parsing crashed: ~p",
                       [{E,R,erlang:get_stacktrace()}]),
                ?API_ERROR(?BLOCKCHAIN_PARSING_FAILED)
        end,
    case {GiverOpenOutput, TakerOpenOutput} of
        {[{_,_,_,?T1_AMOUNT_INT} | _],
         [{_,_,_,?T1_AMOUNT_INT} | _]} ->
            UnsignedT2 =
                make_raw_t2_tx(lists:append([GiverOpenOutput, TakerOpenOutput]),
                               GiverPubkey, TakerPubkey, EventPubkey,
                               OutputAmount),
            T2ForSigningByGiver =
                make_raw_t2_tx(GiverOpenOutput,
                               GiverPubkey, TakerPubkey, EventPubkey,
                               OutputAmount),
            T2ForSigningByTaker =
                make_raw_t2_tx(TakerOpenOutput,
                               GiverPubkey, TakerPubkey, EventPubkey,
                               OutputAmount),

            T2SigHashInput0 = make_tx_sighash(T2ForSigningByGiver),
            T2SigHashInput1 = make_tx_sighash(T2ForSigningByTaker),
            {T2SigHashInput0, T2SigHashInput1, UnsignedT2};
        {GiverOpenOutput,
         TakerOpenOutput} ->
            ?error("Open outputs not supported. Giver: ~p Taker: ~p",
                   [GiverOpenOutput, TakerOpenOutput]),
            %% ?API_ERROR(?CONTRACT_T2_NO_SUPPORTED_OUTPUTS)
            {error, no_supported_outputs}
    end.

sign_and_submit_t2_signatures(TakerECPubkeyB58Check,
                              GiverECPrivkeyB58Check,
                              GiverECPubkeyB58Check,
                              TakerT2SignatureHex,
                              T2SigHashInput0Hex,
                              UnsignedT2Hex) ->
    TakerECPubkey    = mw_lib:dec_b58check(TakerECPubkeyB58Check),
    GiverECPrivkey   = mw_lib:dec_b58check(GiverECPrivkeyB58Check),
    GiverECPubkey    = mw_lib:dec_b58check(GiverECPubkeyB58Check),

    TakerT2Signature = mw_lib:hex_to_bin(TakerT2SignatureHex),
    T2SigHashInput0  = mw_lib:hex_to_bin(T2SigHashInput0Hex),
    UnsignedT2       = mw_lib:hex_to_bin(UnsignedT2Hex),

    GiverT2Signature = sign_tx_hash(T2SigHashInput0, GiverECPrivkey),
    GiverScriptSig   = make_scriptsig(GiverT2Signature, GiverECPubkey),
    TakerScriptSig   = make_scriptsig(TakerT2Signature, TakerECPubkey),
    %% Bitcoin protocol brain surgery. We take apart the intermediate T2 and
    %% replace scriptPubKey with scriptSig in giver/taker inputs.
    %% NOTE: Due to SIGHASH_ANYONECANPAY, this T2 is NOT the exact version
    %% that was hashed for signing by giver and taker, respectively.
    %% See tx in [1], [5], steps 16-18 in [6] and get_unsigned_t2/4 above
    %% First input is giver
    <<TxVersion:4/binary,
      16#02,
      %% Giver's input
      PrevOutPutTxHash:32/bytes,
      Index:32/little-integer,
      R/binary>> = UnsignedT2,
    {_LenLen, ScriptPubkeyLen, R2} = parse_varint(R),
    <<_ScriptPubkey:ScriptPubkeyLen/bytes, R3/binary>> = R2,
    <<Seq1:4/bytes, R4/binary>> = R3,
    %% Taker's input
    <<PrevOutPutTxHash2:32/bytes,
      Index2:32/little-integer,
      R5/binary>> = R4,
    {_LenLen2, ScriptPubkeyLen2, R6} = parse_varint(R5),
    <<_ScriptPubkey2:ScriptPubkeyLen2/bytes, R7/binary>> = R6,
    <<Seq2:4/bytes, R8/binary>> = R7,

    FinalT2 =
        <<TxVersion/binary,
          16#02,
          PrevOutPutTxHash:32/bytes,
          Index:32/little-integer,
          (varint(byte_size(GiverScriptSig)))/binary,
          GiverScriptSig/binary,
          Seq1/binary,
          PrevOutPutTxHash2:32/bytes,
          Index2:32/little-integer,
          (varint(byte_size(TakerScriptSig)))/binary,
          TakerScriptSig/binary,
          Seq2/binary,
          R8/binary
        >>,
    ?info("FinalT2: ~p", [FinalT2]),
    {ok, FinalT2TxHash} = send_raw_tx_to_bitcoind(FinalT2),
    {ok, FinalT2, FinalT2TxHash}.

get_unsigned_t3(FinalT2, FinalT2Hash, T3ToAddress) ->
    %% We want the output in T2, so we ignore the inputs, but we still need
    %% to parse them to get to the correct position in the tx binary.
    <<_TxVersion:4/binary,
      16#02,
      _PrevOutPutTxHash1:32/bytes,
      _Index:32/little-integer,
      R/binary>> = FinalT2,
    {_LenLen, ScriptSigLen, R2} = parse_varint(R),
    <<_ScriptSig:ScriptSigLen/bytes, R3/binary>> = R2,
    <<_Seq1:4/bytes, R4/binary>> = R3,
    <<_PrevOutPutTxHash2:32/bytes,
      _Index2:32/little-integer,
      R5/binary>> = R4,
    {_LenLen2, ScriptSigLen2, R6} = parse_varint(R5),
    <<_ScriptSig2:ScriptSigLen2/bytes, R7/binary>> = R6,
    <<_Seq2:4/bytes, R8/binary>> = R7,

    <<16#01,
      %% Now we're at the T2 output - which is referenced in the T3 input.
      T2OutputValue:64/little-integer,
      R9/binary>> = R8,
    {_LenLen, ScriptPubkeyLen, R10} = parse_varint(R9),
    <<ScriptPubkey:ScriptPubkeyLen/bytes, _R11/binary>> = R10,

    OutputAddrHash = addr_to_hash(T3ToAddress),
    OutputAmount = T2OutputValue - ?BITCOIN_MIN_FEE,
    %% See [2] standard tx to bitcoin address
    OutputScript = <<?OP_DUP,
                     ?OP_HASH160,
                     20,
                     OutputAddrHash/binary,
                     ?OP_EQUALVERIFY,
                     ?OP_CHECKSIG>>,
    UnsignedT3 =
        <<?TX_VERSION/binary,
          16#01, %% Tx input count
          (mw_lib:rev_bin(FinalT2Hash))/binary,
          16#00:32/little-integer, %% T2 has a single output
          (varint(byte_size(ScriptPubkey)))/binary,
          ScriptPubkey/binary,
          ?TX_IN_SEQ/binary,
          16#01, %% Tx output count
          OutputAmount:64/little-integer,
          (varint(byte_size(OutputScript)))/binary,
          OutputScript/binary,
          ?TX_LOCK_TIME/binary
        >>,
    T3SigHash = make_tx_sighash(UnsignedT3),
    {T3SigHash, UnsignedT3}.

submit_t3_signatures(UnsignedT3, T3Signature1, T3Signature2) ->
    %% Similar to when we add signatures to T2, we add two signatures to T3.
    %% However, we add them to a single input - spending the T2 multisig output.
    %% See [7].
    ScriptSig = <<?OP_0,
                  (byte_size(T3Signature1)), T3Signature1/binary,
                  (byte_size(T3Signature2)), T3Signature2/binary
                >>,

    <<TxVersion:4/binary,
      16#01,
      PrevOutPutTxHash:32/bytes,
      Index:32/little-integer,
      R/binary>> = UnsignedT3,
    {_LenLen, ScriptPubkeyLen, R2} = parse_varint(R),
    <<_ScriptPubkey:ScriptPubkeyLen/bytes, R3/binary>> = R2,
    <<Seq:4/bytes, R4/binary>> = R3,

    FinalT3 =
        <<TxVersion/binary,
          16#01,
          PrevOutPutTxHash:32/bytes,
          Index:32/little-integer,
          (varint(byte_size(ScriptSig)))/binary,
          ScriptSig/binary,
          Seq/binary,
          R4/binary
        >>,
    ?info("FinalT3: ~p", [FinalT3]),
    {ok, FinalT3TxHash} = send_raw_tx_to_bitcoind(FinalT3),
    {ok, FinalT3, FinalT3TxHash}.

bitcoin_signature_der(<<16#30,
                        _TotalLen,
                        16#02,
                        RLen,
                        _R:RLen/bytes,
                        16#02,
                        SLen,
                        _S:SLen/bytes,
                        _HashType>>) -> true;
bitcoin_signature_der(_Bin) -> false.

get_address_utxo(Address) ->
    case query_address_in_mempool(Address) of
        {ok, MemPoolOO} ->
            ?info("Mempool OO: ~p", [MemPoolOO]),
            [MemPoolOO];
        not_found ->
            ?info("No open outputs for address in mempool. "
                  "Starting parsing of blockchain ~p seconds into the past",
                  [?BLOCK_TIMESTAMP_PARSE_LIMIT]),
            {Time, Value} =
                timer:tc(fun() -> query_address_in_blockchain(Address) end),
            ?info("Blockchain OO parsing took: ~p ms", [Time div 1000]),
            #{acc := Acc} = Value,
            OOs = lists:flatten(Acc),
            ?info("Blockchain OOs: ~p", [OOs]),
            OOs
    end.


%%%===========================================================================
%%% Internal functions
%%%===========================================================================
%%%===========================================================================
%%% Blockchain parsing
%%%===========================================================================
query_address_in_blockchain(Address) ->
    AddrHash = addr_to_hash(Address),
    {ok, FileNames} = file:list_dir(filename:join([?BITCOIND_DIR, "blocks"])),
    IsBlockFile = fun([$b, $l, $k | _]) -> true; (_) -> false end,
    BlockFiles0 =
        lists:reverse(lists:sort(lists:filter(IsBlockFile, FileNames))),
    AbsPath = fun(FN) -> filename:join([?BITCOIND_DIR, "blocks", FN]) end,
    BlockFiles = lists:map(AbsPath, BlockFiles0),
    parse_block_files(BlockFiles, #{addr_hash => AddrHash, acc => []}).

parse_block_files([], Acc) -> Acc;
parse_block_files([BlockFile | BlockFiles], Acc) ->
    {ok, FileBin} = file:read_file(BlockFile),
    case parse_blocks(FileBin, Acc) of
        {done, NewAcc} ->
            NewAcc;
        {continue, NewAcc} ->
            %% ?info("Parsed ~p", [BlockFile]),
            parse_block_files(BlockFiles, NewAcc)
    end.

parse_blocks(<<>>, Acc) -> {continue, Acc};
parse_blocks(Blocks, Acc) ->
    case parse_block_header(Blocks) of
        done ->
            {continue, Acc};
        {more, {BlockTime, TxCount, Txs}} ->
            case BlockTime < ?BLOCK_TIMESTAMP_PARSE_LIMIT of
                true ->
                    %%?info("Done blocks ~p", [Blocks]),
                    {done, Acc};
                false ->
                    {Rest, NewAcc} = parse_txs(Txs, TxCount, Acc),
                    parse_blocks(Rest, NewAcc)
            end
    end.

%% We pass around multiple accumulators when parsing a single pass:
%% 1. one "state" acc is passed through to every part of the blockchain parsed.
%%    this one contains input to the parsing and the final parse output
%% 2. One acc for parsing of inputs for a single tx
%% 3. One acc for parsing of outputs for a single tx
parse_txs(Rest, 0, State) -> {Rest, State};
parse_txs(Txs, TxCount, State) ->
    <<_Version:4/bytes, R/binary>> = Txs,
    {TxInsLenLen, TxInCount, R2}     = parse_varint(R),
    {R3, TxInsLen, State2, _InsAcc}  = parse_tx_ins(R2, TxInCount, 0,
                                                    State, []),
    {TxOutsLenLen, TxOutCount, R4}   = parse_varint(R3),
    {R5, TxOutsLen, State3, OutsAcc} = parse_tx_outs(R4, {0, TxOutCount}, 0,
                                                     State2, []),
    <<_LockTime:4/bytes, R6/binary>> = R5,
    TxLen = 4 + TxInsLenLen + TxInsLen + TxOutsLenLen + TxOutsLen + 4,
    <<Tx:TxLen/bytes, _/binary>> = Txs,
    TxHash = mw_lib:rev_bin(mw_lib:double_sha256(Tx)),
    AddTxHash = fun({Index, ScriptPubkey, Value}) ->
                        {TxHash, Index, ScriptPubkey, Value} end,
    State4 =
        case OutsAcc of
            [] -> State3;
            %% TODO: native maps update syntax?
            _  ->
                %% ?info("Tx: ~p", [mw_lib:bin_to_hex(Tx)]),
                %% ?info("Tx hash: ~p", [mw_lib:bin_to_hex(mw_lib:rev_bin(TxHash))]),
                #{acc := A} = State3,
                maps:update(acc, lists:append(lists:map(AddTxHash, OutsAcc), A),
                            State3)
        end,
    parse_txs(R6, TxCount - 1, State4).

parse_tx_ins(R, 0, InsLen, State, InsAcc) ->
    {R, InsLen, State, InsAcc};
parse_tx_ins(TxIns, TxInCount, InsLen, #{acc := Acc} = State, InsAcc) ->
    <<PrevOutPutTxHash0:32/bytes, Index:32/little-integer, R/binary>> = TxIns,
    PrevOutPutTxHash = mw_lib:rev_bin(PrevOutPutTxHash0),
    %?info("Index ~p !", [Index]),
    {LenLen, ScriptSigLen, R2} = parse_varint(R),
    <<ScriptSig:ScriptSigLen/bytes, R3/binary>> = R2,
    <<_Sequence:4/bytes, R4/binary>> = R3,
    NotSpendsOutput =
        fun({H,I,_,_}) when (H =:= PrevOutPutTxHash) andalso
                            (I =:= Index) ->
                ?info("Input spends output. ScriptSig: ~p", [ScriptSig]),
                false;
           (_) ->
                true
        end,
    State2 =
        case Acc of
            [] -> State;
            _  ->
                maps:update(acc, lists:filter(NotSpendsOutput, Acc), State)
        end,
    parse_tx_ins(R4,
                 TxInCount - 1,
                 InsLen + LenLen + ScriptSigLen + 40,
                 State2,
                 InsAcc).

parse_tx_outs(R, {_,0}, OutsLen, State, OutsAcc) ->
    {R, OutsLen, State, OutsAcc};
parse_tx_outs(Outs, {Index, OutCount}, OutsLen, State, OutsAcc) ->
    <<Value:64/little-integer, R/binary>> = Outs,
    {LenLen, ScriptPubkeyLen, R2} = parse_varint(R),
    <<ScriptPubkey:ScriptPubkeyLen/bytes, R3/binary>> = R2,
    %% See [4] , output section, output script format 3
    %% TODO: for now we just check pay-to-address, not pay-to-pubkey formats
    #{addr_hash := AddrHash} = State,
    NewOutsAcc =
        case ScriptPubkey of
            <<?OP_DUP, ?OP_HASH160, 20, H:20/bytes, _/binary>>
              when H =:= AddrHash ->
                ?info("Matching output: ~p", [{ScriptPubkey, Index, Value}]),
                [{Index, ScriptPubkey, Value} | OutsAcc];
            _ ->
                OutsAcc
        end,
    parse_tx_outs(R3,
                  {Index + 1, OutCount - 1},
                  OutsLen + LenLen + ScriptPubkeyLen + 8,
                  State,
                  NewOutsAcc).

%% From [4] protocol.erl and slightly modified
parse_varint(<<16#fd, Len:16/little-integer, R/binary>>) -> {3, Len, R};
parse_varint(<<16#fe, Len:32/little-integer, R/binary>>) -> {5, Len, R};
parse_varint(<<16#ff, Len:64/little-integer, R/binary>>) -> {9, Len, R};
parse_varint(<<Len:8, R/binary>>)                        -> {1, Len, R}.

varint(X) when X < 16#FD                -> <<X>>;
varint(X) when X =< 16#FFFF             -> <<16#FD, X:16/little>>;
varint(X) when X =< 16#FFFFFFFF         -> <<16#FE, X:32/little>>;
varint(X) when X =< 16#FFFFFFFFFFFFFFFF -> <<16#FF, X:64/little>>.

parse_block_header(<<FirstFour:4/bytes,
                     _HeaderLength:32/integer-little,
                     _Version:32/integer-little,
                     _HashPrevBlock:32/bytes,
                     _HashMerkleRoot:32/bytes,
                     Time:32/integer-little,
                     _TargetDifficulty:32/bits,
                     _Nonce:32/integer-little,
                     R/binary>> = Blocks) ->
    MagicID = mw_lib:rev_bin(?BLOCK_MAGIC_ID),
    %% ?info("Version: ~p, Time: ~p (~p)", [Version, Time, mw_lib:unix_ts_to_datetime(Time)]),
    %% See [4] note about a bunch of zero bytes before next block.
    case FirstFour of
        MagicID ->
            {_, TxCount, R2} = parse_varint(R),
            {more, {Time, TxCount, R2}};
        <<0,0,0,0>> ->
            case binary:split(Blocks, mw_lib:rev_bin(?BLOCK_MAGIC_ID)) of
                [_Crap, NotCrap] ->
                    parse_block_header(NotCrap);
                _JustCrap ->
                    done
            end
    end.

%%%===========================================================================
%%% Tx
%%%===========================================================================
sign_tx_hash(TxHash, ECPrivkey) ->
    %% 81 is hashtype / sig flags byte for SIGHASH_ALL + SIGHASH_ANYONECANPAY
    %% 01 is hashtype / sig flags byte for SIGHASH_ALL
    S = crypto:sign(ecdsa, sha256, {digest, TxHash}, [ECPrivkey, secp256k1]),
    <<S/binary, 16#81>>.

make_tx_sighash(Tx0) ->
    Tx = <<Tx0/binary, ?SIGHASH_ALL_ANYONECANPAY/binary>>,
    mw_lib:double_sha256(Tx).

make_scriptsig(Signature, ECPubkey) ->
    <<(byte_size(Signature)), Signature/binary,
      (byte_size(ECPubkey)), ECPubkey/binary>>.

%% See [1] section on tx and [5] makeRawTransaction function
%% TODO: support any number of inputs and outputs
%% TODO: this is only pay-to-address - rename function?
make_raw_tx([{OutPointTxHash, OutPointIndex}],
            %% When this function is called to create tx for signing,
            %% InputScript is scriptPubKey from the previous output.
            %% When we call this function to create final tx, it is scriptSig.
            InputScript,
            [{OutputAmount, OutputAddress}]) ->
    OutputAddrHash = addr_to_hash(OutputAddress),
    %% See [2] standard tx to bitcoin address
    OutputScript = <<?OP_DUP,
                     ?OP_HASH160,
                     20,
                     OutputAddrHash/binary,
                     ?OP_EQUALVERIFY,
                     ?OP_CHECKSIG>>,
    %% See [1] tx / inputs / outputs sections.
    <<
      ?TX_VERSION/binary,
      16#01, %% Tx input count
      (mw_lib:rev_bin(OutPointTxHash))/binary,
      OutPointIndex:32/little-integer,
      (varint(byte_size(InputScript)))/binary,
      InputScript/binary, %% scriptPubKey OR scriptSig
      ?TX_IN_SEQ/binary,
      16#01, %% Tx output count
      OutputAmount:64/little-integer,
      (varint(byte_size(OutputScript)))/binary,
      OutputScript/binary,
      ?TX_LOCK_TIME/binary
    >>.

make_raw_t2_tx(Inputs, GiverPubkey, TakerPubkey, EventPubkey, OutputAmount) ->
    OutputScript =
        <<
          ?OP_2,
          (byte_size(GiverPubkey)), GiverPubkey/binary,
          (byte_size(TakerPubkey)), TakerPubkey/binary,
          (byte_size(EventPubkey)), EventPubkey/binary,
          ?OP_3,
          ?OP_CHECKMULTISIG
        >>,
    <<?TX_VERSION/binary,
      (length(Inputs)),
      (make_raw_inputs(Inputs))/binary,
      16#01, %% Tx output count
      %% Multisig output
      OutputAmount:64/little-integer,
      (varint(byte_size(OutputScript)))/binary,
      OutputScript/binary,
      ?TX_LOCK_TIME/binary
    >>.

make_raw_inputs(Inputs) ->
    InputBin =
        fun({OutPointTxHash, OutPointIndex, InputScript, _Value}) ->
                <<
                  (mw_lib:rev_bin(OutPointTxHash))/binary,
                  OutPointIndex:32/little-integer,
                  (varint(byte_size(InputScript)))/binary,
                  InputScript/binary, %% scriptPubkey OR scriptSig
                  ?TX_IN_SEQ/binary
                >>
        end,
    <<(binary:list_to_bin(lists:map(InputBin, Inputs)))/binary>>.

ecpubkey_to_addr(ECPubkey) ->
    Hash = ecpubkey_to_hash(ECPubkey),
    KeyHash = <<0, Hash/binary>>,
    mw_lib:enc_b58check(KeyHash).

ecpubkey_to_hash(ECPubkey) ->
    crypto:hash(ripemd160, crypto:hash(sha256, ECPubkey)).

addr_to_hash(Address) ->
    %% TODO: should base58check decoder remove leading zero bytes?
    binary:part(mw_lib:dec_b58check(Address), {1, 20}).

send_raw_tx_to_bitcoind(Tx) ->
    JSONParams = [mw_lib:bin_to_hex(Tx)],
    FinalTxHash = call_bitcoind_api(<<"sendrawtransaction">>, JSONParams),
    {ok, FinalTxHash}.

get_bitcoind_mempool() ->
    call_bitcoind_api(<<"getrawmempool">>, []).

query_address_in_mempool(Address) ->
    T1 = os:timestamp(),
    AddrHash = addr_to_hash(Address),
    TxHashes = get_bitcoind_mempool(),
    TxCount = length(TxHashes),
    ?info("TxHashes count: ~p", [TxCount]),
    %% Down and Dirty Erlang scaling <3
    %% We call bitcoind with 4 concurrent threads to speed things up.
    %% We can only scale to 4 threads without a recompile of bitcoind due to:
    %% https://github.com/litecoin-project/litecoin/issues/67
    {Part1, Rest1} = lists:split(TxCount div 4, TxHashes),
    {Part2, Rest2} = lists:split(TxCount div 4, Rest1),
    {Part3, Part4} = lists:split(TxCount div 4, Rest2),
    Parts = [Part1, Part2, Part3, Part4],
    Pid = self(),
    Spawn = fun(L) -> spawn_link(fun() -> query_txs(L, AddrHash, Pid) end) end,
    lists:foreach(Spawn, Parts),
    Res = receive_results(3),
    T2 = os:timestamp(),
    Time = timer:now_diff(T2, T1),
    ?info("query_address_in_mempool on ~p txs: ~p ms",
          [TxCount, Time div 1000]),
    Res.

query_txs([], _AddrHash, Pid) ->
    Pid ! done;
query_txs([TxHash | TxHashes], AddrHash, Pid) ->
    TxHex = get_bitcoind_tx(TxHash),
    case query_addrhash_in_tx(AddrHash, TxHex) of
        not_found ->
            query_txs(TxHashes, AddrHash, Pid);
        {found, OO} ->
            Pid ! {found, OO}
    end.

receive_results(ProcsLeft) ->
    receive
        done ->
            case ProcsLeft of
                0 -> not_found;
                _ -> receive_results(ProcsLeft - 1)
            end;
        {found, OO} ->
            {ok, OO}
    end.

query_addrhash_in_tx(AddrHash, TxHex) ->
    Tx = mw_lib:hex_to_bin(TxHex),
    {_, AccRes} = parse_txs(Tx, 1, #{addr_hash => AddrHash, acc => []}),
    #{acc := Acc} = AccRes,
    MatchingOpenOutput =
        fun({_H,_I,_SPK,V}) when V =:= ?T1_AMOUNT_INT -> true; (_) -> false end,
    case lists:filter(MatchingOpenOutput, Acc) of
        [] ->
            not_found;
        Matching ->
            {found, hd(Matching)}
    end.

get_bitcoind_tx(TxHash) ->
    call_bitcoind_api(<<"getrawtransaction">>, [TxHash]).

call_bitcoind_api(Command, JSONParams) ->
    B64 = base64:encode(?BITCOIND_JSON_RPC_USER ++ ":" ++ ?BITCOIND_JSON_RPC_PASS),
    Auth = "Basic " ++ binary_to_list(B64),
    Headers = [{"Content-Type", "text/plain"},
               {"Authorization", Auth}],
    JSONPL =
        [
         {<<"jsonrpc">>, <<"1.0">>},
         {<<"id">>, <<"for_rachael">>},
         {<<"method">>, Command},
         {<<"params">>, JSONParams}
        ],
    JSONBody = jiffy:encode({JSONPL}),
    %% ?info("JSON body: ~p", [JSONBody]),
    Resp = lhttpc:request(?BITCOIND_URL, post, Headers, JSONBody, 5000),
    %% ?info("bitcoind ~s response: ~p", [Command, Resp]),
    {ok,{{200,"OK"}, _HTTPRespPL, JSONResp}} = Resp,
    {[{<<"result">>, Result},
      {<<"error">>, null},
      {<<"id">>, _Id}]} = jiffy:decode(JSONResp),
    Result.

%%%===========================================================================
%%% Tests
%%%===========================================================================
