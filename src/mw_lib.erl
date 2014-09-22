%%%-------------------------------------------------------------------
%%% @author Gustav Simonsom <gustav.simonson@gmail.com>
%%% @copyright (C) 2014, AI Effect Group, Berlin
%%% @doc
%%% PostgreSQL / epgsql query utility functions
%%% @end
%%% Created : 06 Jun 2014 by gustav <gustav.simonsson@gmail.com>
%%%-------------------------------------------------------------------
-module(mw_lib).

-compile(export_all).
%% API
-export([]). %% TODO: remove export_all and add API exports

-include("mw.hrl").
-include("mw_contract.hrl").
-include("mw_api_errors.hrl").
-include("log.hrl").
-include_lib("proper/include/proper.hrl").

-define(DEFAULT_REQUEST_TIMEOUT, 5000).

-define(B58_ALPHABET,
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz").
-define(B58_BASE, length(?B58_ALPHABET)).
-define(ALPHABET_CODE(Num), lists:nth((Num rem ?B58_BASE) + 1, ?B58_ALPHABET)).

%%%===========================================================================
%%% API
%%%===========================================================================
hex_to_bin(L) when is_list(L) -> hex_to_bin(binary:list_to_bin(L));
hex_to_bin(B) when is_binary(B) ->
    <<<<(list_to_integer([D,D2], 16))>> || <<D,D2>> <= B>>.

bin_to_hex(B) when is_binary(B) ->
    <<<<(binary:list_to_bin(case length(S = integer_to_list(I, 16)) of
                                1 -> [$0|S];
                                2 -> S
                            end))/bytes>> || <<I>> <= B>>.

%% We assume application/version byte was already concatenated with payload
enc_b58check(S) when is_list(S) ->
    enc_b58check(binary:list_to_bin(S));
enc_b58check(B) when is_binary(B) ->
    <<Hash:4/bytes, _/binary>> = double_sha256(B),
    enc_b58(<<B/binary, Hash/binary>>).

dec_b58check(S) when is_list(S)   -> dec_b58check(binary:list_to_bin(S));
dec_b58check(B58) when is_binary(B58) ->
    PayloadLen = byte_size(Bin = dec_b58(B58)) - 4,
    <<Payload:PayloadLen/bytes, Hash:4/bytes>> = Bin,
    <<ExpectedHash:4/bytes, _/binary>> = double_sha256(Payload),
    [throw(base58_checksum_validation_failed) || not (ExpectedHash =:= Hash)],
    Payload.

leading_zeroes_as_ones(<<0, B/binary>>) ->
    <<"1", (leading_zeroes_as_ones(B))/binary>>;
leading_zeroes_as_ones(_B) -> <<>>.

remove_leading_zeroes(<<0, B/binary>>) -> remove_leading_zeroes(B);
remove_leading_zeroes(B) -> B.

split_leading_ones_to_zeroes(<<"1", B/binary>>, Acc) ->
    split_leading_ones_to_zeroes(B, <<0, Acc/binary>>);
split_leading_ones_to_zeroes(B, Acc) -> {Acc, B}.

double_sha256(B) when is_binary(B) ->
    crypto:hash(sha256, crypto:hash(sha256, B)).

enc_b58(S) when is_list(S)   -> enc_b58(binary:list_to_bin(S));
enc_b58(<<>>)                -> <<>>;
enc_b58(B) when is_binary(B) ->
    case Rest = remove_leading_zeroes(B) of
        <<>> ->
            <<(leading_zeroes_as_ones(B))/binary>>;
        _ ->
            Enc = enc_b58(binary:decode_unsigned(Rest), <<>>),
            <<(leading_zeroes_as_ones(B))/binary, Enc/binary>>
    end.

enc_b58(Num, Acc) when Num < ?B58_BASE ->
    <<(?ALPHABET_CODE(Num)), Acc/binary>>;
enc_b58(Num, Acc) ->
    enc_b58(Num div ?B58_BASE, <<(?ALPHABET_CODE(Num)), Acc/binary>>).

dec_b58(S) when is_list(S) ->
    dec_b58(binary:list_to_bin(S));
dec_b58(<<>>) -> <<>>;
dec_b58(B) when is_binary(B) ->
    case split_leading_ones_to_zeroes(B, <<>>) of
        {Zeroes, <<>>} ->
            <<Zeroes/binary>>;
        {Zeroes, Rest} ->
            <<Zeroes/binary, (dec_b58(rev_bin(Rest), 1, 0))/binary>>
    end.

dec_b58(<<>>, _Pow, Num) ->
    binary:encode_unsigned(Num);
dec_b58(<<C, Rest/binary>>, Pow, Num) ->
    case pos_in_list(C, ?B58_ALPHABET) of
        {error, _} ->
            {error, invalid_base58};
        Pos ->
            dec_b58(Rest, Pow * ?B58_BASE, Num + (Pow * (Pos - 1)))
    end.

rev_bin(Bin) -> rev_bin(Bin, <<>>).
rev_bin(<<>>, Acc) -> Acc;
rev_bin(<<H:1/binary, Rest/binary>>, Acc) -> %% binary concatenation is fastest?
    rev_bin(Rest, <<H/binary, Acc/binary>>).

pos_in_list(E, L) when is_list(L) ->
    pos_in_list_aux(E, L, 1).

pos_in_list_aux(E, [E|_], Pos) -> Pos;
pos_in_list_aux(E, [_|T], Pos) -> pos_in_list_aux(E, T, Pos + 1);
pos_in_list_aux(_E, [], _Pos) -> {error, not_in_list}.


datetime_to_iso_timestamp({Date, {H, Min, Sec}}) when is_float(Sec) ->
    %% TODO: proper support for milliseconds
    datetime_to_iso_timestamp({Date, {H, Min, round(Sec)}});
datetime_to_iso_timestamp({{Y, Mo, D}, {H, Min, Sec}}) when is_integer(Sec) ->
    FmtStr = "~4.10.0B-~2.10.0B-~2.10.0BT~2.10.0B:~2.10.0B:~2.10.0BZ",
    IsoStr = io_lib:format(FmtStr, [Y, Mo, D, H, Min, Sec]),
    list_to_binary(IsoStr).

now_unix_timestamp() ->
    {M, S, _} = os:timestamp(),
    M*1000000 + S.

unix_ts_to_datetime(TS) when is_integer(TS) ->
    Start = calendar:datetime_to_gregorian_seconds({{1970,1,1},{0,0,0}}),
    calendar:gregorian_seconds_to_datetime(Start + TS).

bj_http_req(URL) ->
    bj_http_req(URL, [], ?DEFAULT_REQUEST_TIMEOUT).
bj_http_req(URL, BodyArgs) ->
    bj_http_req(URL, BodyArgs, ?DEFAULT_REQUEST_TIMEOUT).
bj_http_req(URL, _BodyArgs, Timeout) ->
    %% TODO: does cowboy has something like this?
    %% Body = mochiweb_util:urlencode(BodyArgs),
    Headers = [], %% [{content_type, "application/x-www-form-urlencoded"}],
    lhttpc:request(ensure_list(URL), get, Headers, [], Timeout).

ensure_list(B) when is_binary(B) -> binary:bin_to_list(B);
ensure_list(L) when is_list(L) -> L.

set_resp_headers(Headers, Req) ->
    SetHeader = fun({H,V}, ReqAcc) ->
                        cowboy_req:set_resp_header(H, V, ReqAcc)
                end,
    lists:foldl(SetHeader, Req, Headers).

cowboy_req_enable_cors(Req) ->
    Req2 = set_resp_headers([
                             %% TODO: what headers do we need to enable CORS?
                             {<<"Access-Control-Allow-Origin">>,
                              <<"http://127.0.0.1">>
                                  %%<<"*">>
                             },
                             {<<"Access-Control-Allow-Methods">>, <<"GET,POST,OPTIONS">>}
                            ],
                            Req),
    Req2.
%%%===========================================================================
%%% Internal functions
%%%===========================================================================
%%%===========================================================================
%%% Tests
%%%===========================================================================
proper() ->
    ProperOpts =
        [{to_file, user},
         {numtests, 10000}],
    true = proper:quickcheck(prop_base58(), ProperOpts),
    true = proper:quickcheck(prop_base58check(), ProperOpts),
    true = proper:quickcheck(prop_hex(), ProperOpts),
    ok.

prop_base58() ->
    ?FORALL(Bin,
            binary(),
            begin
                Bin =:= mw_lib:dec_b58(mw_lib:enc_b58(Bin))
            end).

prop_base58check() ->
    ?FORALL(Bin,
            binary(),
            begin
                Bin =:= mw_lib:dec_b58check(mw_lib:enc_b58check(Bin))
            end).

prop_hex() ->
    ?FORALL(Bin,
            binary(),
            Bin =:= mw_lib:hex_to_bin(mw_lib:bin_to_hex(Bin))).

aes_enc(Key, Plaintext) when byte_size(Key) == 16 ->
    PaddingLen = 16 - (byte_size(Plaintext) rem 16),
    Padding = binary:copy(<<PaddingLen>>, PaddingLen),
    PaddedPlaintext = <<Plaintext/binary, Padding/binary>>,

    Ciphertext = crypto:block_encrypt(aes_cbc128,
                                      Key,
                                      <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>,
                                      PaddedPlaintext),
    {ok, Ciphertext}.

aes_dec(Key, Ciphertext) when byte_size(Key) == 16 ->
    crypto:block_decrypt(aes_cbc128,
                         Key,
                         <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>,
                         Ciphertext).

%% TODO: this assumes RSA 2048.
hybrid_aes_rsa_enc(Plaintext, RSAPubkey) ->
    %% TODO: validate entropy source! We may want to block for /dev/random
    %% to be sure the AES key is cryptographically strong.
    AESKey = crypto:strong_rand_bytes(16),
    %% PKCS #7 padding; value of each padding byte is the integer representation
    %% of the number of padding bytes. We align to 16 bytes.
    PaddingLen = 16 - (byte_size(Plaintext) rem 16),
    Padding = binary:copy(<<PaddingLen>>, PaddingLen),
    PaddedPlaintext = <<Plaintext/binary, Padding/binary>>,
    Ciphertext = crypto:block_encrypt(aes_cbc128, AESKey,
                                      ?DEFAULT_AES_IV, PaddedPlaintext),
    %% Use OAEP as it's supported by Tom Wu's rsa2.js (RSADecryptOAEP)
    %% http://en.wikipedia.org/wiki/Optimal_Asymmetric_Encryption_Padding
    {_RecordName, Modulus, Exponent} = RSAPubkey,
    EncAESKey = crypto:public_encrypt(rsa, AESKey, [Exponent, Modulus],
                                      rsa_pkcs1_oaep_padding),
    %% Distinguishable prefix to identify the binary in case it's on the loose
    <<(mw_lib:hex_to_bin(?BINARY_PREFIX))/binary,
      EncAESKey/binary,
      Ciphertext/binary>>.

pem_decode_bin(Bin) ->
    [Entry] = public_key:pem_decode(Bin),
    Key = public_key:pem_entry_decode(Entry),
    {ok, Key}.

%% Single, top-level try catch to ensure we return correct JSON error code / msg
%% for all handled errors, with a default for any unhandled error (crash).
%% This allows code deeper in the stack to be written in idiomatic Erlang style
%% for the correct case, without defensive coding.
json_try_catch_handler(HandleFun) ->
    try
        Response = HandleFun(),
        %% ?info("Response: ~p", [Response]),
        jiffy:encode(pl_to_ejson(Response))
    catch throw:{api_error, {ErrorCode, ErrorMsg}} ->
            ?error("Handled API Error Code: ~p : ~p", [ErrorCode, ErrorMsg]),
            Response2 = {[{<<"error-code">>, ErrorCode},
                          {<<"error-message">>, ErrorMsg}]},
            jiffy:encode(Response2);
          Error:Reason ->
            Stack = erlang:get_stacktrace(),
            ?error("Unhandled Error: ~p Reason: ~p Stack: ~p",
                   [Error, Reason, Stack]),
            jiffy:encode({[{<<"error-code">>, 0},
                           {<<"error-message">>,
                            <<"Something is on fire. Don't panic. "
                              "Blame Gustav.">>}]})
    end.

pl_to_ejson(undefined) -> null;
pl_to_ejson([]) -> [];
pl_to_ejson([{_,_}|_] = X) -> {[{K, pl_to_ejson(V)} || {K, V} <- X]};
pl_to_ejson(List) when is_list(List) -> [pl_to_ejson(I) || I <- List];
pl_to_ejson(Other) -> Other.

api_validation(false, APIError) -> ?API_ERROR(APIError);
api_validation(true, _)         -> continue.

%%%===========================================================================
%%% Dev / Debug / Manual Tests
%%%===========================================================================
decryption_test(_UserECPrivkey, UserRSAPrivkeyPEM,
                OraclePrivkeyHex, EncEventKey) ->
    {ok, UserRSAPrivkey} = mw_lib:pem_decode_bin(UserRSAPrivkeyPEM),
    {ok, OraclePrivkey} = mw_lib:pem_decode_bin(mw_lib:hex_to_bin(OraclePrivkeyHex)),

    <<_Prefix:8/binary, EncAESKey:256/binary, CipherText1/binary>> =
        mw_lib:hex_to_bin(EncEventKey),
    AESKey = public_key:decrypt_private(EncAESKey, UserRSAPrivkey),
    Plaintext1 = crypto:block_decrypt(aes_cbc128,
                                      AESKey,
                                      ?DEFAULT_AES_IV,
                                      CipherText1),
    %% Yo dawg
    <<_Prefix:8/binary,
      EncAESKey2:256/binary,
      CipherText2/binary>> = remove_pkcs_7_padding(Plaintext1),
    AESKey2 = public_key:decrypt_private(EncAESKey2, OraclePrivkey),
    Plaintext2Padded = crypto:block_decrypt(aes_cbc128,
                                            AESKey2,
                                            ?DEFAULT_AES_IV,
                                            CipherText2),
    Plaintext2 = remove_pkcs_7_padding(Plaintext2Padded),
    ?info("Plaintext2: ~p, is base58check: ~p",
          [Plaintext2, is_binary(catch mw_lib:dec_b58check(Plaintext2))]),
    ok.

log(Call, Param, Expect) ->
    ?info(
        list_to_binary(
            io_lib:format("-----------------------~ncall: ~p~nparameter: ~p~nexpected response: ~p~n",
                [Call, Param, Expect]))).

remove_pkcs_7_padding(Bin) ->
    Len = byte_size(Bin),
    PaddingLen = binary:last(Bin),
    binary:part(Bin, {0, Len - PaddingLen}).

%% mw_contract:decryption_test_1().
decryption_test_1() ->
    mw_contract:decryption_test(
      <<"5KDPmciYDKwsfY6nkKrsQvS6aFMRPaBMHGwY5EMRu41keyukhHU">>,
      <<"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAte5anzaNkLHc5X81utnpaeGQka3R6mgc3rT+M8qXNax9NKGJ\nEXqmCHG+Kbbx0CqvdL0wxyfg7tmiF+EW5pqjlSWwqBPvYUJYWiT1z/sscAnoM1zr\nL3M6NSWhztTj97+Pfn5RdehhMJ2VmnxczJxPuncrkH1UoSS1cduiBplDAMYsk8eW\nuwVpW8RDgAooAm2j2GqJWpi+y2qv4RaM59jY7dPgudQPPdCm7u2l4YK1tesMtsAZ\na4fWdPwW3JMuJ7SSf9V7NshhH78BixOcZA6lZm7vldmXYaFRS9sVMZ65S8S9UYGB\nbO3RmpOOYwT0GCFS7O6/WUWtvoxaYbAXRaUb9QIDAQABAoIBAFFPJ71EelySwXDo\nO7E4tvMVVrFlCA5FXbHDHmEzSAU7A/JDx6jCMfZQL3chRk2M5kG8VFKN5h+ZsLIP\nbVa/AiEkaSGVV0UWi7ouDpZXYXLpWpeqDYp1ayxZl0mDKCePu6gC+JFDvDwoEbar\noiXoLlHd9OBswygJ6fXq/S0JzkJHjo+hUOzFI6iZtM4IfpfFjXU/1wU/eSjWVxzr\napelnSz5CsV/kouHnpD9tGudnBKOilcWnYmhr1WsTI2xiNZWKkxKylj+zj9Fkp+v\nHOYR8UCTuWVPKLS6JaPd2TCAMagPjTB9sS13HhJZguFm14PgVQtcOUSfkpIpXOlM\nA4v5vDkCgYEA4Nad92oJ3N80MPEdSPqaC2pfDc1NVOjY72XrTLOcnTYZ2HWTg8/6\nKKdCV0ipmVo/n/wH+vkM54Njtj/dQHdGUeozK89e1UG0vQHXScS3ZtaAVZlF1msC\niFx9sS9HuJI0JFNIQPNTEq7Fs4ZLfJdhcGgeMz6VAjRL7AHo+ZLH4U8CgYEAzyVd\nODLqcwCh7NaDdYjCrmDRf3VBOBAyjeHGKoTjTa6v+7p8gH6DQDyehDuXDiCrA8xH\nVIMF/62VElXKwqvOnbLMm2kUkDycSDseQFzSFbk6x/xlw0WSVe56T7qWnM4KkJEw\n3TqVzYoTNM7mYiK5VtGB5cnjdSS57YVD3bQBtXsCgYEAqFFCtMPXWlhmU/VNPSMO\nS1l4i3aUW+ps7NtZyXP03ORxeNCcfGMoHWMJkRo+jSU42GXu+32SoYaFERzCX85r\nAEvZvwRhNDkaOxyztO/ldMFEFdDGrXwyyy6ikhCZGp2pF0CZqLYADM52Bq2UuVMC\niQoJAcfp+Vp5M9dCOAQgSpUCgYAsY7liPab4Ff6dHir1mOT/MUgzpBDhzrbGqMcq\nfWeoUfLsYr4jWvkNXvApLgvkvyNmoPP4LEuwyqXTVAcrSF3ydUpbU11Qu2xSHjkR\nWdK7TQJHsNKt0c7WE1CqnTWBTLX+3N43ykIn1ZrgCiZciUxmSmcnsufHRqOBPrmY\nXOaw2QKBgQCZpCI52nKRBaDB3cfKS2gW+M2hBBHVd/yMg5l+QI3nO1qqS3oRAZli\nssOjdcizgf5lJIosmjr3mmLtfBg6vWah0DmHaJh8NC58c7X8//1sHmd7Pv/r1Jpc\nrQabJyiQFULwgUJTmNUlY70Ii+q4Yk25F7S83s+ld3kXNbs5/d6dUA==\n-----END RSA PRIVATE KEY-----">>,
      <<"2d2d2d2d2d424547494e205253412050524956415445204b45592d2d2d2d2d0a4d4949456f77494241414b43415145417a51463646714845523242684444637643412b66496375472b416f62442b7865613147625753786845385158354455650a5667413531447951484b424d7031636a54783530486347706f4d67746e48663057435a306d7a4f665a623462656835366c7035754a62787a6849664a6d3436530a6541557746306f34357a46566d75556b5777726463524a4842496968344b686d444c69456a5334334978436e764d797058532f567a6c4b2f4564386c30376b410a79384a62482f4e6149493739545361567772663333796a474d4261703333695251597a464a744c44384d424b77714165306931596a584b6238666c306c762b710a386b6c38534a48696e4863747459785074667a5978545173796b6658644e786b5445687a324c757552704244764c44324a746e45416b743352384c707a6230720a7956342f497047594b58314436664c764f772f6c6f2f6d2f55654541583578726849352f6d77494441514142416f49424147474445315353693638377938326f0a72676c536a4f6e68536f6a50486349384e306b7133773753696a614272712b52434b58316f3477745a6f7348514937555a756f715853634f5343592f4d5672630a762b2f7945734d4545677975475a6e447836472f4b4474773453326e2f53437439304e356a4439337759744f7278356e59687967465762455039324c4e42794e0a5855557475336341425a2f374f7834563533563433475577664d76396b7277364641316a2f4e744342615a47576a48496c543445314542722b774866545971520a513745736633693241632b3848337a34764e3261693141485a4f4564765a636b38546355316c6f5a617a6a667851694d7378355a4a6c395a2b68443730682b6b0a6462366d3963597677432f484b7550732b64692f395272537237367942374c4963664a532b474743315272684b4c386d353841364a595a51495150694130396c0a5179364e2f544543675945412b31453753796a576a543377626e51466856622b716c6658554b5a4f663242547a354c626a784e472b45503770484d42317074540a4d4d3155656d7368456d6e436f7a7930646e354c6d767156616f6265575548714d4a444b63663735354e6b687355513667734a6e7578394d366f4675795975750a4150614b733231737843382f4f716162586d50783462657665637754665848555545485567364e4a4337366f47306267526653554b486b4367594541304e4e580a6a37643377553754453635356e586c53316961736f6e74486a615376642b304d6b2b74776e7a454761394e32764153634e43786155336c5764782f51717739630a6142564e3456413479516e46665344645276442f61667376664a6c69773063726a6c4b31332f595253434f4331676c4d58452f657654416d434e78333535536d0a4d384e366a4d50724a377a486d6d5a5a352b6e65496f734136467a39434d71327961444243374d43675945413053436b62594f6248636448396a47586b6f42300a78447a3655414e44324e7a496754646365713934354168324d7a3738625a2b73317a5256737454496e5844695a5547546a664c4561543952374759305369502b0a673946496c526d75796f386761556b30517a4551626e6136593332334f6747416c773652466f50632b56657a6a744f72414232383371346957414449797839590a7044785459674d544f724735593546542b514a7638306b43675941747146653373337836686e702b44694c472f48545248386d564350452f4665664c683865390a4f376633426d674b415555766e4b3575646467563869796d6851314271573068304b366a65622f41724f4e4346594a723956745331376d744f3367746a4130490a354371683268497a504a68707063544e566955304a6966617669463150376f4c4455317049356a78716b50574456545138514242657a54716d524931377553430a4e79536549774b4267465051715941394a4a77363668615230634d4b59356d424b3039396a2b4a6b6464537031464a434345693569724d7062764379374d68780a76336c4348705a6b42616d435a3942484f7a63785730532b4e584f54614464536e764c6b45777938692f505641566d73794251517938617a736f7537787477410a333579355a754c365a3670585865576c774f7973434e73486d77575448347047586c6272656e797579324e6b435139392b7843440a2d2d2d2d2d454e44205253412050524956415445204b45592d2d2d2d2d0a">>,
      <<"a1effec1000000008219cc73f7a5be22c634bb81a363aebe75d1e22656e073b5b428564f2c0430ba32b85381a62ee5bca6f3fb8680efa0b2c6bdf3267dbddb74615713e382b5745c6f36361545631dd105ec0a346ef17b9bff3b41f9220e65f3e7919d36b0fc5345bb69d12de124e43b0105cddb662d371563dae2ed341f5dcef2c8df388cc1d53c18893100c4dd5accf6a9db69ed865068bb0f851b41b6c90b6d7b7613018b742c1c558e18478b80870066bac2477fe9d8a1ba51330c91f993f8eab116797fc3c8226c3a2a2d67d83d445d755cbfaac653b2489c1743b28f6c3431db10e9d5548900a4ef871c1049dcc12d693e12aa9d1de8057ca226ee94ebb4f16efe02bbae0b612f88bd3386fa821d9f5c8a59603ff5ce4381c66b8629d2d66e75c2803f97911b0e78e8b382ff27925b839b627bf02eeba1f1b9e56f902a32cd163d80d9535c50bff2014f8168d4b7a99bd6cab77dfd77d78301834f58ca2e28c43e42b98fd5329ecbfb55ef5b9f1ae27fca829a5ae5ccbed1491b4983243cd6710aeede6fc0371f9201bb85b2ca15d45db7157dc9a8cb323cd5386e0e8ff6413621848384dd3559370d4b32befb1182c2b68730f05a9e0e9ecf49bcb9bf3053142744b054b80567cf5fecf2b092663d6545a8a6725df89d15207d943a1c5254cdc6459314847aa567f599bac759208e5846920f8a191cdaed045f5ca8b138d17f16a125652dfb8848cf351fe29d7f4fd8143c0f1b010999b627a035bf642775b802375983b9b30aefdf786c08df8213f636dea70b7d0c08884a4bf94d19e16588f809c8f3fb02f730a67f1dc722b587856a6837fb08">>).
