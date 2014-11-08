%%%===========================================================================
%%% Bitcoin protocol.
%%%
%%% References:
%%% 1. https://en.bitcoin.it/wiki/Protocol_specification
%%% 2. https://en.bitcoin.it/wiki/Script
%%%
%%%===========================================================================

%%%===========================================================================
%%% Block
%%%===========================================================================
-define(BLOCK_MAGIC_ID, <<16#D9, 16#B4, 16#BE, 16#F9>>).

%%%===========================================================================
%%% Transaction
%%%===========================================================================
-define(TX_VERSION,    <<16#01, 16#00, 16#00, 16#00>>).
-define(TX_IN_SEQ,     <<16#FF, 16#FF, 16#FF, 16#FF>>).
-define(TX_LOCK_TIME,  <<16#00, 16#00, 16#00, 16#00>>).

-define(SIGHASH_ALL,              <<16#01, 16#00, 16#00, 16#00>>).
-define(SIGHASH_ALL_ANYONECANPAY, <<16#81, 16#00, 16#00, 16#00>>).

%%%===========================================================================
%%% Script, see [2]
%%%===========================================================================
-define(OP_DUP,           16#76).
-define(OP_HASH160,       16#A9).
-define(OP_EQUALVERIFY,   16#88).
-define(OP_CHECKSIG,      16#AC).
-define(OP_CHECKMULTISIG, 16#AE).

-define(OP_0, 16#00).
-define(OP_2, 16#52).
-define(OP_3, 16#53).

%%%===========================================================================
%%% Misc
%%%===========================================================================
-define(BITCOIN_MIN_FEE, 10000).