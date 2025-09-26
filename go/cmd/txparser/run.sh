#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
# run.sh
# author David Egan <csknk@protonmail.com>
#
# Build & run the Bitcoin Tx Parser with a known input
# https://mempool.space/api/tx/e778e8765fdbb60f62e267de4705789f526a5fe9bb0c0f5e56ab4f566c5240eb/hex
# https://mempool.space/api/tx/e778e8765fdbb60f62e267de4705789f526a5fe9bb0c0f5e56ab4f566c5240eb
#
# --------------------------------------------------------------------------------------

rawTx="010000000104dde43b0e4724f1e3b45782a9bfbcc91ea764c7cb1c245fba1fefa175c3a5d0010000006a4730440220519f7867349790ee441e83e545afbd25b954a34e0733cd4da3b5f1e5588625050220166730d053c3672973bcb2bb1a977b747837023b647e3af2ac9c15728b0681da01210236ccb7ee3a9f154127f384a05870c4fd86a8727eab7316f1449a0b9e65bfd90dffffffff025d360100000000001976a91478364a559841329304188cd791ad9dabbb2a3fdb88ac605b0300000000001976a914064e0aa817486573f4c2de09f927697e1e6f233f88ac00000000"
bin=txparser
go build -o "$bin"

"./$bin" "$rawTx" | jq
