# shadowsocks-lua

Shadowsocks client implement in Lua, based on my libuv binding.

Usage: luajit Shadowsocks.lua local.json

The json file is compatible with the official one.

# TODOs:

I will implement these functions one-by-one:

1. iptables-based transparent proxy on Linux
2. dynamic proxying without PAC files
3. HTTP CONNECT proxy and a web UI to control it
4. Shadowsocks server with Web UI authentication
5. Easy-to-deploy scripts

# Benchmarking

I wrote a server that prints how many client it has accepted after 10 seconds and sends 20000 SOCKS5 connect request to the Shadowsocks client. The Shadowsocks server is the official python server.py. Here are the results:

## This implement

luajit 59.9 MiB
server 110.2 MiB

Got 16669 connections.

## Python implement

local 58.8 MiB
server 66.7 MiB

Got 9056 connections.
