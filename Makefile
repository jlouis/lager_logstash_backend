#!/usr/bin/make
REBAR=./rebar3

compile:
	${REBAR} compile | sed -e 's|_build/default/lib/lager_logstash_backend/||g'

