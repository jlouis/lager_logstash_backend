-module(lager_logstash_backend).

%% Started from the lager logstash backend
-author('marc.e.campbell@gmail.com').
-author('mhald@mac.com').

-behaviour(gen_event).

-export([init/1,
         handle_call/2,
         handle_event/2,
         handle_info/2,
         terminate/2,
         code_change/3,
         logtime/0,
         get_app_version/0
]).

-record(state, {connection ::
		  {udp, port(), inet:ip_address(), inet:port_number()}
		| {error, term()},
                lager_level_type :: 'mask' | 'number' | 'unknown',
                level :: atom() | integer(),
                node_role :: string(),
                node_version :: string(),
                metadata :: list()
}).

init(Params) ->
  %% we need the lager version, but we aren't loaded, so... let's try real hard
  %% this is obviously too fragile
  {ok, Properties}     = application:get_all_key(),
  {vsn, Lager_Version} = proplists:lookup(vsn, Properties),
  Lager_Level_Type =
    case string:to_float(Lager_Version) of
      {V1, _} when V1 < 2.0 ->
        'number';
      {V2, _} when V2 =:= 2.0 ->
        'mask';
      {_, _} ->
        'unknown'
    end,

  Level = lager_util:level_to_num(proplists:get_value(level, Params, debug)),
  Node_Role = proplists:get_value(node_role, Params, "no_role"),
  Node_Version = proplists:get_value(node_version, Params, "no_version"),

  Metadata = proplists:get_value(metadata, Params, []) ++
     [
         {pid, [{encoding, process}]},
         {line, [{encoding, integer}]},
         {file, [{encoding, string}]},
         {module, [{encoding, atom}]}
     ],

  Connection = connect(proplists:get_value(connection, Params, undefined)),


  {ok, #state{connection = Connection,
              lager_level_type = Lager_Level_Type,
              level = Level,
              node_role = Node_Role,
              node_version = Node_Version,
              metadata = Metadata}}.

handle_call({set_loglevel, Level}, State) ->
  {ok, ok, State#state{level=lager_util:level_to_num(Level)}};

handle_call(get_loglevel, State) ->
  {ok, State#state.level, State};

handle_call(_Request, State) ->
  {ok, ok, State}.

handle_event({log, _}, #state{connection={error, _Err}}=State) ->
  {ok, State};
handle_event({log, {lager_msg, Q, Metadata, Severity, {Date, Time}, _, Message}}, State) ->
  handle_event({log, {lager_msg, Q, Metadata, Severity, {Date, Time}, Message}}, State);
handle_event({log, {lager_msg, _, Metadata, Severity, {Date, Time}, Message}}, #state{level=L, metadata=Config_Meta, connection = Conn }=State) ->
    case guard_severity(Severity, L) of
        log ->
            JSONEvent =encode_json_event(State#state.lager_level_type,
                                                  node(),
                                                  State#state.node_role,
                                                  State#state.node_version,
                                                  Severity,
                                                  Date,
                                                  Time,
                                                  Message,
                                                  metadata(Metadata, Config_Meta)),
            send(Conn, JSONEvent);
        skip ->
           ok
    end,
    {ok, State};
handle_event(_Event, State) ->
  {ok, State}.

handle_info({'DOWN', MRef, process, Pid, _Reason},
  #state { connection = {redis, Pid, MRef, _}}) ->
    error_logger:error_report([reaping_event_handler, redis_is_down]),
    remove_handler;
handle_info(_Info, State) ->
  {ok, State}.

terminate(_Reason, #state{connection=Conn}=_State) ->
    close(Conn),
    ok;
terminate(_Reason, _State) ->
  ok.

code_change(_OldVsn, State, _Extra) ->
  %% TODO version number should be read here, or else we don't support upgrades
  Vsn = get_app_version(),
  {ok, State#state{node_version=Vsn}}.

encode_json_event(_, Node, NodeRole, NodeVersion, Severity, Date, Time, Message, Metadata) ->
  DateTime = io_lib:format("~sT~s", [Date,Time]),
  jsx:encode([{<<"fields">>, 
                    [
                        {<<"level">>, Severity},
                        {<<"role">>, list_to_binary(NodeRole)},
                        {<<"role_version">>, list_to_binary(NodeVersion)},
                        {<<"node">>, Node}
                    ] ++ Metadata },
                {<<"@timestamp">>, list_to_binary(DateTime)}, %% use the logstash timestamp
                {<<"message">>, safe_list_to_binary(Message)},
                {<<"type">>, <<"erlang">>}
            ]).

safe_list_to_binary(L) when is_list(L) ->
  unicode:characters_to_binary(L);
safe_list_to_binary(L) when is_binary(L) ->
  unicode:characters_to_binary(L).

get_app_version() ->
  [App,_Host] = string:tokens(atom_to_list(node()), "@"),
  Apps = application:which_applications(),
  case proplists:lookup(list_to_atom(App), Apps) of
    none ->
      "no_version";
    {_, _, V} ->
      V
  end.

logtime() ->
    {{Year, Month, Day}, {Hour, Minute, Second}} = erlang:universaltime(),
    lists:flatten(io_lib:format("~4.10.0B-~2.10.0B-~2.10.0BT~2.10.0B:~2.10.0B:~2.10.0B.~.10.0BZ",
        [Year, Month, Day, Hour, Minute, Second, 0])).

metadata(Metadata, Config_Meta) ->
    Expanded = [{Name, Properties, proplists:get_value(Name, Metadata)} || {Name, Properties} <- Config_Meta],
    [{list_to_binary(atom_to_list(Name)), encode_value(Value, proplists:get_value(encoding, Properties))} || {Name, Properties, Value} <- Expanded, Value =/= undefined].

encode_value(Val, string) when is_list(Val) -> list_to_binary(Val);
encode_value(Val, string) when is_binary(Val) -> Val;
encode_value(Val, string) when is_atom(Val) -> list_to_binary(atom_to_list(Val));
encode_value(Val, binary) when is_list(Val) -> list_to_binary(Val);
encode_value(Val, binary) -> Val;
encode_value(Val, process) when is_pid(Val) -> list_to_binary(pid_to_list(Val));
encode_value(Val, process) when is_list(Val) -> list_to_binary(Val);
encode_value(Val, process) when is_atom(Val) -> list_to_binary(atom_to_list(Val));
encode_value(Val, integer) -> list_to_binary(integer_to_list(Val));
encode_value(Val, atom) -> list_to_binary(atom_to_list(Val));
encode_value(_Val, undefined) -> throw(encoding_error).

%% Connect to the target
connect({redis, Host, Port, Key}) ->
    {ok, _} = application:ensure_all_started(eredis),
    Old = process_flag(trap_exit, true),
    Res = eredis:start_link(Host, Port),
    process_flag(trap_exit, Old),
    case Res of
        {ok, C} ->
            MRef = monitor(process, C),
            {redis, C, MRef, iolist_to_binary(Key)};
        {error, Err} ->
            {error, {redis, Err}}
    end;
connect({udp, Host, Port}) ->
    case inet:getaddr(Host, inet) of
        {ok, Addr} ->
            {ok, Sock} = gen_udp:open(0, [list]),
            {udp, Sock, Addr, Port};
        {error, Err} ->
            {error, {udp, Err}}
    end.

send({redis, Client, _Mref, Key}, Event) ->
    ok = eredis:q(Client, ["RPUSH", Key, Event]),
    ok;
send({udp, Sock, Host, Port}, Event) ->
    gen_udp:send(Sock, Host, Port, Event);
send({error, _}, _Event) ->
    ok.

close({udp, Sock, _,_}) ->
    gen_udp:close(Sock);
close({redis, C, MRef}) ->
    demonitor(MRef, [flush]),
    ok = eredis:stop(C),
    ok;
close({error, _}) ->
    ok.


%% Check if we should log a given severity at a given level.
guard_severity(Severity, L) ->
    case lager_util:level_to_num(Severity) =< L of
        true -> log;
        false -> skip
    end.
