defmodule MTProto do
  use Connection

  require Logger

  alias MTProto.{Auth, Crypto, Packet}

  def start_link(opts) do
    Connection.start_link(__MODULE__, opts)
  end

  def notifier_process(client, notifier_pid) do
    Connection.call(client, {:notifier_process, notifier_pid})
  end

  def authorize(client) do
    Connection.call(client, :authorize)
  end

  def authorize(client, auth_key, auth_key_hash, server_salt) do
    Connection.call(client, {:authorize, auth_key, auth_key_hash, server_salt})
  end

  def send_request(client, request) do
    Connection.call(client, {:send, request})
  end

  def dump_state(client) do
    Connection.call(client, :dump_state)
  end

  # ...

  defmodule State do
    @moduledoc """
    :notifier - pid of the process where MTProto client sends notifications;
    :socket - TCP socket;
    :packet_buffer - gluing incomplete TCP packets into fully one;
    :session_id - MTProto session ID, generated for every client instance (process);

    :auth_state authentication state, can be one of these values:
      * :connected - when client only connected to the telegram server;
      * :req_pq - first request to the server in authorization flow,
        requests P and Q numbers;
      * :req_dh_params - second request to the server, for getting DH data;
      * :dh_gen - last request to the server, to check new_nonce_hashN;
      * :encrypted - authorized state of the client, when it has auth_key,
        auth_key_hash and server_salt.

    :auth_params - for storing authentication params between steps, used AuthParams struct;
    :auth_key - authentication key, see MTProto docs for details;
    :auth_key_hash - authentication key hash;
    :server_salt - telegram server salt;
    :msg_seqno - used for storing message sequence number, for using in MTProto packets;
    :msg_ids - list of message IDs, using for server acks;
    :dc_options - list of telegram datacenters;
    :dc - current datacenter ID.
    """
    defstruct [:notifier, :socket,
               :packet_buffer,
               :session_id,
               :auth_state, :auth_params,
               :auth_key, :auth_key_hash, :server_salt,
               :msg_seqno, :msg_ids,
               :dc_options, :dc]
  end

  defmodule AuthParams do
    defstruct [:nonce, :server_nonce, :new_nonce, :nonce_hash1]
  end

  def init(opts) do
    notifier = opts[:notifier]
    session_id = Keyword.get(opts, :session_id, Crypto.make_session_id)
    msg_seqno = Keyword.get(opts, :msg_seqno, 0)

    {:connect, :init,
      %State{notifier: opts[:notifier], packet_buffer: <<>>,
             session_id: session_id, msg_seqno: msg_seqno, msg_ids: []}}
  end

  def connect(_, %{socket: nil} = state) do
    {host, port} = choose_server(state)
    Logger.debug("connect to #{inspect host}, #{inspect port}")

    case :gen_tcp.connect(host, port, [:binary, active: false], 5000) do
      {:ok, socket} ->
        Logger.debug("connected")
        send(self, :after_connect)
        send_to_notifier(state, :connected)
        {:ok, %{state|socket: socket, auth_state: :connected}}
      {:error, _} ->
        {:backoff, 1000, state}
    end
  end

  def disconnect(info, %{socket: socket} = state) do
    Logger.debug("disconnected #{inspect info}")
    :ok = :gen_tcp.close(socket)
    {:connect, :reconnect, %{state|socket: nil}}
  end

  def handle_call(:dump_state, _, state) do
    {:reply, state, state}
  end
  def handle_call(:authorize, _, state) do
    # init MTProto authorization
    state = Auth.init(self(), state)

    {:reply, :ok, state}
  end
  def handle_call({:authorize, auth_key, auth_key_hash, server_salt}, _, state) do
    # set auth credentials
    state =
      %{state|auth_state: :encrypted, auth_key: auth_key,
              auth_key_hash: auth_key_hash, server_salt: server_salt}

    # notify client about authentication
    send(self, :authorized)

    # set auth credentials
    {:reply, :ok, state}
  end
  def handle_call({:notifier_process, pid}, _, state) do
    {:reply, :ok, %{state|notifier: pid}}
  end
  def handle_call({:send, request}, _, %{socket: socket} = state) do
    case send_rpc_request(socket, request, state) do
      {:ok, state} -> {:reply, :ok, state}
      {:error, reason, state} -> {:disconnect, {:error, reason}, state}
    end
  end
  def handle_call(:close, from, s) do
    {:disconnect, {:close, from}, s}
  end
  def handle_call(_, _, state) do
    {:noreply, state}
  end

  def handle_info(:after_connect, %{socket: socket} = state) do
    # first packet
    :ok = :gen_tcp.send(socket, <<0xef>>)

    # allow to receive first packet
    next_packet(socket)

    Logger.debug("connection ok!")

    {:noreply, state}
  end
  def handle_info({:reconnect, reason}, state) do
    Logger.debug("reconnect #{inspect reason}")
    {:disconnect, {:reconnect, reason}, state}
  end
  def handle_info(:authorized, %{socket: socket} = state) do
    # notify about authorization result
    send(state.notifier,
      {:authorized, state.auth_key, state.auth_key_hash, state.server_salt})

    # init connection
    case send_rpc_request(socket, init_connection_request(), state) do
      {:ok, state} -> {:noreply, state}
      {:error, reason, state} -> {:disconnect, {:error, reason}, state}
    end
  end
  def handle_info({:send_bare, packet}, %{socket: socket} = state) do
    case :gen_tcp.send(socket, packet) do
      :ok ->
        {:noreply, state}
      {:error, reason} ->
        {:disconnect, {:error, reason}, state}
    end
  end
  def handle_info({:tcp, socket, packet}, state) do
    case Packet.decode(<<state.packet_buffer :: binary, packet :: binary>>) do
      {:more, _need_bytes, incomplete_packet} ->
        next_packet(socket)
        {:noreply, %{state|packet_buffer: incomplete_packet}}
      {:ok, packet, rest} ->
        state = %{state|packet_buffer: rest}

        # IO.puts " |-| packet:  #{inspect packet, limit: 50_000}"
        decode_result = Packet.decode_packet(packet, state)

        # IO.puts " |-| decoded: #{inspect decode_result}"
        case decode_result do
          {:error, reason} ->
            {:stop, {:error, reason}, state}
          {:ok, decoded_packet} ->
            case state.auth_state do
              :encrypted ->
                state = handle_packet(state, decoded_packet)
                next_packet(socket)
                {:noreply, state}
              _ ->
                handle_auth(self(), state, decoded_packet)
            end
        end
    end
  end
  def handle_info({:tcp_closed, socket}, state) do
    {:disconnect, :tcp_closed, state}
  end
  def handle_info(_request, state) do
    {:noreply, state}
  end

  defp handle_packet(state, packet) do
    IO.puts "\n\n ---- handle_packet #{inspect packet, limit: 100_000}\n"
    case packet do
      %TL.MTProto.Msg.Container{messages: messages} ->
        Enum.reduce(messages, state, fn(message, state) ->
          handle_packet(state, message)
        end)
      %TL.MTProto.Message{msg_id: msg_id, body: body} ->
        handle_packet(state, body)
      %TL.MTProto.Msgs.Ack{msg_ids: msg_ids} ->
        %{state|msg_ids: state.msg_ids -- msg_ids}
      %TL.MTProto.New.Session.Created{server_salt: server_salt} ->
        # convert to binary
        server_salt = <<server_salt :: little-size(64)>>
        # notify about authorization result, because this packet means
        # that connection is initialized after authorization
        send_to_notifier(state,
          {:authorized, state.auth_key, state.auth_key_hash, server_salt})
        # update state
        %{state|server_salt: server_salt}
      %TL.MTProto.Rpc.Error{error_code: code, error_message: message} ->
        send_to_notifier(state, {:error, code, message})
        # TODO do we need to reconnect when server responds with error?
        # send(self, {:reconnect, :change_dc})
        state
      %TL.MTProto.Rpc.Result{req_msg_id: msg_id, result: result} ->
        state = handle_packet(state, result)
        # FIXME do we need to remove msg_id from current state in this place?
        %{state|msg_ids: state.msg_ids -- [msg_id]}
      %TL.MTProto.Bad.Server.Salt{new_server_salt: server_salt} ->
        # convert to binary
        server_salt = <<server_salt :: little-size(64)>>
        send(self, {:reconnect, :server_salt_changed})
        send_to_notifier(state, {:config, :server_salt, server_salt})
        %{state|server_salt: server_salt}
      %TL.MTProto.Gzip.Packed{packed_data: packed_data} ->
        {:ok, data} = TL.Serializer.decode(:zlib.gunzip(packed_data))
        handle_packet(state, data)
      # stores this_dc and dc list, changes when server fails
      # or returns Rpc.Error, or accidentally disconnected
      %TL.Config{dc_options: dc_options, this_dc: dc} = config ->
        # notify config
        send_to_notifier(state, {:config, :server_config, config})
        %{state|dc_options: dc_options, dc: dc}
      result ->
        # IO.puts " --- handle_packet result: #{inspect result}"
        send_to_notifier(state, {:result, result})
        state
    end
  end

  defp handle_auth(client, state, packet) do
    case Auth.handle(client, state, packet) do
      {:ok, new_state} ->
        next_packet(state.socket)
        {:noreply, new_state}
      {:error, reason, new_state} ->
        {:stop, {:error, reason}, new_state}
    end
  end

  defp init_connection_request do
    %TL.InvokeWithLayer{
      layer: 57,
      query: %TL.InitConnection{
        api_id: config(:api_id),
        device_model: config(:device_model, "elixir"),
        system_version: config(:system_version, "0.1.0"),
        app_version: config(:app_version, "0.0.1"),
        lang_code: config(:lang_code, "en"),
        query: %TL.Help.GetConfig{}}}
  end

  defp send_to_notifier(state, message) do
    send(state.notifier, {:tl, message})
  end

  defp send_rpc_request(socket, request, state) do
    {packet, state} = Packet.encode(request, state)

    send_to_notifier(state, {:msg_seqno, state.msg_seqno})

    case :gen_tcp.send(socket, packet) do
      :ok ->
        {:ok, state}
      {:error, reason} ->
        {:error, reason, state}
    end
  end

  defp next_packet(socket) do
    :ok = :inet.setopts(socket, active: :once)
  end

  defp choose_server(%{dc: dc, dc_options: dc_options} = state) when length(dc_options) > 0 do
    acceptable_dcs = Enum.filter(dc_options, fn(dc_opt) ->
        dc_opt.ipv6 == false and dc_opt.id != dc
      end)

    new_dc = Enum.random(acceptable_dcs)

    {String.to_charlist(new_dc.ip_address), new_dc.port}
  end
  defp choose_server(_state) do
    {telegram_host(), telegram_port()}
  end

  defp telegram_host do
    config(:host)
  end

  defp telegram_port do
    config(:port)
  end

  defp config(key, default \\ nil) do
    Application.get_env(:mtproto, key, default)
  end
end
