defmodule MTProto do
  use Connection

  require Logger

  alias MTProto.{Auth, Crypto, DC, Math, Packet, Response}

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

  def close(client) do
    Connection.call(client, :close)
  end

  # gen_server callbacks

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
    :dc - current datacenter ID;
    :reconnect - reconnect state, see MTProto.DC for details.
    """
    defstruct [:notifier, :socket,
               :packet_buffer,
               :session_id,
               :auth_state, :auth_params,
               :auth_key, :auth_key_hash, :server_salt,
               :msg_seqno, :msg_ids, :msg_ids_to_ack,
               :last_message_id, :server_time_offset,
               :dc_options, :dc,
               :reconnect]
  end

  defmodule AuthParams do
    defstruct [:nonce, :server_nonce, :new_nonce, :nonce_hash1]
  end

  def init(opts) do
    session_id = Keyword.get(opts, :session_id, Crypto.make_session_id)
    msg_seqno = Keyword.get(opts, :msg_seqno, 0)
    last_message_id = Keyword.get(opts, :last_message_id, 0)
    server_time_offset = Keyword.get(opts, :server_time_offset, 0)

    {:connect, :init,
      %State{auth_state: :connected, notifier: opts[:notifier], packet_buffer: <<>>,
             session_id: session_id, msg_seqno: msg_seqno, msg_ids: %{}, msg_ids_to_ack: [],
             last_message_id: last_message_id, server_time_offset: server_time_offset}}
  end

  def connect(_, %{socket: nil} = state) do
    {host, port} = choose_server(state)
    Logger.debug("connect to #{inspect host}, #{inspect port}")

    case :gen_tcp.connect(host, port, [:binary, active: false], 5000) do
      {:ok, socket} ->
        send(self, :after_connect)
        send_to_notifier(state, {:connected, host, port})
        {:ok, %{state|socket: socket}}
      {:error, _} ->
        {:backoff, 1000, state}
    end
  end

  def disconnect({:close, _from}, %{socket: socket} = state) do
    :ok = :gen_tcp.close(socket)
    {:stop, :normal, state}
  end
  def disconnect({:reconnect, reason}, %{socket: socket} = state) do
    Logger.debug("need to reconnect #{inspect reason}")
    :ok = :gen_tcp.close(socket)
    {:connect, :reconnect, %{state|socket: nil}}
  end
  def disconnect(info, %{socket: socket} = state) do
    Logger.debug("disconnected #{inspect info}")
    :ok = :gen_tcp.close(socket)
    {:connect, :reconnect, %{state|socket: nil}}
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
      {:ok, state, message_id} -> {:reply, {:ok, message_id}, state}
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

    # TODO migrate to another DC
    # if we tried to reconnect
    # state =
    #   case state.reconnect do
    #     {:dc, dc_id} ->
    #       # auth_key used from %TL.Auth.ExportedAuthorization{id: user_id, bytes: auth_key}
    #       %TL.Auth.ImportAuthorization{id: user_id, bytes: auth_key}
    #     _ ->
    #       state
    #   end

    if state.auth_key && state.auth_key_hash && state.server_salt do
      send(self, :authorized)
    end

    schedule_ack()

    {:noreply, %{state|reconnect: nil}}
  end
  def handle_info({:reconnect, {:change_dc, dc_id} = reason}, state) do
    Logger.debug("migrate to DC##{dc_id}")
    {:disconnect, {:reconnect, reason}, %{state|reconnect: {:dc, dc_id}}}
  end
  def handle_info({:reconnect, reason}, state) do
    Logger.debug("reconnect #{inspect reason}")
    {:disconnect, {:reconnect, reason}, %{state|reconnect: :random}}
  end
  def handle_info(:authorized, %{socket: socket} = state) do
    # init connection
    case send_rpc_request(socket, init_connection_request(), state) do
      {:ok, state, _} -> {:noreply, state}
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
  def handle_info(:ack_msg_ids, %{msg_ids_to_ack: acks} = state) do
    if state.auth_state == :encrypted && length(acks) > 0 do
      case send_rpc_request(state.socket, msgs_ack(acks), state) do
        {:ok, state, _} ->
          schedule_ack()
          {:noreply, %{state|msg_ids_to_ack: []}}
        {:error, reason, state} ->
          {:disconnect, {:error, reason}, state}
      end
    else
      schedule_ack()
      {:noreply, state}
    end
  end
  def handle_info({:sync_server_time, server_time}, state) do
    offset = server_time - :erlang.system_time(:seconds)
    {:noreply, %{state|server_time_offset: offset}}
  end
  def handle_info({:tcp, socket, packet}, state) do
    case Packet.decode(<<state.packet_buffer :: binary, packet :: binary>>) do
      {:more, _need_bytes, incomplete_packet} ->
        next_packet(socket)
        {:noreply, %{state|packet_buffer: incomplete_packet}}
      {:ok, packet, rest} ->
        state = %{state|packet_buffer: rest}
        decode_result = Packet.decode_packet(packet, state)

        case decode_result do
          {:error, reason, state} ->
            {:stop, {:error, reason}, state}
          {:ok, decoded_packet, meta, state} ->
            case state.auth_state do
              :encrypted ->
                state = Response.handle(state, decoded_packet, meta)
                next_packet(socket)
                {:noreply, state}
              _ ->
                handle_auth(self(), state, decoded_packet)
            end
        end
    end
  end
  def handle_info({:tcp_closed, _socket}, state) do
    {:disconnect, :tcp_closed, state}
  end
  def handle_info(_request, state) do
    {:noreply, state}
  end

  def terminate(_reason, _state) do
    # :gen_tcp.close(state.socket)
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

  defp msgs_ack(acks) do
    %TL.MTProto.Msgs.Ack{msg_ids: acks}
  end

  defp send_to_notifier(state, message) do
    send(state.notifier, {:tl, message})
  end

  defp send_rpc_request(socket, request, state) do
    message_id = make_message_id(state)
    {packet, state} = Packet.encode(request, state, message_id)

    send_to_notifier(state, {:msg_id_seqno, message_id, state.msg_seqno})

    case :gen_tcp.send(socket, packet) do
      :ok ->
        {:ok, %{state|last_message_id: message_id}, message_id}
      {:error, reason} ->
        {:error, reason, state}
    end
  end

  defp make_message_id(state) do
    message_id = Math.make_message_id(state.server_time_offset)
    Math.check_message_id(state.last_message_id, message_id)
  end

  defp next_packet(socket) do
    :ok = :inet.setopts(socket, active: :once)
  end

  defp choose_server(state) do
    DC.choose(state.reconnect, state.dc, state.dc_options)
  end

  defp schedule_ack do
    Process.send_after(self, :ack_msg_ids, ack_timeout)
  end

  defp ack_timeout do
    config(:ack_timeout, 500)
  end

  defp config(key, default \\ nil) do
    Application.get_env(:mtproto, key, default)
  end
end
