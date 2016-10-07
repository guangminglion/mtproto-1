defmodule MTProto.Conn do
  use Connection

  alias MTProto.Auth

  def start_link(host) do
    Connection.start_link(__MODULE__, {host}, name: __MODULE__)
  end

  def send(packet) do
    Connection.call(__MODULE__, {:send, packet})
  end

  # ...

  def init({host}) do
    {:connect, :init, %{host: host, port: 443, socket: nil, session_id: nil, auth_state: nil}}
  end

  def connect(_, %{socket: nil, host: host, port: port} = state) do
    IO.puts(" -- connect #{host}:#{port}")
    case :gen_tcp.connect(host, port, [:binary, active: false], 5000) do
      {:ok, socket} ->
        send(self, :after_connect)
        session_id = :crypto.strong_rand_bytes(64)
        {:ok, %{state | socket: socket, session_id: session_id, auth_state: :connected}}
      {:error, _} ->
        {:backoff, 1000, state}
    end
  end

  def disconnect(info, %{socket: socket} = state) do
    :ok = :gen_tcp.close(socket)
    :error_logger.format("Connection error: ~p~n", [info])
    {:connect, :reconnect, %{state | socket: nil}}
  end

  def handle_call(_, _, %{socket: nil} = state) do
    {:reply, {:error, :closed}, state}
  end
  def handle_call({:send, packet}, _, %{socket: socket} = state) do
    case :gen_tcp.send(socket, packet) do
      :ok ->
        {:reply, :ok, state}
      {:error, _} = error ->
        {:disconnect, error, error, state}
    end
  end
  def handle_call(:close, from, s) do
    {:disconnect, {:close, from}, s}
  end

  def handle_info(:after_connect, %{socket: socket} = state) do
    encrypted = false
    # first packet
    :ok = :gen_tcp.send(socket, <<0xeeeeeeee :: 32>>)
    # :ok = :gen_tcp.send(socket, <<0xef :: 8>>)
    # set opts
    # :ok = :inet.setopts(socket, active: :once, packet: 4)
    :ok = :inet.setopts(socket, active: true)

    # make auth
    packet = encode_packet(Auth.req_pq(), state)
    IO.puts " --- tl_req_pq (#{byte_size packet}): #{inspect packet}"
    :ok = :gen_tcp.send(socket, packet)

    # %TL.InitConnection{}
    # config = %TL.Help.GetConfig{}
    # packet = TL.encode(
    #   %TL.InitConnection{api_id: 60834, device_model: "elixir", system_version: "0.1",
    #                      app_version: "0.1", lang_code: "en", query: config})
    #
    # IO.puts " -- first packet #{inspect packet}"
    #
    # :gen_tcp.send(socket, packet)

    {:noreply, %{state|auth_state: :req_pq}}
  end
  def handle_info({:tcp_closed, socket}, state) do
    {:stop, :tcp_closed, state}
  end
  def handle_info({:tcp, socket, packet}, state) do
    IO.puts " |-| packet: #{inspect packet}"
    decoded = decode_packet(packet)

    # IO.puts " -- packet:"
    # IO.inspect packet
    # IO.puts " -- packet decoded #{inspect decode_packet(packet)}"

    IO.puts " --- decoded packet: #{inspect decoded}"

    case state.auth_state do
      :req_pq ->
        res_pq = Auth.res_pq(decoded)
        [p, q] = Auth.factorize(res_pq.pq)

        p_q_inner_data = Auth.p_q_inner_data(res_pq.pq, p, q, res_pq.nonce, res_pq.server_nonce)

        [public_key_fingerprint|_] = res_pq.server_public_key_fingerprints

        encrypted_data = Auth.p_q_inner_data_rsa(p_q_inner_data)

        req_dh_params = Auth.req_dh_params(res_pq.nonce, res_pq.server_nonce, p, q,
          public_key_fingerprint, encrypted_data)
        req_dh_params_packet = encode_packet(req_dh_params, state)

        :gen_tcp.send(socket, req_dh_params_packet)

        {:noreply, %{state|auth_state: {:req_dh_params}}}
      {:req_dh_params} ->
        IO.inspect " ------ REQ_DH_PARAMS"
        # ...
        {:noreply, state}
      _ ->
        {:noreply, state}
    end

    # {:noreply, state}
  end
  def handle_info(request, state) do
    IO.puts(" -- handle_info request #{inspect request}")
    {:noreply, state}
  end

  defp generate_message_id do
    :erlang.system_time(:nanosecond)
  end

  defp encode_packet(packet, %{session_id: session_id} = state) do
    # FIXME salt
    auth_key_id = 0
    message_counter = 0

    # packet_with_meta =
    #   <<session_id :: binary-size(64),
    #     generate_message_id :: little-size(64),
    #     message_counter :: little-size(32),
    #     salt :: little-size(64),
    #     byte_size(packet) :: little-size(32),
    #     packet :: binary>>
    packet_with_meta =
      <<auth_key_id :: 64,
        generate_message_id :: little-size(64),
        byte_size(packet) :: little-size(32),
        packet :: binary>>

    # IO.puts " -- size: #{byte_size(packet)}"

    <<byte_size(packet_with_meta) :: little-size(32),
      packet_with_meta :: binary>>
  end

  defp decode_packet(<<size :: little-size(32), packet_with_meta :: binary-size(size)>>) do
    case packet_with_meta do
      <<error_reason :: little-signed-integer-size(32)>> ->
        {:error, error_reason}
      <<auth_key_id :: 64, message_id :: little-size(64),
        packet_size :: little-size(32), packet :: binary-size(packet_size)>> ->
          packet
    end
  end
end
