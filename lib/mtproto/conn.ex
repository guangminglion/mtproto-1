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

  defmodule State do
    defstruct [:host, :port, :socket, :session_id,
               :auth_state, :auth_params,
               :auth_key, :auth_key_hash, :server_salt]
  end

  defmodule AuthParams do
    defstruct [:nonce, :server_nonce, :new_nonce, :nonce_hash1]
  end

  def init({host}) do
    {:connect, :init,
      %State{host: host, port: 443, socket: nil, session_id: nil, auth_state: nil}}
  end

  def connect(_, %{socket: nil, host: host, port: port} = state) do
    IO.puts(" -- connect #{host}:#{port}")
    case :gen_tcp.connect(host, port, [:binary, active: false], 5000) do
      {:ok, socket} ->
        send(self, :after_connect)
        session_id = :crypto.strong_rand_bytes(64)
        {:ok, %{state|socket: socket, session_id: session_id, auth_state: :connected}}
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
    # encrypted = false
    # first packet
    :ok = :gen_tcp.send(socket, <<0xeeeeeeee :: 32>>)

    # set opts
    :ok = :inet.setopts(socket, active: true)

    # generate first nonce
    nonce = Auth.make_nonce(16)

    # make req_pq#60469778
    req_pq = Auth.req_pq(nonce)

    # make auth
    :ok = :gen_tcp.send(socket, encode_packet(req_pq, state))

    # create auth_params
    auth_params = %AuthParams{nonce: nonce}

    {:noreply, %{state|auth_state: :req_pq, auth_params: auth_params}}
  end
  def handle_info({:tcp_closed, socket}, state) do
    {:stop, :tcp_closed, state}
  end
  def handle_info({:tcp, socket, packet}, state) do
    IO.puts " |-| packet: #{inspect packet}"
    decoded = decode_packet(packet)

    # IO.puts " --- decoded packet: #{inspect decoded}"

    case state.auth_state do
      :req_pq ->
        # decode res_pq#05162463
        res_pq = Auth.res_pq(decoded)
        [p, q] = Auth.factorize(res_pq.pq)

        # make new_nonce
        new_nonce = Auth.make_nonce(32)

        # make p_q_inner_data#83c95aec
        p_q_inner_data = Auth.p_q_inner_data(res_pq.pq, p, q,
          res_pq.nonce, res_pq.server_nonce, new_nonce)

        [public_key_fingerprint|_] = res_pq.server_public_key_fingerprints

        encrypted_data = Auth.p_q_inner_data_rsa(p_q_inner_data)

        # make req_dh_params#d712e4be
        req_dh_params = Auth.req_dh_params(res_pq.nonce, res_pq.server_nonce, p, q,
          public_key_fingerprint, encrypted_data)

        :gen_tcp.send(socket, encode_packet(req_dh_params, state))

        # update auth_params with new values
        auth_params =
          %{state.auth_params|server_nonce: res_pq.server_nonce,
                              new_nonce: new_nonce}

        {:noreply, %{state|auth_state: :req_dh_params, auth_params: auth_params}}
      :req_dh_params ->
        # decode server_dh_params_fail#79cb045d or server_dh_params_ok#d0e8075c
        case Auth.server_dh_params(decoded) do
          %{status: :fail} ->
            {:stop, :server_dh_params_fail, state}
          %{status: :ok, encrypted_answer: encrypted_answer} = server_dh_params ->
            # auth params
            auth_params = state.auth_params

            # get tmp_aes_key, tmp_aes_iv and encoded server answer
            decoded_server_dh_params = Auth.server_dh_params_decode(
              auth_params.new_nonce, auth_params.server_nonce, encrypted_answer)

            # decode server_dh_inner_data
            server_dh_inner_data = Auth.server_dh_inner_data(
              decoded_server_dh_params.answer)

            # generate b and g_b numbers
            b = Auth.make_b
            g_b = Auth.make_g_b(server_dh_inner_data.g, b, server_dh_inner_data.dh_prime)

            # make auth_key, auth_key_hash
            auth_key = Auth.make_auth_key(server_dh_inner_data.g_a, b,
              server_dh_inner_data.dh_prime)
            auth_key_hash = Auth.auth_key_hash(auth_key)

            # make server_salt
            server_salt = Auth.make_server_salt(auth_params.new_nonce, auth_params.server_nonce)

            # make nonce_hash1
            nonce_hash1 = Auth.make_nonce_hash1(auth_params.new_nonce, auth_key)

            # decode client_dh_inner_data
            client_dh_inner_data = Auth.client_dh_inner_data(auth_params.nonce,
              auth_params.server_nonce, 0, g_b)

            # encrypt client_dh_inner_data
            encrypted_client_dh_inner_data = Auth.client_dh_inner_data_encrypt(
              decoded_server_dh_params.tmp_aes_key, decoded_server_dh_params.tmp_aes_iv,
              client_dh_inner_data)

            # make set_client_dh_params
            set_client_dh_params = Auth.set_client_dh_params(auth_params.nonce,
              auth_params.server_nonce, encrypted_client_dh_inner_data)

            # send it to the server
            :gen_tcp.send(socket, encode_packet(set_client_dh_params, state))

            # update auth_params
            auth_params = %{auth_params|nonce_hash1: nonce_hash1}

            {:noreply, %{state|auth_state: :dh_gen, auth_key: auth_key,
                               auth_key_hash: auth_key_hash, server_salt: server_salt,
                               auth_params: auth_params}}
        end
      :dh_gen ->
        # decode dh_gen_ok, dh_gen_fail, dh_gen_retry
        case Auth.dh_gen(decoded) do
          %{status: :fail} ->
            {:stop, :dh_gen_fail, state}
          %{status: :retry} ->
            {:stop, :dh_gen_retry, state}
          %{status: :ok} = dh_gen ->
            # check nonce_hash1
            if state.auth_params.nonce_hash1 == dh_gen.new_nonce_hash1 do
              IO.puts " -- authenticated"
              IO.puts " --- auth_key      #{inspect state.auth_key}"
              IO.puts " --- auth_key_hash #{inspect state.auth_key_hash}"
              IO.puts " --- server_salt   #{inspect state.server_salt}"

              {:noreply, %{state|auth_state: :ok, auth_params: nil}}
            else
              {:stop, :mismatched_nonce_hash1, state}
            end
        end
      _ ->
        {:noreply, state}
    end
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
