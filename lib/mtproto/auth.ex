defmodule MTProto.Auth do
  alias MTProto.{State, AuthParams}
  alias MTProto.{Crypto, Math, Packet}

  @type state :: %State{}

  def init(client, state) do
    # generate first nonce
    nonce = Crypto.make_nonce(16)

    # make req_pq#60469778
    req_pq = TL.MTProto.encode(%TL.MTProto.Req.Pq{nonce: nonce})

    # send req_pq
    send_bare_packet(client, req_pq)

    # create auth_params
    auth_params = %AuthParams{nonce: nonce}

    %State{state|auth_state: :req_pq, auth_params: auth_params}
  end

  @doc """
  ...
  """
  @spec handle(pid, state, binary) :: {:ok, state} | {:error, term, state}

  def handle(client, %State{auth_state: :req_pq} = state, packet) do
    # decode res_pq#05162463
    {:ok, res_pq} = TL.MTProto.decode(packet)
    <<pq_int :: big-unsigned-integer-size(64)>> = res_pq.pq
    [p, q] = Math.factorize(pq_int)

    # make new_nonce
    new_nonce = Crypto.make_nonce(32)

    # make p_q_inner_data#83c95aec
    p_q_inner_data = TL.MTProto.encode(%TL.MTProto.P.Q.Inner.Data{
      pq: res_pq.pq, p: <<p :: 32>>, q: <<q :: 32>>, nonce: res_pq.nonce,
      server_nonce: res_pq.server_nonce, new_nonce: new_nonce})

    [public_key_fingerprint|_] = res_pq.server_public_key_fingerprints

    encrypted_data = Crypto.p_q_inner_data_rsa(p_q_inner_data)

    # make req_dh_params#d712e4be
    req_dh_params = TL.MTProto.encode(%TL.MTProto.Req.DH.Params{
      nonce: res_pq.nonce, server_nonce: res_pq.server_nonce,
      p: <<p :: 32>>, q: <<q :: 32>>, public_key_fingerprint: public_key_fingerprint,
      encrypted_data: encrypted_data})

    send_bare_packet(client, req_dh_params)

    # update auth_params with new values
    auth_params =
      %{state.auth_params|server_nonce: res_pq.server_nonce,
                          new_nonce: new_nonce}

    {:ok, %State{state|auth_state: :req_dh_params, auth_params: auth_params}}
  end
  def handle(client, %State{auth_state: :req_dh_params} = state, packet) do
    # decode server_dh_params_fail#79cb045d or server_dh_params_ok#d0e8075c
    case TL.MTProto.decode(packet) do
      {:error, reason} ->
        {:error, reason, state}
      {:ok, %TL.MTProto.Server.DH.Params.Fail{}} ->
        {:error, :server_dh_params_fail, state}
      {:ok, %TL.MTProto.Server.DH.Params.Ok{encrypted_answer: encrypted_answer}} ->
        # auth params
        auth_params = state.auth_params

        # get tmp_aes_key, tmp_aes_iv and encoded server answer
        decoded_server_dh_params = Crypto.server_dh_params_decode(
          auth_params.new_nonce, auth_params.server_nonce,
          encrypted_answer)

        # decode server_dh_inner_data
        {:ok, server_dh_inner_data} = TL.MTProto.decode(
          decoded_server_dh_params.answer)

        # send server_time to make offset
        send(client, {:sync_server_time, server_dh_inner_data.server_time})

        # generate b and g_b numbers
        b = Math.make_b
        g_b = Math.make_g_b(server_dh_inner_data.g, b, server_dh_inner_data.dh_prime)

        # make auth_key, auth_key_hash
        auth_key = Math.make_auth_key(server_dh_inner_data.g_a, b,
          server_dh_inner_data.dh_prime)
        auth_key_hash = Crypto.auth_key_hash(auth_key)

        # make server_salt
        server_salt = Crypto.make_server_salt(auth_params.new_nonce, auth_params.server_nonce)

        # make nonce_hash1
        nonce_hash1 = Crypto.make_nonce_hash1(auth_params.new_nonce, auth_key)

        # decode client_dh_inner_data
        # TODO retry_id
        client_dh_inner_data = TL.MTProto.encode(%TL.MTProto.Client.DH.Inner.Data{
          nonce: auth_params.nonce, server_nonce: auth_params.server_nonce,
          retry_id: 0, g_b: g_b})

        # encrypt client_dh_inner_data
        encrypted_client_dh_inner_data = Crypto.client_dh_inner_data_encrypt(
          decoded_server_dh_params.tmp_aes_key, decoded_server_dh_params.tmp_aes_iv,
          client_dh_inner_data)

        # make set_client_dh_params
        set_client_dh_params = TL.MTProto.encode(%TL.MTProto.Set.Client.DH.Params{
          nonce: auth_params.nonce, server_nonce: auth_params.server_nonce,
          encrypted_data: encrypted_client_dh_inner_data})

        send_bare_packet(client, set_client_dh_params)

        # update auth_params
        auth_params = %{auth_params|nonce_hash1: nonce_hash1}

        {:ok, %State{state|auth_state: :dh_gen, auth_key: auth_key,
                           auth_key_hash: auth_key_hash, server_salt: server_salt,
                           auth_params: auth_params}}
    end
  end
  def handle(client, %State{auth_state: :dh_gen} = state, packet) do
    case TL.MTProto.decode(packet) do
      {:error, reason} ->
        {:error, reason, state}
      {:ok, %TL.MTProto.Dh.Gen.Fail{}} ->
        {:error, :dh_gen_fail, state}
      {:ok, %TL.MTProto.Dh.Gen.Retry{}} ->
        {:error, :dh_gen_retry, state}
      {:ok, %TL.MTProto.Dh.Gen.Ok{} = dh_gen} ->
        # check nonce_hash1
        if state.auth_params.nonce_hash1 == dh_gen.new_nonce_hash1 do
          send(client, :authorized)
          {:ok, %State{state|auth_state: :encrypted, auth_params: nil}}
        else
          {:error, :mismatched_nonce_hash1, state}
        end
    end
  end

  ###

  def send_bare_packet(client, packet) do
    send(client, {:send_bare, Packet.encode_bare(packet, Math.make_message_id_time())})
  end
end
