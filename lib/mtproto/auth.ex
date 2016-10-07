defmodule MTProto.Auth do
  alias TL.Str
  alias TL.Vec

  def make_nonce(size \\ 16) do
    :crypto.strong_rand_bytes(size)
  end

  def req_pq(nonce) do
    <<0x60469778 :: little-size(32),
      nonce :: binary-size(16)>>
  end

  def res_pq(<<0x05162463 :: little-size(32), packet :: binary>>) do
    <<nonce :: binary-size(16),
      server_nonce :: binary-size(16),
      rest :: binary>> = packet

    {<<pq_int :: big-unsigned-integer-size(64)>>, rest} = Str.decode(rest)
    {server_public_key_fingerprints, rest} = Vec.decode_long(rest)

    %{nonce: nonce, server_nonce: server_nonce, pq: pq_int,
      server_public_key_fingerprints: server_public_key_fingerprints}
  end

  def factorize(n) do
    Enum.sort(pollard(n))
  end

  def p_q_inner_data(pq, p, q, nonce, server_nonce, new_nonce) do
    <<0x83c95aec :: little-size(32),
      Str.encode(<<pq :: 64>>) :: binary,
      Str.encode(<<p :: 32>>) :: binary,
      Str.encode(<<q :: 32>>) :: binary,
      nonce :: binary-size(16),
      server_nonce :: binary-size(16),
      new_nonce :: binary-size(32)>>
  end

  def p_q_inner_data_sha1(p_q_inner_data) do
    sha1(p_q_inner_data)
  end

  def p_q_inner_data_rsa(p_q_inner_data) do
    hash = p_q_inner_data_sha1(p_q_inner_data)
    data = data_with_hash_and_padding_255(p_q_inner_data, hash)

    rsa_encrypt(data, server_public_key())
  end

  def req_dh_params(nonce, server_nonce, p, q, public_key_fingerprint, encrypted_data) do
    <<0xd712e4be :: little-size(32),
      nonce :: binary-size(16),
      server_nonce :: binary-size(16),
      Str.encode(<<p :: 32>>) :: binary,
      Str.encode(<<q :: 32>>) :: binary,
      public_key_fingerprint :: little-integer-size(64),
      Str.encode(encrypted_data) :: binary>>
  end

  # server_DH_params_fail
  def server_dh_params(<<0x79cb045d :: little-size(32), packet :: binary>>) do
    <<nonce :: binary-size(16),
      server_nonce :: binary-size(16),
      new_nonce_hash :: binary-size(16)>> = packet

    %{status: :fail, nonce: nonce, server_nonce: server_nonce,
      new_nonce_hash: new_nonce_hash}
  end
  # server_DH_params_ok
  def server_dh_params(<<0xd0e8075c :: little-size(32), packet :: binary>>) do
    <<nonce :: binary-size(16),
      server_nonce :: binary-size(16),
      encrypted_answer_str :: binary>> = packet

    {encrypted_answer, _rest} = Str.decode(encrypted_answer_str)

    %{status: :ok, nonce: nonce, server_nonce: server_nonce,
      encrypted_answer: encrypted_answer}
  end

  def server_dh_params_decode(new_nonce, server_nonce, encrypted_answer) do
    tmp_aes_key = make_tmp_aes_key(new_nonce, server_nonce)
    tmp_aes_iv = make_tmp_aes_iv(new_nonce, server_nonce)
    answer = decrypt_answer(tmp_aes_key, tmp_aes_iv, encrypted_answer)

    %{tmp_aes_key: tmp_aes_key, tmp_aes_iv: tmp_aes_iv, answer: answer}
  end

  def server_dh_inner_data(<<0xb5890dba :: little-size(32), packet :: binary>>) do
    <<nonce :: binary-size(16),
      server_nonce :: binary-size(16),
      g :: little-integer-size(32),
      rest :: binary>> = packet

    {dh_prime, rest} = Str.decode(rest)
    {g_a, rest} = Str.decode(rest)

    <<server_time :: little-integer-size(32),
      padding :: binary>> = rest

    %{nonce: nonce, server_nonce: server_nonce,
      g: g, dh_prime: dh_prime, g_a: g_a,
      server_time: server_time, _padding: padding}
  end

  def make_b do
    :crypto.strong_rand_bytes(2048)
  end

  def make_g_b(g, b, dh_prime) do
    mod_pow(g, b, dh_prime)
  end

  def client_dh_inner_data(nonce, server_nonce, retry_id, g_b) do
    <<0x6643b654 :: little-size(32),
      nonce :: binary-size(16),
      server_nonce :: binary-size(16),
      retry_id :: little-integer-size(64),
      Str.encode(g_b) :: binary>>
  end

  def client_dh_inner_data_encrypt(tmp_aes_key, tmp_aes_iv, data) do
    data_with_hash = TL.Utils.padding(16, <<sha1(data) :: binary, data :: binary>>)

    encrypt_aes_ige256(tmp_aes_key, tmp_aes_iv, data_with_hash)
  end

  def set_client_dh_params(nonce, server_nonce, encrypted_client_dh_inner_data) do
    <<0xf5045f1f :: little-size(32),
      nonce :: binary-size(16),
      server_nonce :: binary-size(16),
      Str.encode(encrypted_client_dh_inner_data) :: binary>>
  end

  ### Pollard implementation

  defp gcd(a,0), do: abs(a)
  defp gcd(a,b), do: gcd(b, rem(a,b))

  defp pollard(n) do
    pollard(n, :rand.uniform(n - 2), 1, 0, 2, 1)
  end
  defp pollard(n, x, y, i, stage, factor) when factor != 1 do
    [factor, div(n, factor)]
  end
  defp pollard(n, x, y, i, stage, factor) do
    {y, stage} =
      if i == stage do
        {x, stage * 2}
      else
        {y, stage}
      end
    x = rem((x*x - 1), n)
    i = i + 1
    factor = gcd(n, abs(x - y))
    pollard(n, x, y, i, stage, factor)
  end

  ### internal functions

  defp rsa_encrypt(data, {:RSAPublicKey, n, e} = key) do
    mod_pow(data, e, n)
  end

  defp mod_pow(a, b, c) do
    :crypto.mod_pow(a, b, c)
  end

  defp data_with_hash_and_padding_255(data, hash) do
    data_with_hash = <<hash :: binary-size(20), data :: binary>>
    padding = (255 - byte_size(data_with_hash))

    <<data_with_hash :: binary,
      :crypto.strong_rand_bytes(padding) :: binary>>
  end

  defp sha1(data) do
    :crypto.hash(:sha, data)
  end

  # tmp_aes_key := SHA1(new_nonce + server_nonce) + substr(SHA1(server_nonce + new_nonce), 0, 12);
  defp make_tmp_aes_key(new_nonce, server_nonce) do
    a = sha1(<<new_nonce :: binary, server_nonce :: binary>>)
    b = :binary.part(sha1(<<server_nonce :: binary, new_nonce :: binary>>), 0, 12)

    <<a :: binary, b :: binary>>
  end

  # tmp_aes_iv := substr(SHA1(server_nonce + new_nonce), 12, 8) +
  #               SHA1(new_nonce + new_nonce) + substr(new_nonce, 0, 4);
  defp make_tmp_aes_iv(new_nonce, server_nonce) do
    a = :binary.part(sha1(<<server_nonce :: binary, new_nonce :: binary>>), 12, 8)
    b = sha1(<<new_nonce :: binary, new_nonce :: binary>>)
    c = :binary.part(new_nonce, 0, 4)

    <<a :: binary, b :: binary, c :: binary>>
  end

  defp decrypt_answer(tmp_aes_key, tmp_aes_iv, encrypted_answer) do
    answer_with_hash = decrypt_aes_ige256(tmp_aes_key, tmp_aes_iv, encrypted_answer)
    <<hash :: binary-size(20), answer_with_padding :: binary>> = answer_with_hash
    answer_with_padding
  end

  defp decrypt_aes_ige256(tmp_aes_key, tmp_aes_iv, encrypted) do
    :crypto.block_decrypt(:aes_ige256, tmp_aes_key, tmp_aes_iv, encrypted)
  end

  defp encrypt_aes_ige256(tmp_aes_key, tmp_aes_iv, plain) do
    :crypto.block_encrypt(:aes_ige256, tmp_aes_key, tmp_aes_iv, plain)
  end

  defp server_public_key do
    priv = :code.priv_dir(:mtproto)

    with {:ok, key} <- File.read("#{priv}/server_public.key"),
         [entry|_] <- :public_key.pem_decode(key),
         public_key <- :public_key.pem_entry_decode(entry)
    do
      public_key
    else
      {:error, reason} -> {:error, reason}
    end
  end
end
