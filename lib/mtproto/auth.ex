defmodule MTProto.Auth do
  alias TL.Str
  alias TL.Vec

  def req_pq(nonce \\ :crypto.strong_rand_bytes(16)) do
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

  def p_q_inner_data(pq, p, q, nonce, server_nonce, new_nonce \\ :crypto.strong_rand_bytes(32)) do
    <<0x83c95aec :: little-size(32),
      Str.encode(<<pq :: 64>>) :: binary,
      Str.encode(<<p :: 32>>) :: binary,
      Str.encode(<<q :: 32>>) :: binary,
      nonce :: binary-size(16),
      server_nonce :: binary-size(16),
      new_nonce :: binary-size(32)>>
  end

  def p_q_inner_data_sha1(p_q_inner_data) do
    :crypto.hash(:sha, p_q_inner_data)
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
    :crypto.mod_pow(data, e, n)
  end

  defp data_with_hash_and_padding_255(data, hash) do
    data_with_hash = <<hash :: binary-size(20), data :: binary>>
    padding = (255 - byte_size(data_with_hash))

    <<data_with_hash :: binary,
      :crypto.strong_rand_bytes(padding) :: binary>>
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
