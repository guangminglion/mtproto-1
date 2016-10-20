defmodule MTProto.Crypto do
  alias MTProto.Math

  def encrypt_packet(packet, auth_key, auth_key_hash) do
    msg_key = substr(sha1(packet), 4, 16)
    {aes_key, aes_iv} = generate_aes(msg_key, auth_key, :encode)
    encrypted_data = encrypt_aes_ige256(aes_key, aes_iv, packet)

    <<auth_key_hash :: binary-size(8),
      msg_key :: binary-size(16),
      encrypted_data :: binary>>
  end

  def decrypt_packet(packet, auth_key) do
    <<_auth_key_hash :: binary-size(8),
      msg_key :: binary-size(16),
      encrypted_data :: binary>> = packet

    {aes_key, aes_iv} = generate_aes(msg_key, auth_key, :decode)
    decrypt_aes_ige256(aes_key, aes_iv, encrypted_data)
  end

  @doc """
  sha1_a = SHA1(msg_key + substr(auth_key, x, 32));
  sha1_b = SHA1(substr(auth_key, 32+x, 16) + msg_key + substr(auth_key, 48+x, 16));
  sha1_с = SHA1(substr(auth_key, 64+x, 32) + msg_key);
  sha1_d = SHA1(msg_key + substr(auth_key, 96+x, 32));
  aes_key = substr(sha1_a, 0, 8) + substr(sha1_b, 8, 12) + substr(sha1_c, 4, 12);
  aes_iv = substr(sha1_a, 8, 12) + substr(sha1_b, 0, 8) + substr(sha1_c, 16, 4) + substr(sha1_d, 0, 8);
  """
  def generate_aes(msg_key, auth_key, action) do
    x = action_value(action)

    sha1_a = sha1(merge([msg_key, substr(auth_key, x, 32)]))
    sha1_b = sha1(merge([substr(auth_key, 32 + x, 16), msg_key, substr(auth_key, 48 + x, 16)]))
    sha1_c = sha1(merge([substr(auth_key, 64 + x, 32), msg_key]))
    sha1_d = sha1(merge([msg_key, substr(auth_key, 96 + x, 32)]))

    aes_key = merge([substr(sha1_a, 0, 8), substr(sha1_b, 8, 12), substr(sha1_c, 4, 12)])
    aes_iv = merge([substr(sha1_a, 8, 12), substr(sha1_b, 0, 8), substr(sha1_c, 16, 4), substr(sha1_d, 0, 8)])

    {aes_key, aes_iv}
  end

  def make_session_id do
    :crypto.strong_rand_bytes(8)
  end

  def make_nonce(size \\ 16) do
    :crypto.strong_rand_bytes(size)
  end

  def p_q_inner_data_rsa(p_q_inner_data) do
    hash = sha1(p_q_inner_data)
    data = data_with_hash_and_padding_255(p_q_inner_data, hash)

    rsa_encrypt(data, server_public_key())
  end

  def server_dh_params_decode(new_nonce, server_nonce, encrypted_answer) do
    tmp_aes_key = make_tmp_aes_key(new_nonce, server_nonce)
    tmp_aes_iv = make_tmp_aes_iv(new_nonce, server_nonce)
    answer = decrypt_answer(tmp_aes_key, tmp_aes_iv, encrypted_answer)

    %{tmp_aes_key: tmp_aes_key, tmp_aes_iv: tmp_aes_iv, answer: answer}
  end

  def client_dh_inner_data_encrypt(tmp_aes_key, tmp_aes_iv, data) do
    data_with_hash = TL.Utils.padding(16, <<sha1(data) :: binary, data :: binary>>)

    encrypt_aes_ige256(tmp_aes_key, tmp_aes_iv, data_with_hash)
  end

  @doc """
  auth_key_hash is computed := 64 lower-order bits of SHA1(auth_key).

  The server checks whether there already is another key with the same
  `auth_key_hash` and responds in one of the following ways.
  """
  def auth_key_hash(auth_key) do
    substr(sha1(auth_key), 12, 8)
  end

  @doc """
  `new_nonce_hash1`, `new_nonce_hash2`, and `new_nonce_hash3` are obtained
  as the 128 lower-order bits of SHA1 of the byte string derived from the
  new_nonce string by adding a single byte with the value of 1, 2, or 3,
  and followed by another 8 bytes with auth_key_aux_hash.

  Different values are required to prevent an intruder from changing server
  response `dh_gen_ok` into `dh_gen_retry`.
  """
  def make_nonce_hash1(new_nonce, auth_key) do
    auth_key_hash = substr(sha1(auth_key), 0, 8)
    nonce =
      <<new_nonce :: binary-size(32), 1 :: size(8),
        auth_key_hash :: binary-size(8)>>

    substr(sha1(nonce), 4, 16)
  end

  @doc """
  server_salt := substr(new_nonce, 0, 8) XOR substr(server_nonce, 0, 8)

  https://core.telegram.org/mtproto/auth_key#dh-key-exchange-complete (9)
  """
  def make_server_salt(new_nonce, server_nonce) do
    Math.binary_bxor(substr(new_nonce, 0, 8), substr(server_nonce, 0, 8))
  end

  def sha1(data) do
    :crypto.hash(:sha, data)
  end

  def encrypt_aes_ige256(aes_key, aes_iv, plain) do
    :crypto.block_encrypt(:aes_ige256, aes_key, aes_iv, plain)
  end

  def decrypt_aes_ige256(aes_key, aes_iv, encrypted) do
    :crypto.block_decrypt(:aes_ige256, aes_key, aes_iv, encrypted)
  end

  ### internal functions

  defp action_value(:decode), do: 8
  defp action_value(:encode), do: 0

  defp substr(bin, start, length) do
    :binary.part(bin, start, length)
  end

  defp merge(binlist) do
    Enum.join(binlist)
  end

  defp rsa_encrypt(data, {:RSAPublicKey, n, e} = _key) do
    :crypto.mod_pow(data, e, n)
  end

  defp data_with_hash_and_padding_255(data, hash) do
    data_with_hash = <<hash :: binary-size(20), data :: binary>>
    padding = (255 - byte_size(data_with_hash))

    <<data_with_hash :: binary,
      :crypto.strong_rand_bytes(padding) :: binary>>
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
    <<_hash :: binary-size(20), answer_with_padding :: binary>> = answer_with_hash
    answer_with_padding
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
