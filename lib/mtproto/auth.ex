defmodule MTProto.Auth do
  alias TL.Str
  alias TL.Vec

  def req_pq do
    <<0x60469778 :: little-size(32),
      :crypto.strong_rand_bytes(16) :: binary>>
  end

  def res_pq(<<0x05162463 :: little-size(32), packet :: binary>>) do
    <<nonce :: binary-size(16),
      server_nonce :: binary-size(16),
      rest :: binary>> = packet

    {pg, rest} = Str.decode(rest)
    {server_public_key_fingerprints, rest} = Vec.decode_long(rest)

    <<pg_int :: big-unsigned-integer-size(64)>> = pg

    %{nonce: nonce, server_nonce: server_nonce,
      pg: pg, server_public_key_fingerprints: server_public_key_fingerprints}
  end
end
