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
      pg: pg_int, server_public_key_fingerprints: server_public_key_fingerprints}
  end

  def factorize(n) do
    pollard(n)
  end

  defp gcd(a,0), do: abs(a)
  defp gcd(a,b), do: gcd(b, rem(a,b))

  defp pollard(n) do
    pollard(n, :random.uniform(n-2), 1, 0, 2, 1)
  end
  defp pollard(n, x, y, i, stage, factor) when factor != 1 do
    [factor, div(n, factor)]
  end
  defp pollard(n, x, y, i, stage, factor) do
    if i == stage do
      y = x
      stage = stage*2
    end
    x = rem((x*x - 1), n)
    i = i + 1
    factor = gcd(n, abs(x-y))
    pollard(n, x, y, i, stage, factor)
  end
end
