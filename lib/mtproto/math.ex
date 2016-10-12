defmodule MTProto.Math do
  import Bitwise

  def factorize(n) do
    Enum.sort(pollard(n))
  end

  def make_b do
    :crypto.strong_rand_bytes(2048)
  end

  def make_g_b(g, b, dh_prime) do
    mod_pow(g, b, dh_prime)
  end

  def make_auth_key(g_a, b, dh_prime) do
    mod_pow(g_a, b, dh_prime)
  end

  def make_message_id_time do
    :erlang.system_time(:nanosecond)
  end

  def make_message_id do
    time = :erlang.system_time(:nanosecond)
    nano = 1000*1000*1000
    bor(round(time / nano) <<< 32, band(rem(time, nano), -4))
  end

  def binary_bxor(bin1, bin2) do
    size1 = bit_size(bin1)
    size2 = bit_size(bin2)

    <<int1 :: size(size1)>> = bin1
    <<int2 :: size(size2)>> = bin2

    int3 = bxor(int1, int2)
    size3 = max(size1, size2)

    <<int3 :: size(size3)>>
  end

  def bor1(number) do
    bor(number, 1)
  end

  ### Pollard implementation

  defp gcd(a,0), do: abs(a)
  defp gcd(a,b), do: gcd(b, rem(a,b))

  defp pollard(n) do
    pollard(n, :rand.uniform(n - 2), 1, 0, 2, 1)
  end
  defp pollard(n, _x, _y, _i, _stage, factor) when factor != 1 do
    [factor, div(n, factor)]
  end
  defp pollard(n, x, y, i, stage, _factor) do
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

  defp mod_pow(a, b, c) do
    :crypto.mod_pow(a, b, c)
  end
end
