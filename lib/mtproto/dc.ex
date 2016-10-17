defmodule MTProto.DC do
  @moduledoc """
  Helpers to dealing with Telegram Data Centers
  """

  @type dc_id :: binary
  @type dc_list :: [%TL.DcOption{}]
  @type reconnect :: {:dc, dc_id} | :random | nil
  @type dc_address :: {:inet.ip4_address, :inet.port_number}

  @doc """
  Function to choose server depend on `reconnect` client state, current DC id and DC list.

  * reconnect == {:dc, dc_id} - client should connect to specific DC.
  * reconnect == :random - means that client should randomly choose server from DC list;
  * reconnect == _any - means that it's first client connection or accidental error, use default address;
  """
  @spec choose(reconnect, dc_id, dc_list) :: dc_address
  def choose({:dc, dc_id}, _dc, dc_list) do
    dc_list
    |> find_dc_by_id(dc_id)
    |> parse_dc_address
  end
  def choose(:random = _reconnect, dc, dc_list) when length(dc_list) > 0 do
    dc_list
    |> filter_dcs_without_current(dc)
    |> random_dc
    |> parse_dc_address
  end
  def choose(_reconnect, _dc, _dc_list) do
    {telegram_host(), telegram_port()}
  end

  ### internal functions

  defp find_dc_by_id(dc_list, need_dc_id) do
    Enum.find(dc_list, fn(dc) ->
      dc.id == need_dc_id and dc.ipv6 == false
    end)
  end

  defp filter_dcs_without_current(dc_list, current_dc_id) do
    Enum.filter(dc_list, fn(dc) ->
      dc.id != current_dc_id and dc.ipv6 == false
    end)
  end

  defp random_dc([]) do
    default_dc()
  end
  defp random_dc(dc_list) do
    Enum.random(dc_list)
  end

  defp parse_dc_address(nil) do
    default_dc()
  end
  defp parse_dc_address(dc) do
    address = String.to_charlist(dc.ip_address)

    case :inet.parse_address(address) do
      {:ok, ip} -> {ip, dc.port}
      {:error, _} -> {telegram_host(), telegram_port()}
    end
  end

  defp default_dc do
    {telegram_host(), telegram_port()}
  end

  defp telegram_host do
    Application.get_env(:mtproto, :host, {149,154,167,50})
  end

  defp telegram_port do
    Application.get_env(:mtproto, :port, 443)
  end
end
