defmodule MTProto.Packet do
  @moduledoc """
  Module for dealing with packets - encode, decode, ecnrypt, decrypt.
  """

  alias TL.{Utils, Serializer}
  alias MTProto.{Crypto, Math}

  # TODO
  @doc """
  """
  def encode(request, %{auth_state: :encrypted} = state) do
    message_id = Math.make_message_id()
    packet = Serializer.encode(request)
    msg_seqno = if need_ack?(request) do
      Math.bor1(state.msg_seqno)
    else
      state.msg_seqno
    end

    packet_with_meta =
      <<state.server_salt :: binary-size(8),
        state.session_id :: binary-size(8),
        message_id :: little-size(64),
        msg_seqno :: little-size(32),
        byte_size(packet) :: little-size(32),
        packet :: binary>>

    packet_with_meta = Utils.padding(16, packet_with_meta)

    encrypted_packet = Crypto.encrypt_packet(packet_with_meta,
      state.auth_key, state.auth_key_hash)

    packet = encode_packet_size(encrypted_packet)

    {packet, %{state|msg_seqno: state.msg_seqno + 2,
                     msg_ids: [message_id | state.msg_ids]}}
  end

  @doc """
  Encodes packet as "bare", without encryption and empty auth_key,
  used for authorizaion only.
  """
  @spec encode_bare(binary, non_neg_integer) :: binary
  def encode_bare(packet, message_id) do
    auth_key_id = 0

    packet_with_meta =
      <<auth_key_id :: little-size(64),
        message_id :: little-size(64),
        byte_size(packet) :: little-size(32),
        packet :: binary>>

    encode_packet_size(packet_with_meta)
  end


  def encode_packet_size(packet) do
    size = trunc(Float.ceil(byte_size(packet) / 4))

    if size < 127 do
      <<size :: 8, packet :: binary>>
    else
      <<0x7f, size :: little-size(24), packet :: binary>>
    end
  end

  @doc """
  Tries to extract packet by it size, returns :more when packet is incomplete, otherwise :ok
  """
  @spec decode(binary) :: {:more, pos_integer, binary} :: {:ok, binary, binary}
  def decode(<<0x7f, size :: little-size(24), packet :: binary>> = packet_with_size) when byte_size(packet) < size * 4 do
    {:more, size * 4, packet_with_size}
  end
  def decode(<<0x7f, size :: little-size(24), rest :: binary>>) do
    size = size * 4
    <<packet :: binary-size(size), rest :: binary>> = rest
    {:ok, packet, rest}
  end
  def decode(<<size :: 8, packet :: binary>> = packet_with_size) when byte_size(packet) < size * 4 do
    {:more, size * 4, packet_with_size}
  end
  def decode(<<size :: 8, rest :: binary>>) do
    size = size * 4
    <<packet :: binary-size(size), rest :: binary>> = rest
    {:ok, packet, rest}
  end

  def decode_packet(<<error_reason :: little-signed-integer-size(32)>>, _state) do
    {:error, error_reason}
  end
  def decode_packet(packet_with_meta, %{auth_state: :encrypted} = state) do
    decrypted_packet = Crypto.decrypt_packet(packet_with_meta,
      state.auth_key)

    <<_server_salt :: binary-size(8),
      _session_id :: binary-size(8),
      message_id :: little-size(64),
      msg_seqno :: little-size(32),
      packet_size :: little-size(32),
      packet :: binary-size(packet_size),
      _rest :: binary>> = decrypted_packet

    Serializer.decode(packet)
  end
  def decode_packet(<<_auth_key_id :: 64, _message_id :: little-size(64),
                      packet_size :: little-size(32), packet :: binary-size(packet_size)>>, _state) do
    {:ok, packet}
  end

  def need_ack?(%TL.MTProto.Ping{}), do: false
  def need_ack?(%TL.MTProto.Msgs.Ack{}), do: false
  def need_ack?(_), do: true
end
