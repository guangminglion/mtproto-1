defmodule MTProto.PacketTest do
  use ExUnit.Case

  import MTProto.Factory

  alias MTProto.Packet

  describe "#encode" do
    setup do
      {:ok, state: build(:encrypted_state)}
    end

    test "encodes without ack", %{state: state} do
      {packet, _state} = Packet.encode(%TL.MTProto.Ping{ping_id: 1}, state, 42)

      expected_packet =
        <<18, 224, 228, 243, 169, 134, 100, 52, 190, 57, 31, 210, 46, 147, 133, 255, 5,
          243, 48, 238, 118, 120, 71, 120, 167, 172, 22, 70, 3, 223, 198, 1, 102, 200,
          48, 245, 36, 41, 199, 172, 117, 92, 154, 161, 140, 240, 250, 127, 184, 125,
          109, 47, 78, 247, 4, 109, 219, 137, 251, 30, 24, 139, 243, 20, 26, 240, 202,
          78, 57, 245, 106, 187, 222>>

      assert expected_packet == packet
    end

    test "updates state with msg_seqno and msg_ids", %{state: state} do
      {_packet, state} = Packet.encode(
        %TL.Updates{updates: [], users: [], chats: [], date: 0, seq: 0}, state, 42)

      assert 2 == state.msg_seqno
      assert [42] == state.msg_ids
    end

    test "updates state with msg_seqno", %{state: state} do
      {_packet, state} = Packet.encode(%TL.MTProto.Ping{ping_id: 1}, state, 42)

      assert 2 == state.msg_seqno
    end

    test "doesn't updates state with msg_ids when it's not need to ack", %{state: state} do
      {_packet, state} = Packet.encode(%TL.MTProto.Ping{ping_id: 1}, state, 42)

      refute [42] == state.msg_ids
    end
  end

  describe "#encode_bare" do
    test "encodes zero auth_key" do
      <<_ :: size(8),
        auth_key :: little-size(64),
        _rest :: binary>> = Packet.encode_bare(<<42>>, 0)

      assert 0 == auth_key
    end

    test "encodes message_id" do
      <<_ :: size(72),
        message_id :: little-size(64),
        _rest :: binary>> = Packet.encode_bare(<<42>>, 142)

      assert 142 == message_id
    end

    test "encodes packet with size" do
      <<_ :: size(136),
        size :: little-size(32),
        packet :: binary>> = Packet.encode_bare(<<42>>, 142)

      assert 1 == size
      assert <<42>> == packet
    end
  end

  describe "#encode_packet_size" do
    test "decodes size/4 in 1 byte when packet size less than 127" do
      assert <<16, _rest :: binary-size(64)>>
           = Packet.encode_packet_size(:crypto.strong_rand_bytes(64))
    end

    test "decodes size/4 in 3 bytes after 0x7f when packet size more or equal than 127" do
      assert <<32, _rest :: binary-size(127)>>
           = Packet.encode_packet_size(:crypto.strong_rand_bytes(127))
      assert <<64, _rest :: binary-size(256)>>
           = Packet.encode_packet_size(:crypto.strong_rand_bytes(256))
    end

    test "rounds up decoded packet size when it's not divisible by 4" do
      assert <<32, _rest :: binary>>
           = Packet.encode_packet_size(:crypto.strong_rand_bytes(125))
    end

    test "appends 0x7f and encodes size in 3 bytes when it big" do
      assert <<0x7f, 512 :: little-size(24), _rest :: binary>>
          = Packet.encode_packet_size(:crypto.strong_rand_bytes(2048))
    end
  end

  describe "#decode" do
    test "0x7f returns more when packet is incomplete" do
      assert {:more, _, <<0x7f,1,0,0>>}
           = Packet.decode(<<0x7f,1,0,0>>)
      assert {:more, _, <<0x7f,2,0,0,1>>}
           = Packet.decode(<<0x7f,2,0,0,1>>)
      assert {:more, _, <<0x7f,3,0,0,1,2>>}
           = Packet.decode(<<0x7f,3,0,0,1,2>>)
    end

    test "0x7f returns the number of missing bytes when packet is incomplete" do
      assert {:more, 12, <<0x7f,3,0,0,0>>}
          == Packet.decode(<<0x7f,3,0,0,0>>)
      assert {:more, 200, <<0x7f,50,0,0,0,1,1,1,1,1,1,1,1>>}
          == Packet.decode(<<0x7f,50,0,0,0,1,1,1,1,1,1,1,1>>)
    end

    test "0x7f returns packet without size when it's complete" do
      assert {:ok, <<1,2,3,4>>, <<>>}
          == Packet.decode(<<0x7f,1,0,0,1,2,3,4>>)
      assert {:ok, <<1,2,3,4,5,6,7,8>>, <<>>}
          == Packet.decode(<<0x7f,2,0,0,1,2,3,4,5,6,7,8>>)
      assert {:ok, <<1,2,3,4,5,6,7,8>>, <<9,10>>}
          == Packet.decode(<<0x7f,2,0,0,1,2,3,4,5,6,7,8,9,10>>)
    end

    test "returns more when packet is incomplete" do
      assert {:more, _, <<1,0,0>>}
           = Packet.decode(<<1,0,0>>)
      assert {:more, _, <<2,0,0,1>>}
           = Packet.decode(<<2,0,0,1>>)
      assert {:more, _, <<3,0,0,1,2>>}
           = Packet.decode(<<3,0,0,1,2>>)
    end

    test "returns the number of missing bytes when packet is incomplete" do
      assert {:more, 12, <<3,0,0,0>>}
          == Packet.decode(<<3,0,0,0>>)
      assert {:more, 200, <<50,0,0,0,1,1,1,1,1,1,1,1>>}
          == Packet.decode(<<50,0,0,0,1,1,1,1,1,1,1,1>>)
    end

    test "returns packet without size when it's complete" do
      assert {:ok, <<1,2,3,4>>, <<>>}
          == Packet.decode(<<1,1,2,3,4>>)
      assert {:ok, <<1,2,3,4,5,6,7,8>>, <<>>}
          == Packet.decode(<<2,1,2,3,4,5,6,7,8>>)
      assert {:ok, <<1,2,3,4,5,6,7,8>>, <<9,10>>}
          == Packet.decode(<<2,1,2,3,4,5,6,7,8,9,10>>)
    end

    test "how it works" do
      packet = <<2,1,2,3>>

      {:more, _, packet} = Packet.decode(packet)
      {:more, _, packet} = Packet.decode(<<packet :: binary, 4, 5, 6>>)
      {:ok, <<1, 2, 3, 4, 5, 6, 7, 8>>, <<9, 10>>} = Packet.decode(<<packet :: binary, 7, 8, 9, 10>>)
    end
  end

  describe "#decode_packet" do
    setup do
      {:ok, state: build(:encrypted_state)}
    end

    test "returns error", %{state: state} do
      assert {:error, -400} == Packet.decode_packet(<<112, 254, 255, 255>>, state)
    end

    test "decodes encrypted packet", %{state: state} do
      packet =
        <<224, 228, 243, 169, 134, 100, 52, 190, 179, 21, 141, 143, 80, 14, 6, 23, 108,
          127, 159, 172, 39, 216, 64, 188, 217, 19, 77, 213, 239, 10, 99, 209, 196, 185,
          110, 78, 70, 6, 54, 222, 117, 67, 250, 130, 241, 230, 26, 139, 135, 191, 7,
          98, 41, 5, 177, 192, 81, 220, 33, 27, 108, 35, 178, 163, 205, 40, 107, 134,
          159, 110, 165, 95, 135, 165, 210, 194, 88, 52, 186, 207, 151, 14, 72, 180, 78,
          22, 239, 61>>

      expected_struct =
        %TL.UpdateShort{
          date: 1476183058,
          update: %TL.UpdateUserStatus{
            status: %TL.UserStatusOffline{was_online: 1476183058},
            user_id: 30193135}}

      assert {:ok, ^expected_struct, _} = Packet.decode_packet(packet, state)
    end

    test "returns state with msg_ids_to_ack in state if (seq_no & 1) == 1", %{state: state} do
      packet =
        <<224, 228, 243, 169, 134, 100, 52, 190, 179, 21, 141, 143, 80, 14, 6, 23, 108,
          127, 159, 172, 39, 216, 64, 188, 217, 19, 77, 213, 239, 10, 99, 209, 196, 185,
          110, 78, 70, 6, 54, 222, 117, 67, 250, 130, 241, 230, 26, 139, 135, 191, 7,
          98, 41, 5, 177, 192, 81, 220, 33, 27, 108, 35, 178, 163, 205, 40, 107, 134,
          159, 110, 165, 95, 135, 165, 210, 194, 88, 52, 186, 207, 151, 14, 72, 180, 78,
          22, 239, 61>>
      {:ok, _, new_state} = Packet.decode_packet(packet, state)

      assert [6340157961025832961] == new_state.msg_ids_to_ack
    end

    test "returns old state if (seq_no & 1) != 1", %{state: state} do
      packet =
        <<224, 228, 243, 169, 134, 100, 52, 190, 179, 21, 141, 143, 80, 14, 6, 23, 108,
          127, 159, 172, 39, 216, 64, 188, 217, 19, 77, 213, 239, 10, 99, 209, 196, 185,
          110, 78, 70, 6, 54, 222, 117, 67, 250, 130, 241, 230, 26, 139, 135, 191, 7,
          98, 41, 5, 177, 192, 81, 220, 33, 27, 108, 35, 178, 163, 205, 40, 107, 134,
          159, 110, 165, 95, 135, 165, 210, 194, 88, 52, 186, 207, 151, 14, 72, 180, 78,
          22, 239, 61>>
      {:ok, _, new_state} = Packet.decode_packet(packet, state)

      assert [6340157961025832961] == new_state.msg_ids_to_ack
    end

    test "decodes raw packet" do
      state = build(:state)
      packet =
        <<0, 0, 0, 0, 0, 0, 0, 0, 1, 12, 216, 150, 39, 66, 7, 88, 52, 0, 0, 0, 52, 247,
          203, 59, 152, 88, 230, 65, 73, 43, 0, 57, 239, 158, 106, 248, 52, 234, 33,
          181, 57, 206, 195, 249, 216, 124, 149, 31, 131, 162, 14, 203, 22, 4, 124, 193,
          23, 27, 237, 164, 89, 232, 158, 129, 140, 174, 191, 170, 201, 190, 241, 78>>
      expected_packet =
        <<52, 247, 203, 59, 152, 88, 230, 65, 73, 43, 0, 57, 239, 158, 106, 248, 52, 234, 33,
          181, 57, 206, 195, 249, 216, 124, 149, 31, 131, 162, 14, 203, 22, 4, 124, 193,
          23, 27, 237, 164, 89, 232, 158, 129, 140, 174, 191, 170, 201, 190, 241, 78>>

      assert {:ok, expected_packet, state} == Packet.decode_packet(packet, state)
    end
  end
end
