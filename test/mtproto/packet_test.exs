defmodule MTProto.PacketTest do
  use ExUnit.Case

  alias MTProto.Math
  alias MTProto.Packet

  describe "#encode" do
    test "encodes without ack"
    test "encrypts packet with padding by 16 bytes"
  end

  describe "#encode_bare" do
    test "encodes zero auth_key"
    test "appends 1 byte size"
    test "appends 3 byte size after 0x7f"
  end

  describe "#encode_packet_size" do
    test "decodes size/4 in 1 byte when packet size less than 127" do
      assert <<16, rest :: binary-size(64)>>
           = Packet.encode_packet_size(:crypto.strong_rand_bytes(64))
    end

    test "decodes size/4 in 3 bytes after 0x7f when packet size more or equal than 127" do
      assert <<32, rest :: binary-size(127)>>
           = Packet.encode_packet_size(:crypto.strong_rand_bytes(127))
      assert <<64, rest :: binary-size(256)>>
           = Packet.encode_packet_size(:crypto.strong_rand_bytes(256))
    end

    test "rounds up decoded packet size when it's not divisible by 4" do
      assert <<32, rest :: binary>>
           = Packet.encode_packet_size(:crypto.strong_rand_bytes(125))
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
    test "returns error"
    test "decodes encrypted packet"
    test "decodes raw packet"
  end
end
