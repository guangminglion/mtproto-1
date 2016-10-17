defmodule MTProto.DCTest do
  use ExUnit.Case
  alias MTProto.DC

  @dc_list [
    %TL.DcOption{id: 1, ip_address: "149.154.175.50",
                 ipv6: false, media_only: false, port: 443, tcpo_only: false},
    %TL.DcOption{id: 1, ip_address: "2001:0b28:f23d:f001:0000:0000:0000:000a",
                 ipv6: true, media_only: false, port: 443, tcpo_only: false},
    %TL.DcOption{id: 2, ip_address: "149.154.167.51",
                 ipv6: false, media_only: false, port: 443, tcpo_only: false},
    %TL.DcOption{id: 2, ip_address: "2001:067c:04e8:f002:0000:0000:0000:000a",
                 ipv6: true, media_only: false, port: 443, tcpo_only: false},
    %TL.DcOption{id: 3, ip_address: "149.154.175.100",
                 ipv6: false, media_only: false, port: 443, tcpo_only: false},
    %TL.DcOption{id: 3, ip_address: "2001:0b28:f23d:f003:0000:0000:0000:000a",
                 ipv6: true, media_only: false, port: 443, tcpo_only: false},
    %TL.DcOption{id: 4, ip_address: "149.154.167.91",
                 ipv6: false, media_only: false, port: 443, tcpo_only: false},
    %TL.DcOption{id: 4, ip_address: "2001:067c:04e8:f004:0000:0000:0000:000a",
                 ipv6: true, media_only: false, port: 443, tcpo_only: false},
    %TL.DcOption{id: 4, ip_address: "149.154.165.120",
                 ipv6: false, media_only: true, port: 443, tcpo_only: false},
    %TL.DcOption{id: 5, ip_address: "91.108.56.165",
                 ipv6: false, media_only: false, port: 443, tcpo_only: false},
    %TL.DcOption{id: 5, ip_address: "2001:0b28:f23f:f005:0000:0000:0000:000a",
                 ipv6: true, media_only: false, port: 443, tcpo_only: false}
  ]

  describe "#choose" do
    test "reconnect == {:dc, dc_id}" do
      assert {{149,154,175,50}, 443} == DC.choose({:dc, 1}, 42, @dc_list)
    end

    test "reconnect == {:dc, dc_id} when dc_id isn't in list" do
      assert {{149,154,167,50}, 443} == DC.choose({:dc, 42}, 42, @dc_list)
    end

    test "reconnect == :random" do
      assert {_, _} = DC.choose(:random, 42, @dc_list)
    end

    test "reconnect == nil or any" do
      assert {_, _} = DC.choose(nil, 4, @dc_list)
    end

    test "always return ipv4" do
      assert {{_, _, _, _}, _port} = DC.choose({:dc, 1}, 42, @dc_list)
      assert {{_, _, _, _}, _port} = DC.choose({:dc, 42}, 42, @dc_list)
      assert {{_, _, _, _}, _port} = DC.choose(:random, 42, @dc_list)
      assert {{_, _, _, _}, _port} = DC.choose(nil, 4, @dc_list)
    end
  end
end
