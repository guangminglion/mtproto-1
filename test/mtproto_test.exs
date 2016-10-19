defmodule MTProtoTest do
  use ExUnit.Case

  import Mock
  import MTProto.Factory

  alias MTProto.{Auth, Crypto, DC, Math, Packet}

  require Logger

  setup_all do
    :meck.new(:inet, [:passthrough, :unstick])
    :meck.expect(:inet, :setopts, fn(_socket, _opts) -> :ok end)
    :meck.expect(:inet, :tcp_close, fn(_socket) -> :ok end)

    Logger.configure(level: :warn)
    :ok
  end

  describe "connection" do
    test "calls DC module to choose server" do
      with_mocks [tcp_mocks, dc_mocks] do
        start_client

        assert_receive {:tl, _}
        assert called DC.choose(nil, nil, nil)
      end
    end

    test "generates session_id" do
      with_mocks [tcp_mocks] do
        c = start_client

        assert state(c, :session_id)
      end
    end

    test "uses provided session_id" do
      with_mocks [tcp_mocks] do
        c = start_client(session_id: <<42>>)

        assert <<42>> == state(c, :session_id)
      end
    end

    test "receives {:connected, addr, ip}" do
      with_mocks [tcp_mocks] do
        start_client

        assert_receive {:tl, {:connected, {149,154,167,50}, 443}}
      end
    end

    test "sends first packet (0xef)" do
      with_mocks [tcp_mocks] do
        start_client

        assert_receive {:tcp, <<0xef>>}
      end
    end

    test "after success connecton state is :connected" do
      with_mocks [tcp_mocks] do
        c = start_client

        assert :connected == state(c, :auth_state)
      end
    end

    test "backoff started when server unreachable" do
      with_mocks [tcp_connect_fail_mocks] do
        c = start_client

        assert is_reference(conn_state(c).backoff)
      end
    end

    test "backoff is nil when server unreachable" do
      with_mocks [tcp_mocks] do
        c = start_client

        refute conn_state(c).backoff
      end
    end
  end

  # test "turtles all the way down" do

  describe "authorization" do
    test "saves auth_key, auth_key_hash and server_salt after successfull auth" do
      ak = File.read!("test/support/auth.key")
      akh = Crypto.auth_key_hash(ak)
      ss = <<229, 75, 20, 16, 208, 160, 102, 243>>

      with_mocks [tcp_mocks, auth_mocks(ak, akh, ss)] do
        c = start_client
        MTProto.authorize(c)

        # to handle Auth.handle/3 after init/2
        request = %TL.MTProto.ResPQ{
          nonce: random_bytes(16), pq: random_bytes(8),
          server_nonce: random_bytes(16), server_public_key_fingerprints: [0]}
        send_as_server_bare(c, request)

        assert state(c, :auth_key)
        assert state(c, :auth_key_hash)
        assert state(c, :server_salt)
      end
    end

    test "proper handle auth errors" do
      with_mocks [tcp_mocks, auth_error_mocks(:dh_gen_fail)] do
        Process.flag(:trap_exit, true)
        c = start_client
        MTProto.authorize(c)

        # to handle Auth.handle/3 after init/2
        request = %TL.MTProto.ResPQ{
          nonce: random_bytes(16), pq: random_bytes(8),
          server_nonce: random_bytes(16), server_public_key_fingerprints: [0]}
        send_as_server_bare(c, request)

        assert_receive {:EXIT, _, {:error, :dh_gen_fail}}
      end
    end
  end

  describe "reconnection" do
    test "when server fails" do
      with_mocks [tcp_mocks] do
        c = start_authorized_client
        config = build(:config)

        assert_receive {:tl, {:connected, {149,154,167,50}, 443}}

        with_mocks [packet_decode_mocks] do
          send_as_server(c, config)
          assert_receive {:tl, {:config, :server_config, _}}
        end

        with_mocks [dc_mocks({149,154,42,42}, 443)] do
          send(c, {:tcp_closed, self})

          assert_receive {:tl, {:connected, {149,154,42,42}, 443}}
          assert called DC.choose(nil, 2, config.dc_options)
        end
      end
    end

    test "random" do
      with_mocks [tcp_mocks] do
        c = start_authorized_client
        config = build(:config)

        assert_receive {:tl, {:connected, {149,154,167,50}, 443}}

        with_mocks [packet_decode_mocks] do
          send_as_server(c, config)
          assert_receive {:tl, {:config, :server_config, _}}
        end

        with_mocks [dc_mocks({149,154,42,42}, 443)] do
          send(c, {:reconnect, :random})

          assert_receive {:tl, {:connected, {149,154,42,42}, 443}}
          assert called DC.choose(:random, 2, config.dc_options)
        end
      end
    end
  end

  describe "packet buffer" do
    test "accumulates packet when it's incomplete" do
      with_mocks [tcp_mocks] do
        c = start_client
        assert_receive {:tcp, <<0xef>>}

        send_as_server_raw(c, <<4,1,2,3,4>>)
        assert <<4,1,2,3,4>> == state(c, :packet_buffer)

        send_as_server_raw(c, <<5,6,7,8>>)
        assert <<4,1,2,3,4,5,6,7,8>> == state(c, :packet_buffer)
      end
    end

    test "decodes packet when it's complete" do
      with_mocks [tcp_mocks, packet_decode_packet_mocks({:error, :packet_decoded})] do
        Process.flag(:trap_exit, true)

        c = start_client
        assert_receive {:tcp, <<0xef>>}

        send_as_server_raw(c, <<4,1,2,3,4>>)
        assert <<4,1,2,3,4>> == state(c, :packet_buffer)

        send_as_server_raw(c, <<5,6,7,8>>)
        assert <<4,1,2,3,4,5,6,7,8>> == state(c, :packet_buffer)

        send_as_server_raw(c, <<0,0,0,0,0,0,0,0>>)
        assert_receive {:EXIT, _, {:error, :packet_decoded}}
      end
    end
  end

  describe "msg_seqno" do
    test "increments within session" do
      with_mocks [tcp_mocks] do
        c = start_authorized_client

        assert_receive {:tl, {:msg_seqno, 2}}
        assert_receive {:tl, {:msg_seqno, 4}}

        # send any packet to make client increment seqno
        send(c, {:reconnect, :random})

        assert_receive {:tl, {:msg_seqno, 6}}
      end
    end
  end

  describe "#notifier_process" do
    test "sets new notifier process" do
      with_mocks [tcp_mocks] do
        c = start_client

        :ok = MTProto.notifier_process(c, :test_pid)

        assert :test_pid == state(c, :notifier)
      end
    end
  end

  describe "#send_request" do
    test "sends request to the server" do
      with_mocks [tcp_mocks, packet_encode_mocks(<<42>>)] do
        c = start_client
        request = %TL.MTProto.Ping{ping_id: 1}

        :ok = MTProto.send_request(c, request)

        assert called Packet.encode(request, state(c))
        assert called :gen_tcp.send(self, <<42>>)
      end
    end

    test "error when sending request to the server fails" do
      c =
        with_mocks [tcp_mocks] do
          c = start_client
          assert_receive {:tl, {:connected, _, _}}
          assert_receive {:tcp, <<0xef>>}

          c
        end

      with_mocks [tcp_send_fail_mocks(:enoent), packet_encode_mocks(<<42>>)] do
        Process.flag(:trap_exit, true)
        catch_exit(MTProto.send_request(c, %TL.MTProto.Ping{ping_id: 1}))

        assert_receive {:tl, {:connected, _, _}}
      end
    end
  end

  describe "#close" do
    test "closes tcp connection" do
      Process.flag(:trap_exit, true)

      c = start_client
      catch_exit(MTProto.close(c))

      assert_receive {:EXIT, _, :normal}
    end
  end

  defp start_client(opts \\ []) do
    {:ok, client} = MTProto.start_link(Keyword.merge([notifier: self], opts))

    client
  end

  defp start_authorized_client(opts \\ []) do
    ak = File.read!("test/support/auth.key")
    akh = Crypto.auth_key_hash(ak)
    ss = <<229, 75, 20, 16, 208, 160, 102, 243>>

    client = start_client(opts)
    MTProto.authorize(client, ak, akh, ss)
    client
  end

  defp send_as_server_raw(client, binary) do
    send(client, {:tcp, self, binary})
  end

  defp send_as_server_bare(client, request) do
    packet = Packet.encode_bare(TL.MTProto.encode(request), Math.make_message_id_time())
    send(client, {:tcp, self, packet})
  end

  defp send_as_server(client, request) do
    # {packet, _} = Packet.encode(request, state(client))
    packet = TL.Serializer.encode(request)
    send(client, {:tcp, self, packet})
  end

  defp state(client) do
    :recon.get_state(client).mod_state
  end
  defp state(client, key) do
    Map.get(:recon.get_state(client).mod_state, key)
  end

  defp conn_state(client) do
    :recon.get_state(client)
  end

  defp random_bytes(size) do
    :crypto.strong_rand_bytes(size)
  end

  defp tcp_mocks(receiver \\ self) do
    {:gen_tcp, [:passthrough, :unstick],
      connect: fn(_host, _port, _opts, _timeout) -> {:ok, receiver} end,
      send: fn(_socket, packet) -> send(receiver, {:tcp, packet}); :ok end,
      close: fn(_socket) -> :ok end}
  end

  defp tcp_connect_fail_mocks do
    {:gen_tcp, [:passthrough, :unstick],
      connect: fn(_host, _port, _opts, _timeout) -> {:error, :reason} end,
      send: fn(socket, packet) -> send(socket, {:tcp, packet}); :ok end,
      close: fn(_socket) -> :ok end}
  end

  defp tcp_send_fail_mocks(reason) do
    {:gen_tcp, [:passthrough, :unstick],
      send: fn(_socket, _packet) -> {:error, reason} end,
      close: fn(_socket) -> :ok end}
  end

  defp packet_decode_mocks do
    {Packet, [:passthrough],
      decode: fn(packet) -> {:ok, packet, <<>>} end,
      decode_packet: fn(packet, _state) -> TL.Serializer.decode(packet) end}
  end

  defp packet_decode_packet_mocks(result) do
    {Packet, [:passthrough],
      decode_packet: fn(_packet, _state) -> result end}
  end

  defp packet_encode_mocks(result) do
    {Packet, [:passthrough],
      encode: fn(_request, state) -> {result, state} end}
  end

  defp dc_mocks(host \\ 'localhost', port \\ 439) do
    {DC, [], choose: fn(_, _, _) -> {host, port} end}
  end

  defp auth_mocks(ak, akh, ss) do
    {Auth, [],
      init: fn(_client, state) -> state end,
      handle:
        fn(_client, state, _packet) ->
          {:ok, %{state|auth_key: ak, auth_key_hash: akh, server_salt: ss,
                        auth_state: :encrypted, auth_params: nil}}
        end}
  end

  defp auth_error_mocks(reason) do
    {Auth, [],
      init: fn(_client, state) -> state end,
      handle: fn(_client, state, _packet) -> {:error, reason, state} end}
  end
end
