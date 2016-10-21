defmodule MTProto.AuthTest do
  use ExUnit.Case

  import MTProto.Factory

  alias MTProto.{Auth, Crypto, Packet}

  describe "#init" do
    setup do
      {:ok, state: build(:state)}
    end

    test "generates nonce", %{state: state} do
      new_state = Auth.init(self, state)

      assert new_state.auth_params.nonce
    end

    test "auth_state is req_pq", %{state: state} do
      new_state = Auth.init(self, state)

      assert :req_pq == new_state.auth_state
    end

    test "sends req_pq packet", %{state: state} do
      Auth.init(self, state)

      assert_receive {:send_bare, _}
    end
  end

  describe "#req_pq" do
    setup do
      nonce = Crypto.make_nonce(16)
      state = build(:state,
        auth_state: :req_pq,
        auth_params: %MTProto.AuthParams{nonce: nonce})

      {:ok, state: state, nonce: nonce}
    end

    test "sends req_dh_params", %{state: state, nonce: nonce} do
      res_pq = TL.MTProto.encode(build(:res_pq, nonce: nonce))
      {:ok, _new_state} = Auth.handle(self, state, res_pq)

      packet =
        receive do
          {:send_bare, packet} -> packet
        end

      {:ok, packet, _} = Packet.decode(packet)
      {:ok, packet, _, _} = Packet.decode_packet(packet, state)
      {:ok, req_dh_params} = TL.MTProto.decode(packet)

      assert <<1229739323 :: 32>> == req_dh_params.p
      assert <<1402015859 :: 32>> == req_dh_params.q
    end

    test "generates new_nonce and sets server_nonce", %{state: state, nonce: nonce} do
      res_pq = TL.MTProto.encode(build(:res_pq, nonce: nonce))
      {:ok, new_state} = Auth.handle(self, state, res_pq)

      assert 32 == byte_size(new_state.auth_params.new_nonce)
      assert 16 == byte_size(new_state.auth_params.server_nonce)
    end

    test "auth_state is req_dh_params", %{state: state, nonce: nonce} do
      res_pq = TL.MTProto.encode(build(:res_pq, nonce: nonce))
      {:ok, new_state} = Auth.handle(self, state, res_pq)

      assert :req_dh_params == new_state.auth_state
    end
  end

  describe "#req_dh_params" do
    setup do
      auth_params =
        %MTProto.AuthParams{
          new_nonce: <<1, 200, 214, 71, 172, 49, 136, 152, 132, 42,
                       63, 70, 74, 179, 78, 190, 218, 248, 59, 208, 98, 56, 57, 194, 46, 247, 228,
                       215, 79, 86, 179, 224>>,
          nonce: <<210, 95, 72, 107, 89, 71, 116, 192, 189, 23, 244, 77, 21, 217, 253, 0>>,
          nonce_hash1: nil,
          server_nonce: <<123, 42, 52, 200, 170, 19, 159, 43, 214, 254, 128, 16, 95, 144, 92, 82>>}

      state = build(:state,
        auth_state: :req_dh_params,
        auth_params: auth_params)

      {:ok, state: state}
    end

    test "server_dh_params_fail returns error", %{state: state} do
      res_pq = TL.MTProto.encode(build(:server_dh_params_fail))
      assert {:error, :server_dh_params_fail, state}
          == Auth.handle(self, state, res_pq)
    end

    test "server_dh_params_ok", %{state: state} do
      encrypted_answer =
        <<18, 1, 212, 182, 130, 175, 113, 155, 206, 247, 64, 11, 61, 47, 62, 28, 132,
          243, 196, 35, 4, 77, 216, 118, 254, 199, 19, 110, 46, 241, 8, 236, 69, 68,
          200, 64, 115, 77, 101, 148, 31, 221, 65, 92, 139, 24, 96, 43, 80, 93, 207,
          195, 128, 74, 210, 74, 226, 212, 150, 128, 127, 173, 54, 19, 145, 184, 176,
          80, 176, 18, 78, 89, 125, 37, 177, 152, 186, 177, 229, 42, 21, 197, 22, 58,
          127, 160, 169, 102, 169, 9, 83, 253, 71, 247, 220, 83, 51, 123, 109, 83, 29,
          195, 251, 62, 165, 160, 43, 231, 3, 38, 224, 250, 17, 253, 112, 158, 72, 33,
          114, 67, 19, 249, 19, 160, 251, 185, 250, 248, 248, 217, 145, 5, 111, 180, 90,
          216, 24, 125, 84, 80, 110, 21, 192, 238, 27, 11, 103, 85, 161, 95, 191, 241,
          18, 167, 192, 113, 193, 189, 249, 152, 133, 154, 100, 39, 132, 202, 96, 192,
          133, 253, 152, 110, 39, 94, 192, 33, 25, 189, 224, 44, 149, 254, 6, 249, 7,
          36, 19, 155, 14, 135, 215, 63, 86, 248, 43, 128, 38, 227, 43, 184, 4, 207,
          203, 112, 128, 158, 66, 92, 215, 32, 184, 214, 78, 239, 96, 125, 228, 152, 74,
          112, 76, 193, 33, 167, 154, 154, 62, 153, 5, 178, 63, 251, 45, 121, 47, 88,
          237, 35, 220, 175, 188, 174, 109, 173, 101, 89, 125, 105, 47, 229, 198, 233,
          35, 134, 78, 250, 44, 189, 48, 70, 21, 34, 54, 218, 187, 182, 220, 123, 188,
          253, 74, 182, 188, 17, 65, 131, 178, 122, 3, 146, 83, 59, 28, 163, 8, 191, 32,
          176, 96, 86, 161, 229, 18, 45, 238, 100, 253, 185, 13, 97, 85, 191, 154, 106,
          162, 91, 88, 198, 44, 248, 23, 60, 242, 162, 235, 192, 221, 250, 2, 242, 188,
          195, 231, 84, 103, 192, 241, 6, 216, 13, 230, 101, 67, 249, 108, 132, 57, 27,
          205, 163, 223, 116, 210, 254, 29, 103, 57, 117, 3, 228, 200, 146, 221, 66,
          150, 20, 243, 70, 179, 246, 243, 149, 46, 233, 155, 20, 216, 27, 188, 56, 130,
          9, 174, 73, 76, 228, 220, 55, 29, 238, 76, 54, 38, 25, 133, 233, 54, 150, 78,
          68, 242, 25, 243, 3, 253, 150, 228, 31, 210, 90, 186, 21, 113, 62, 4, 57, 161,
          31, 219, 231, 92, 114, 224, 42, 252, 108, 48, 126, 156, 203, 215, 40, 161,
          206, 80, 29, 164, 254, 140, 58, 28, 45, 150, 191, 42, 69, 228, 59, 94, 54,
          107, 140, 133, 250, 249, 114, 162, 226, 115, 248, 77, 33, 119, 37, 123, 157,
          43, 248, 223, 133, 156, 237, 93, 174, 20, 82, 34, 233, 149, 165, 59, 198, 26,
          235, 134, 174, 111, 97, 111, 68, 73, 104, 239, 50, 118, 65, 69, 146, 24, 241,
          198, 60, 84, 14, 174, 222, 151, 79, 55, 231, 96, 143, 210, 165, 0, 230, 47,
          174, 207, 94, 115, 97, 122, 171, 167, 237, 144, 101, 162, 197, 117, 150, 149,
          123, 190, 62, 21, 12, 181, 32, 37, 239, 91, 12, 124, 166, 150, 160, 63, 185,
          219, 181, 155, 53, 142, 210, 97, 190, 133, 246, 201, 72, 89, 72, 133, 67, 54,
          179, 173, 53, 163, 114, 214, 37, 148, 200, 212, 18, 171, 158, 242, 25, 80,
          105, 124, 63, 38, 29, 30, 89, 205, 55, 178, 248, 166, 251, 51, 242, 62, 129,
          49, 221>>

      res_pq = TL.MTProto.encode(build(:server_dh_params_ok, encrypted_answer: encrypted_answer))
      {:ok, new_state} = Auth.handle(self, state, res_pq)

      assert 256 == byte_size(new_state.auth_key)
      assert 8   == byte_size(new_state.auth_key_hash)
      assert 8   == byte_size(new_state.server_salt)

      packet =
        receive do
          {:send_bare, packet} -> packet
        end

      {:ok, packet, _} = Packet.decode(packet)
      {:ok, packet, _, _} = Packet.decode_packet(packet, state)
      {:ok, set_client_dh_params} = TL.MTProto.decode(packet)

      assert TL.MTProto.Set.Client.DH.Params == set_client_dh_params.__struct__
    end
  end

  describe "#dh_gen" do
    setup do
      state = build(:state,
        auth_state: :dh_gen, auth_key: <<>>,
        auth_key_hash: <<>>, server_salt: <<>>,
        auth_params: %MTProto.AuthParams{nonce_hash1: <<>>})

      {:ok, state: state}
    end

    test "dh_gen_fail returns error", %{state: state} do
      res_pq = TL.MTProto.encode(build(:dh_gen_fail))

      assert {:error, :dh_gen_fail, state}
          == Auth.handle(self, state, res_pq)
    end

    test "dh_gen_retry returns error", %{state: state} do
      res_pq = TL.MTProto.encode(build(:dh_gen_retry))

      assert {:error, :dh_gen_retry, state}
          == Auth.handle(self, state, res_pq)
    end

    test "dh_gen_ok returns error when salts mismatched", %{state: state} do
      res_pq = TL.MTProto.encode(build(:dh_gen_ok))

      assert {:error, :mismatched_nonce_hash1, state}
          == Auth.handle(self, state, res_pq)
    end

    test "dh_gen_ok returns ok", %{state: state} do
      nonce_hash = Crypto.make_nonce(16)
      auth_params = %MTProto.AuthParams{nonce_hash1: nonce_hash}
      state = %{state|auth_params: auth_params}

      res_pq = TL.MTProto.encode(build(:dh_gen_ok, new_nonce_hash1: nonce_hash))
      {:ok, state} = Auth.handle(self, state, res_pq)

      assert :encrypted == state.auth_state
      assert nil == state.auth_params
    end
  end
end
