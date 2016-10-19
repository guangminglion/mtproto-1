defmodule MTProto.ResponseTest do
  use ExUnit.Case

  import MTProto.Factory

  alias MTProto.Response

  setup do
    {:ok, state: build(:encrypted_state)}
  end

  describe "msg_container" do
    test "handle list of messages in it", %{state: state} do
      state = %{state|msg_ids: [6343121433228688616]}

      message1 =
        %TL.MTProto.New.Session.Created{
          first_msg_id: 6343121433228688616, server_salt: 12316263358524012731,
          unique_id: 12914591209778918544}
      message2 =
        %TL.MTProto.Msgs.Ack{msg_ids: [6343121433228688616]}

      result =
        %TL.MTProto.Msg.Container{
          messages: [
            %TL.MTProto.Message{body: message1, bytes: 28, msg_id: 6343121434061049857, seqno: 1},
            %TL.MTProto.Message{body: message2, bytes: 20, msg_id: 6343121434061063169, seqno: 2}
          ]}

      new_state = Response.handle(state, result)

      assert [] == new_state.msg_ids
      assert <<12316263358524012731 :: little-size(64)>> == new_state.server_salt
      assert_receive {:tl, {:authorized, _, _, _}}
    end
  end

  describe "message" do
    test "handle message bytes as another result", %{state: state} do
      message1 =
        %TL.MTProto.New.Session.Created{
          first_msg_id: 6343121433228688616, server_salt: 12316263358524012731,
          unique_id: 12914591209778918544}
      result =
        %TL.MTProto.Message{body: message1, bytes: 28, msg_id: 6343121434061049857, seqno: 1}

      new_state = Response.handle(state, result)

      assert <<12316263358524012731 :: little-size(64)>> == new_state.server_salt
      assert_receive {:tl, {:authorized, _, _, _}}
    end
  end

  describe "msgs_ack" do
    test "removes msg_id list from state", %{state: state} do
      state = %{state|msg_ids: [6343121433228688616, 6343121433228688723]}

      result = %TL.MTProto.Msgs.Ack{msg_ids: [6343121433228688616]}
      new_state = Response.handle(state, result)

      assert [6343121433228688723] == new_state.msg_ids
    end
  end

  describe "new_session_created" do
    test "accepts new session, stores auth credentials in state", %{state: state} do
      state = %{state|server_salt: nil}

      result =
        %TL.MTProto.New.Session.Created{
          first_msg_id: 6343121433228688616, server_salt: 12316263358524012731,
          unique_id: 12914591209778918544}
      new_state = Response.handle(state, result)

      assert <<12316263358524012731 :: little-size(64)>> == new_state.server_salt
    end
  end

  describe "rpc_error" do
    test "notifies client about error", %{state: state} do
      result = %TL.MTProto.Rpc.Error{error_code: 32, error_message: "msg"}
      Response.handle(state, result)

      assert_receive {:tl, {:error, 32, "msg"}}
    end
  end

  describe "rpc_result" do
    test "adds msg_id to msg_ids_to_ack in state", %{state: state} do
      result =
        %TL.MTProto.Rpc.Result{
          req_msg_id: 6343121433228688616,
          result: %TL.Updates{updates: [], users: [], chats: [], date: 0, seq: 0}}
      new_state = Response.handle(state, result)

      assert [6343121433228688616] == new_state.msg_ids_to_ack
    end

    test "handles rpc as another result", %{state: state} do
      updates = %TL.Updates{updates: [], users: [], chats: [], date: 0, seq: 0}
      result =
        %TL.MTProto.Rpc.Result{
          req_msg_id: 6343121433228688616,
          result: updates}
      Response.handle(state, result)

      assert_receive {:tl, {:result, ^updates}}
    end
  end

  describe "bad_server_salt" do
    test "assigns new server_salt", %{state: state} do
      new_server_salt = 8716363015989386725
      result =
        %TL.MTProto.Bad.Server.Salt{
          bad_msg_id: 0, bad_msg_seqno: 0, error_code: 0,
          new_server_salt: new_server_salt}
      new_state = Response.handle(state, result)

      assert <<new_server_salt :: little-size(64)>> == new_state.server_salt
    end

    test "sends :reconnect to client", %{state: state} do
      new_server_salt = 8716363015989386725
      result =
        %TL.MTProto.Bad.Server.Salt{
          bad_msg_id: 0, bad_msg_seqno: 0, error_code: 0,
          new_server_salt: new_server_salt}
      Response.handle(state, result)

      assert_receive {:reconnect, :server_salt_changed}
    end

    test "sends :server_salt_changed to notifier", %{state: state} do
      new_server_salt = 8716363015989386725
      result =
        %TL.MTProto.Bad.Server.Salt{
          bad_msg_id: 0, bad_msg_seqno: 0, error_code: 0,
          new_server_salt: new_server_salt}
      Response.handle(state, result)

      assert_receive {:tl, {:config, :server_salt, <<229, 93, 102, 85, 251, 189, 246, 120>>}}
    end
  end

  describe "bad_msg_notification" do
    test "sends error to notifier", %{state: state} do
      result = %TL.MTProto.Bad.Msg.Notification{error_code: 32}
      Response.handle(state, result)

      assert_receive {:tl, {:error, 32, "bad_msg_id"}}
    end
  end

  describe "gzip_packed" do
    test "unpacks data and handles as another result", %{state: state} do
      result =
        %TL.MTProto.Gzip.Packed{
          packed_data:
          <<31, 139, 8, 0, 0, 0, 0, 0, 0, 3, 115, 112, 90, 87, 34, 122, 100, 171, 12, 3,
            16, 160, 211, 48, 0, 0, 108, 5, 147, 174, 36, 0, 0, 0>>}
      Response.handle(state, result)

      assert_receive {:tl, {:result, %TL.Updates{updates: [], users: [], chats: [], date: 0, seq: 0}}}
    end
  end

  describe "config" do
    test "sends config to notifier", %{state: state} do
      result = build(:config)
      Response.handle(state, result)

      assert_receive {:tl, {:config, :server_config, ^result}}
    end

    test "appends dc and dc_options to state", %{state: state} do
      result = build(:config)
      new_state = Response.handle(state, result)

      assert result.this_dc == new_state.dc
      assert result.dc_options == new_state.dc_options
    end
  end

  describe "any other packet" do
    test "sends to notifier", %{state: state} do
      result = %TL.Updates{updates: [], users: [], chats: [], date: 0, seq: 0}
      Response.handle(state, result)

      assert_receive {:tl, {:result, ^result}}
    end
  end
end
