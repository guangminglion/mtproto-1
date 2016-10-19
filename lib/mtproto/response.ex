defmodule MTProto.Response do
  def handle(state, result) do
    case result do
      %TL.MTProto.Msg.Container{messages: messages} ->
        Enum.reduce(messages, state, fn(message, state) ->
          handle(state, message)
        end)
      %TL.MTProto.Message{seqno: _seqno, msg_id: _msg_id, body: body} ->
        handle(state, body)
      %TL.MTProto.Msgs.Ack{msg_ids: msg_ids} ->
        %{state|msg_ids: state.msg_ids -- msg_ids}
      %TL.MTProto.New.Session.Created{server_salt: server_salt} ->
        # convert to binary
        server_salt = <<server_salt :: little-size(64)>>
        # notify about authorization result, because this packet means
        # that connection is initialized after authorization
        send_to_notifier(state,
          {:authorized, state.auth_key, state.auth_key_hash, server_salt})
        # update state
        %{state|server_salt: server_salt}
      # TODO migrate to another DC
      # %TL.MTProto.Rpc.Error{error_code: 303, error_message: <<"NETWORK_MIGRATE_", dc_id :: binary>> = message} ->
      #   send_to_notifier(state, {:error, 303, message})
      #   dc_id = String.to_integer(dc_id)
      #   request = %TL.Auth.ExportAuthorization{dc_id: dc_id}
      #   send_rpc_request(state.socket, request, state)
      #   # send(self, {:reconnect, {:change_dc, dc_id}})
      #   %{state|reconnect: {:dc, dc_id}}
      %TL.MTProto.Rpc.Error{error_code: code, error_message: message} ->
        send_to_notifier(state, {:error, code, message})
        state
      %TL.MTProto.Rpc.Result{req_msg_id: req_msg_id, result: result} ->
        state = handle(state, result)
        %{state|msg_ids_to_ack: [req_msg_id|state.msg_ids_to_ack]}
      %TL.MTProto.Bad.Server.Salt{new_server_salt: server_salt} ->
        # convert to binary
        server_salt = <<server_salt :: little-size(64)>>
        # reconnect to use new server_salt
        send(self, {:reconnect, :server_salt_changed})
        # notify handler
        send_to_notifier(state, {:config, :server_salt, server_salt})
        %{state|server_salt: server_salt}
      %TL.MTProto.Bad.Msg.Notification{error_code: code} ->
        send_to_notifier(state, {:error, code, "bad_msg_id"})
        state
      %TL.MTProto.Gzip.Packed{packed_data: packed_data} ->
        {:ok, data} = TL.Serializer.decode(:zlib.gunzip(packed_data))
        handle(state, data)
      # stores this_dc and dc list, changes when server fails
      # or returns Rpc.Error, or accidentally disconnected
      %TL.Config{dc_options: dc_options, this_dc: dc} = config ->
        # notify config
        send_to_notifier(state, {:config, :server_config, config})
        %{state|dc_options: dc_options, dc: dc}
      result ->
        # IO.puts " --- handle client, result: #{inspect result}"
        send_to_notifier(state, {:result, result})
        state
    end
  end

  defp send_to_notifier(state, message) do
    send(state.notifier, {:tl, message})
  end
end
