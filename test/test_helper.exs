Application.put_env(:ex_unit, :assert_receive_timeout, 500)
Application.put_env(:mtproto, :api_id, 1)
Application.put_env(:mtproto, :api_hash, "h3sh")
ExUnit.start()
