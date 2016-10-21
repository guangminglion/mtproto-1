defmodule MTProto.Factory do
  use ExMachina

  alias MTProto.Crypto

  @auth_key File.read!("test/support/crypto_auth.key")

  def state_factory do
    %MTProto.State{
      auth_state: :connected, notifier: self, packet_buffer: <<>>,
      session_id: Crypto.make_session_id, msg_seqno: 0, msg_ids: %{},
      msg_ids_to_ack: []}
  end

  def encrypted_state_factory do
    %MTProto.State{
      auth_state: :encrypted, auth_key: @auth_key, auth_key_hash: Crypto.auth_key_hash(@auth_key),
      server_salt: <<148, 211, 200, 232, 215, 235, 188, 204>>,
      session_id: <<237, 3, 178, 105, 5, 99, 189, 59>>,
      notifier: self, packet_buffer: <<>>, msg_seqno: 0, msg_ids: %{},
      msg_ids_to_ack: []}
  end

  def packet_meta_factory do
    %MTProto.Packet.Meta{}
  end

  def res_pq_factory do
    %TL.MTProto.ResPQ{
      nonce: Crypto.make_nonce(16),
      server_nonce: Crypto.make_nonce(16),
      pq: <<23, 237, 72, 148, 26, 8, 249, 129>>,
      server_public_key_fingerprints: [0]}
  end

  def server_dh_params_ok_factory do
    %TL.MTProto.Server.DH.Params.Ok{
      nonce: Crypto.make_nonce(16),
      server_nonce: Crypto.make_nonce(16),
      encrypted_answer: <<>>}
  end

  def server_dh_params_fail_factory do
    %TL.MTProto.Server.DH.Params.Fail{
      nonce: Crypto.make_nonce(16),
      server_nonce: Crypto.make_nonce(16),
      new_nonce_hash: Crypto.make_nonce(16)}
  end

  def dh_gen_ok_factory do
    %TL.MTProto.Dh.Gen.Ok{
      nonce: Crypto.make_nonce(16),
      server_nonce: Crypto.make_nonce(16),
      new_nonce_hash1: Crypto.make_nonce(16)}
  end

  def dh_gen_retry_factory do
    %TL.MTProto.Dh.Gen.Retry{
      nonce: Crypto.make_nonce(16),
      server_nonce: Crypto.make_nonce(16),
      new_nonce_hash2: Crypto.make_nonce(16)}
  end

  def dh_gen_fail_factory do
    %TL.MTProto.Dh.Gen.Fail{
      nonce: Crypto.make_nonce(16),
      server_nonce: Crypto.make_nonce(16),
      new_nonce_hash3: Crypto.make_nonce(16)}
  end

  def config_factory do
    %TL.Config{
      chat_big_size: 10, chat_size_max: 200, date: 1476812773,
      dc_options: dc_options,
      disabled_features: [], edit_time_limit: 172800,
      expires: 1476816842, forwarded_count_max: 100,
      megagroup_size_max: 5000,
      notify_cloud_delay_ms: 30000, notify_default_delay_ms: 1500,
      offline_blur_timeout_ms: 5000, offline_idle_timeout_ms: 30000,
      online_cloud_timeout_ms: 300000, online_update_period_ms: 120000,
      push_chat_limit: 2, push_chat_period_ms: 60000, rating_e_decay: 2419200,
      saved_gifs_limit: 200, stickers_recent_limit: 30, test_mode: false,
      this_dc: 2, tmp_sessions: nil}
  end

  defp dc_options do
    [
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
  end
end
