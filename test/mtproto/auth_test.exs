defmodule MTProto.AuthTest do
  use ExUnit.Case
  alias MTProto.Auth

  test "#req_pq" do
    # Sample packet getting from [1]
    # 1. https://core.telegram.org/mtproto/samples-auth_key#1-request-for-p-q-authorization
    {:ok, req_pq_bytes} = Base.decode16("789746603E0549828CCA27E966B301A48FECE2FC")
    {:ok, nonce_bytes} = Base.decode16("3E0549828CCA27E966B301A48FECE2FC")

    assert req_pq_bytes
        == Auth.req_pq(nonce_bytes)

    assert <<120, 151, 70, 96, _nonce :: binary-size(16)>>
        = Auth.req_pq
  end

  test "#res_pq" do
    # Sample packet getting from [1] without auth_key_id, message_id, message_length
    # 1. https://core.telegram.org/mtproto/samples-auth_key#2-a-response-from-the-server-has-been-received-with-the-followin
    {:ok, res_pq_bytes} =
      Base.decode16(<<"632416053E0549828CCA27E966B301A48FECE2FCA5CF4D33F4A11EA877BA4AA5",
                      "739073300817ED48941A08F98100000015C4B51C01000000216BE86C022BB4C3">>)
    {:ok, nonce_bytes} = Base.decode16("3E0549828CCA27E966B301A48FECE2FC")

    assert %{nonce: nonce_bytes,
             server_nonce: <<165, 207, 77, 51, 244, 161, 30, 168, 119, 186, 74, 165, 115, 144, 115, 48>>,
             pq: 1724114033281923457,
             server_public_key_fingerprints: [14101943622620965665]}
        == Auth.res_pq(res_pq_bytes)
  end

  test "#pq_inner_data" do
    nonce = <<62, 5, 73, 130, 140, 202, 39, 233, 102, 179, 1, 164, 143, 236, 226, 252>>
    server_nonce = <<165, 207, 77, 51, 244, 161, 30, 168, 119, 186, 74, 165, 115, 144, 115, 48>>

    pq = 1724114033281923457
    p = 1229739323
    q = 1402015859

    {:ok, new_nonce} = Base.decode16("311C85DB234AA2640AFC4A76A735CF5B1F0FD68BD17FA181E1229AD867CC024D")

    assert <<236, 90, 201, 131, 8, 23, 237, 72, 148, 26, 8, 249, 129, 0, 0, 0, 4, 73,
             76, 85, 59, 0, 0, 0, 4, 83, 145, 16, 115, 0, 0, 0, 62, 5, 73, 130, 140,
             202, 39, 233, 102, 179, 1, 164, 143, 236, 226, 252, 165, 207, 77, 51, 244,
             161, 30, 168, 119, 186, 74, 165, 115, 144, 115, 48, 49, 28, 133, 219, 35,
             74, 162, 100, 10, 252, 74, 118, 167, 53, 207, 91, 31, 15, 214, 139, 209,
             127, 161, 129, 225, 34, 154, 216, 103, 204, 2, 77>>
        == Auth.p_q_inner_data(pq, p, q, nonce, server_nonce, new_nonce)
  end

  test "#p_q_inner_data_sha1" do
    # https://core.telegram.org/mtproto/samples-auth_key#4-encrypted-data-generation
    {:ok, sha1_bytes} = Base.decode16("DB761C27718A2305044F71F2AD951629D78B2449")
    packet =
      <<236, 90, 201, 131, 8, 23, 237, 72, 148, 26, 8, 249, 129, 0, 0, 0, 4, 73,
        76, 85, 59, 0, 0, 0, 4, 83, 145, 16, 115, 0, 0, 0, 62, 5, 73, 130, 140,
        202, 39, 233, 102, 179, 1, 164, 143, 236, 226, 252, 165, 207, 77, 51, 244,
        161, 30, 168, 119, 186, 74, 165, 115, 144, 115, 48, 49, 28, 133, 219, 35,
        74, 162, 100, 10, 252, 74, 118, 167, 53, 207, 91, 31, 15, 214, 139, 209,
        127, 161, 129, 225, 34, 154, 216, 103, 204, 2, 77>>

    assert sha1_bytes
        == Auth.p_q_inner_data_sha1(packet)
  end

  test "#p_q_inner_data_rsa" do
    # ...
  end

  test "#req_dh_params" do
    {:ok, req_dh_params_bytes} = Base.decode16(
      <<"BEE412D73E0549828CCA27E966B301A48FECE2FCA5CF4D33F4A11EA877BA4AA5739073",
        "3004494C553B0000000453911073000000216BE86C022BB4C3FE0001007BB0100A5231",
        "61904D9C69FA04BC60DECFC5DD74B99995C768EB60D8716E2109BAF2D4601DAB6B0961",
        "0DC11067BB89021E09471FCFA52DBD0F23204AD8CA8B012BF40A112F44695AB6C26695",
        "5386114EF5211E6372227ADBD34995D3E0E5FF02EC63A43F9926878962F7C570E6A6E7",
        "8BF8366AF917A5272675C46064BE62E3E202EFA8B1ADFB1C32A898C2987BE27B5F31D5",
        "7C9BB963ABCB734B16F652CEDB4293CBB7C878A3A3FFAC9DBEA9DF7C67BC9E9508E111",
        "C78FC46E057F5C65ADE381D91FEE430A6B576A99BDF8551FDB1BE2B57069B1A4573061",
        "8F27427E8A04720B4971EF4A9215983D68F2830C3EAA6E40385562F970D38A05C9F124",
        "6DC33438E6">>)
    {:ok, encrypted_data_bytes} = Base.decode16(
      <<"7BB0100A523161904D9C69FA04BC60DECFC5DD74B99995C768EB60D8716E2109BAF2D4601DAB6B09",
        "610DC11067BB89021E09471FCFA52DBD0F23204AD8CA8B012BF40A112F44695AB6C266955386114E",
        "F5211E6372227ADBD34995D3E0E5FF02EC63A43F9926878962F7C570E6A6E78BF8366AF917A52726",
        "75C46064BE62E3E202EFA8B1ADFB1C32A898C2987BE27B5F31D57C9BB963ABCB734B16F652CEDB42",
        "93CBB7C878A3A3FFAC9DBEA9DF7C67BC9E9508E111C78FC46E057F5C65ADE381D91FEE430A6B576A",
        "99BDF8551FDB1BE2B57069B1A45730618F27427E8A04720B4971EF4A9215983D68F2830C3EAA6E40",
        "385562F970D38A05C9F1246DC33438E6">>)

    nonce = <<62, 5, 73, 130, 140, 202, 39, 233, 102, 179, 1, 164, 143, 236, 226, 252>>
    server_nonce = <<165, 207, 77, 51, 244, 161, 30, 168, 119, 186, 74, 165, 115, 144, 115, 48>>
    p = 1229739323
    q = 1402015859
    public_key_fingerprint = 14101943622620965665

    assert req_dh_params_bytes
        == Auth.req_dh_params(nonce, server_nonce, p, q, public_key_fingerprint, encrypted_data_bytes)
  end

  test "#factorize" do
    # Sample PQ and P, Q numbers from [1]
    # 1. https://core.telegram.org/mtproto/samples-auth_key#3-pq-17ed48941a08f981-decomposed-into-2-prime-cofactors
    {:ok, pq_bytes} = Base.decode16("17ED48941A08F981")
    {:ok, p_bytes} = Base.decode16("494C553B")
    {:ok, q_bytes} = Base.decode16("53911073")

    <<pq :: 64>> = pq_bytes
    <<p :: 32>> = p_bytes
    <<q :: 32>> = q_bytes

    assert [p, q] == Auth.factorize(pq)
  end
end
