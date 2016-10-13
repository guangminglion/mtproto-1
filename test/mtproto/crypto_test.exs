defmodule MTProto.CryptoTest do
  use ExUnit.Case
  alias MTProto.Crypto

  describe "#encrypt_packet" do
    test "encrypts packet"
  end

  describe "#decrypt_packet" do
    setup do
      {:ok, auth_key: File.read!("test/support/crypto_auth.key")}
    end

    test "decrypts packet", %{auth_key: auth_key} do
      packet =
        <<224, 228, 243, 169, 134, 100, 52, 190, 179, 21, 141, 143, 80, 14, 6, 23, 108,
          127, 159, 172, 39, 216, 64, 188, 217, 19, 77, 213, 239, 10, 99, 209, 196, 185,
          110, 78, 70, 6, 54, 222, 117, 67, 250, 130, 241, 230, 26, 139, 135, 191, 7,
          98, 41, 5, 177, 192, 81, 220, 33, 27, 108, 35, 178, 163, 205, 40, 107, 134,
          159, 110, 165, 95, 135, 165, 210, 194, 88, 52, 186, 207, 151, 14, 72, 180, 78,
          22, 239, 61>>

      assert <<149, 207, 239, 138, 34, 182, 169, 27, 8, 71, 155, 79, 245, 248, 199, 44, 1,
               72, 207, 238, 18, 196, 252, 87, 11, 0, 0, 0, 24, 0, 0, 0, 193, 222, 212, 120,
               35, 216, 251, 27, 239, 181, 204, 1, 63, 112, 140, 0, 18, 196, 252, 87, 18,
               196, 252, 87, 238, 107, 182, 74, 125, 109, 15, 67>>
          == Crypto.decrypt_packet(packet, auth_key)
    end
  end

  test "#generate_aes" do
    msg_key = <<186, 66, 170, 172, 108, 132, 64, 89, 239, 14, 164, 98, 92, 135, 137, 32>>
    auth_key = File.read!("test/support/auth.key")

    assert {<<137, 14, 71, 132, 185, 169, 133, 60, 250, 228, 174, 22, 92, 215, 253, 195,
              49, 123, 255, 30, 39, 232, 44, 162, 158, 205, 98, 146, 103, 194, 20, 221>>,
            <<104, 101, 106, 24, 90, 182, 151, 44, 52, 79, 134, 74, 6, 37, 24, 78,
              73, 101, 219, 6, 63, 160, 135, 70, 65, 200, 136, 183, 245, 3, 150, 185>>}
        == Crypto.generate_aes(msg_key, auth_key, :decode)

    assert {<<137, 57, 80, 44, 91, 23, 56, 40, 132, 106, 198, 45, 22, 81, 226, 17, 175,
              40, 107, 252, 252, 214, 187, 137, 237, 22, 75, 158, 253, 173, 244, 125>>,
            <<181, 22, 162, 26, 208, 124, 179, 60, 228, 18, 228, 114, 7, 162, 188, 6,
              30, 136, 207, 202, 22, 52, 254, 36, 20, 90, 129, 37, 24, 179, 221, 147>>}
        == Crypto.generate_aes(msg_key, auth_key, :encode)
  end

  test "#make_session_id"
  test "#make_nonce"
  test "#p_q_inner_data_rsa"

  test "#server_dh_params_decode" do
    {:ok, new_nonce_bytes} = Base.decode16("311C85DB234AA2640AFC4A76A735CF5B1F0FD68BD17FA181E1229AD867CC024D")
    {:ok, nonce_bytes} = Base.decode16("3E0549828CCA27E966B301A48FECE2FC")
    {:ok, server_nonce_bytes} = Base.decode16("A5CF4D33F4A11EA877BA4AA573907330")
    {:ok, encrypted_answer_bytes} = Base.decode16(
      <<"28A92FE20173B347A8BB324B5FAB2667C9A8BBCE6468D5B509A4CBDDC186240AC912CF7006AF8926",
        "DE606A2E74C0493CAA57741E6C82451F54D3E068F5CCC49B4444124B9666FFB405AAB564A3D01E67",
        "F6E912867C8D20D9882707DC330B17B4E0DD57CB53BFAAFA9EF5BE76AE6C1B9B6C51E2D6502A47C8",
        "83095C46C81E3BE25F62427B585488BB3BF239213BF48EB8FE34C9A026CC8413934043974DB03556",
        "633038392CECB51F94824E140B98637730A4BE79A8F9DAFA39BAE81E1095849EA4C83467C92A3A17",
        "D997817C8A7AC61C3FF414DA37B7D66E949C0AEC858F048224210FCC61F11C3A910B431CCBD104CC",
        "CC8DC6D29D4A5D133BE639A4C32BBFF153E63ACA3AC52F2E4709B8AE01844B142C1EE89D075D64F6",
        "9A399FEB04E656FE3675A6F8F412078F3D0B58DA15311C1A9F8E53B3CD6BB5572C294904B726D0BE",
        "337E2E21977DA26DD6E33270251C2CA29DFCC70227F0755F84CFDA9AC4B8DD5F84F1D1EB36BA45CD",
        "DC70444D8C213E4BD8F63B8AB95A2D0B4180DC91283DC063ACFB92D6A4E407CDE7C8C69689F77A00",
        "7441D4A6A8384B666502D9B77FC68B5B43CC607E60A146223E110FCB43BC3C942EF981930CDC4A1D",
        "310C0B64D5E55D308D863251AB90502C3E46CC599E886A927CDA963B9EB16CE62603B68529EE98F9",
        "F5206419E03FB458EC4BD9454AA8F6BA777573CC54B328895B1DF25EAD9FB4CD5198EE022B2B81F3",
        "88D281D5E5BC580107CA01A50665C32B552715F335FD76264FAD00DDD5AE45B94832AC79CE7C511D",
        "194BC42B70EFA850BB15C2012C5215CABFE97CE66B8D8734D0EE759A638AF013">>)
    {:ok, answer_bytes} = Base.decode16(
      <<"BA0D89B53E0549828CCA27E966B301A48FECE2FCA5CF4D33F4A11EA877BA4AA57390733002000000",
        "FE000100C71CAEB9C6B1C9048E6C522F70F13F73980D40238E3E21C14934D037563D930F48198A0A",
        "A7C14058229493D22530F4DBFA336F6E0AC925139543AED44CCE7C3720FD51F69458705AC68CD4FE",
        "6B6B13ABDC9746512969328454F18FAF8C595F642477FE96BB2A941D5BCD1D4AC8CC49880708FA9B",
        "378E3C4F3A9060BEE67CF9A4A4A695811051907E162753B56B0F6B410DBA74D8A84B2A14B3144E0E",
        "F1284754FD17ED950D5965B4B9DD46582DB1178D169C6BC465B0D6FF9CA3928FEF5B9AE4E418FC15",
        "E83EBEA0F87FA9FF5EED70050DED2849F47BF959D956850CE929851F0D8115F635B105EE2E4E15D0",
        "4B2454BF6F4FADF034B10403119CD8E3B92FCC5BFE000100262AABA621CC4DF587DC94CF8252258C",
        "0B9337DFB47545A49CDD5C9B8EAE7236C6CADC40B24E88590F1CC2CC762EBF1CF11DCC0B393CAAD6",
        "CEE4EE5848001C73ACBB1D127E4CB93072AA3D1C8151B6FB6AA6124B7CD782EAF981BDCFCE9D7A00",
        "E423BD9D194E8AF78EF6501F415522E44522281C79D906DDB79C72E9C63D83FB2A940FF779DFB5F2",
        "FD786FB4AD71C9F08CF48758E534E9815F634F1E3A80A5E1C2AF210C5AB762755AD4B2126DFA61A7",
        "7FA9DA967D65DFD0AFB5CDF26C4D4E1A88B180F4E0D0B45BA1484F95CB2712B50BF3F5968D9D55C9",
        "9C0FB9FB67BFF56D7D4481B634514FBA3488C4CDA2FC0659990E8E868B28632875A9AA703BCDCE8F",
        "CB7AE551">>)
    {:ok, tmp_aes_key_bytes} = Base.decode16("F011280887C7BB01DF0FC4E17830E0B91FBB8BE4B2267CB985AE25F33B527253")
    {:ok, tmp_aes_iv_bytes} = Base.decode16("3212D579EE35452ED23E0D0C92841AA7D31B2E9BDEF2151E80D15860311C85DB")

    answer_padding = <<153,226,221,221,83,102,72,216>>
    answer = <<answer_bytes :: binary, answer_padding :: binary>>

    assert %{tmp_aes_key: tmp_aes_key_bytes, tmp_aes_iv: tmp_aes_iv_bytes, answer: answer}
        == Crypto.server_dh_params_decode(new_nonce_bytes, server_nonce_bytes, encrypted_answer_bytes)
  end

  test "#client_dh_inner_data_encrypt" do
    {:ok, tmp_aes_key_bytes} = Base.decode16("F011280887C7BB01DF0FC4E17830E0B91FBB8BE4B2267CB985AE25F33B527253")
    {:ok, tmp_aes_iv_bytes} = Base.decode16("3212D579EE35452ED23E0D0C92841AA7D31B2E9BDEF2151E80D15860311C85DB")
    client_dh_inner_data =
      <<84,182,67,102,62,5,73,130,140,202,39,233,102,179,1,164,143,236,226,252,165,
        207,77,51,244,161,30,168,119,186,74,165,115,144,115,48,0,0,0,0,0,0,0,0,254,0,
        1,0,115,112,14,123,252,122,238,200,40,235,142,13,204,4,208,154,13,213,106,27,
        75,53,247,47,11,85,252,231,219,126,187,114,215,195,60,93,74,165,158,28,116,
        208,155,1,174,83,107,49,140,254,212,54,175,219,21,254,158,180,199,13,127,12,
        177,78,70,219,189,233,5,58,100,48,67,97,235,53,138,155,179,46,157,92,40,67,
        254,135,36,139,137,195,240,102,167,213,135,109,97,101,122,204,82,176,216,28,
        214,131,178,160,250,147,232,173,171,32,55,120,119,243,188,51,105,187,245,123,
        16,245,181,137,230,90,156,39,73,15,48,160,199,15,252,253,52,83,245,179,121,
        193,185,114,122,87,60,255,220,168,210,60,114,27,19,91,146,229,41,177,205,210,
        247,171,212,243,77,172,75,225,238,175,96,153,61,222,142,212,88,144,228,244,
        124,38,242,192,178,224,55,187,80,39,57,200,130,79,42,153,226,177,231,228,22,
        88,52,23,204,121,168,128,122,75,218,198,165,233,128,93,79,97,134,195,125,102,
        246,152,140,159,156,117,40,150,243,211,77,37,82,146,99,250,242,103,10,9,178,
        165,156,227,82,100,81,31>>
    {:ok, encrypted_bytes} = Base.decode16(
      <<"928A4957D0463B525C1CC48AABAA030A256BE5C746792C84CA4C5A0DF60AC799048D98",
        "A38A8480EDCF082214DFC79DCB9EE34E206513E2B3BC1504CFE6C9ADA46BF9A03CA74F",
        "192EAF8C278454ADABC795A566615462D31817382984039505F71CB33A41E2527A4B1A",
        "C05107872FED8E3ABCEE1518AE965B0ED3AED7F67479155BDA8E4C286B64CDF123EC74",
        "8CF289B1DB02D1907B562DF462D8582BA6F0A3022DC2D3504D69D1BA48B677E3A830BF",
        "AFD67584C8AA24E1344A8904E305F9587C92EF964F0083F50F61EAB4A393EAA33C9270",
        "294AEDC7732891D4EA1599F52311D74469D2112F4EDF3F342E93C8E87E812DC3989BAE",
        "CFE6740A46077524C75093F5A5405736DE8937BB6E42C9A0DCF22CA53227D462BCCC2C",
        "FE94B6FE86AB7FBFA395021F66661AF7C0024CA2986CA03F3476905407D1EA9C010B76",
        "3258DB1AA2CC7826D91334EFC1FDC665B67FE45ED0">>)

    encrypted_bytes_size = byte_size(encrypted_bytes) - 16
    <<encrypted :: binary-size(encrypted_bytes_size),
      encrypted_padding :: binary-size(16)>> = encrypted_bytes

    encrypted_result = Crypto.client_dh_inner_data_encrypt(tmp_aes_key_bytes, tmp_aes_iv_bytes, client_dh_inner_data)

    assert <<encrypted :: binary-size(encrypted_bytes_size), _padding :: binary>>
         = encrypted_result
    assert 336 == byte_size(encrypted_result)
  end

  test "#auth_key_hash" do
    {:ok, auth_key_bytes} = Base.decode16(
      <<"AB96E207C631300986F30EF97DF55E179E63C112675F0CE502EE76D74BBEE6CBD1E957",
        "72818881E9F2FF54BD52C258787474F6A7BEA61EABE49D1D01D55F64FC07BC31685716",
        "EC8FB46FEACF9502E42CFD6B9F45A08E90AA5C2B5933AC767CBE1CD50D8E64F89727CA",
        "4A1A5D32C0DB80A9FCDBDDD4F8D5A1E774198F1A4299F927C484FEEC395F29647E43C3",
        "243986F93609E23538C21871DF50E00070B3B6A8FA9BC15628E8B43FF977409A61CEEC",
        "5A21CF7DFB5A4CC28F5257BC30CD8F2FB92FBF21E28924065F50E0BBD5E11A420300E2",
        "C136B80E9826C6C5609B5371B7850AA628323B6422F3A94F6DFDE4C3DC1EA60F7E11EE",
        "63122B3F39CBD1A8430157">>)

    assert <<145, 9, 76, 225, 110, 226, 238, 115>>
        == Crypto.auth_key_hash(auth_key_bytes)
  end

  test "#make_nonce_hash1" do
    {:ok, auth_key_bytes} = Base.decode16(
      <<"AB96E207C631300986F30EF97DF55E179E63C112675F0CE502EE76D74BBEE6CBD1E957",
        "72818881E9F2FF54BD52C258787474F6A7BEA61EABE49D1D01D55F64FC07BC31685716",
        "EC8FB46FEACF9502E42CFD6B9F45A08E90AA5C2B5933AC767CBE1CD50D8E64F89727CA",
        "4A1A5D32C0DB80A9FCDBDDD4F8D5A1E774198F1A4299F927C484FEEC395F29647E43C3",
        "243986F93609E23538C21871DF50E00070B3B6A8FA9BC15628E8B43FF977409A61CEEC",
        "5A21CF7DFB5A4CC28F5257BC30CD8F2FB92FBF21E28924065F50E0BBD5E11A420300E2",
        "C136B80E9826C6C5609B5371B7850AA628323B6422F3A94F6DFDE4C3DC1EA60F7E11EE",
        "63122B3F39CBD1A8430157">>)
    {:ok, new_nonce_bytes} = Base.decode16(
      <<"311C85DB234AA2640AFC4A76A735CF5B1F0FD68BD17FA181E1229AD867CC024D">>)

    assert <<204, 235, 192, 33, 114, 102, 225, 237, 236, 127, 176, 160, 238, 214, 194, 32>>
        == Crypto.make_nonce_hash1(new_nonce_bytes, auth_key_bytes)
  end

  test "#make_server_salt" do
    {:ok, server_nonce_bytes} = Base.decode16("A5CF4D33F4A11EA877BA4AA573907330")
    {:ok, new_nonce_bytes} = Base.decode16(
      <<"311C85DB234AA2640AFC4A76A735CF5B1F0FD68BD17FA181E1229AD867CC024D">>)

    assert <<148, 211, 200, 232, 215, 235, 188, 204>>
        == Crypto.make_server_salt(new_nonce_bytes, server_nonce_bytes)
  end
end