defmodule MTProto.MathTest do
  use ExUnit.Case
  alias MTProto.Math

  test "#factorize" do
    # Sample PQ and P, Q numbers from [1]
    # 1. https://core.telegram.org/mtproto/samples-auth_key#3-pq-17ed48941a08f981-decomposed-into-2-prime-cofactors
    {:ok, pq_bytes} = Base.decode16("17ED48941A08F981")
    {:ok, p_bytes} = Base.decode16("494C553B")
    {:ok, q_bytes} = Base.decode16("53911073")

    <<pq :: 64>> = pq_bytes
    <<p :: 32>> = p_bytes
    <<q :: 32>> = q_bytes

    assert [p, q] == Math.factorize(pq)
  end

  test "#make_b"

  test "#make_g_b" do
    g = 2
    {:ok, b_bytes} = Base.decode16(
      <<"6F620AFA575C9233EB4C014110A7BCAF49464F798A18A0981FEA1E05E8DA67D9681E0FD6DF0EDF02",
        "72AE3492451A84502F2EFC0DA18741A5FB80BD82296919A70FAA6D07CBBBCA2037EA7D3E327B61D5",
        "85ED3373EE0553A91CBD29B01FA9A89D479CA53D57BDE3A76FBD922A923A0A38B922C1D0701F53FF",
        "52D7EA9217080163A64901E766EB6A0F20BC391B64B9D1DD2CD13A7D0C946A3A7DF8CEC9E2236446",
        "F646C42CFE2B60A2A8D776E56C8D7519B08B88ED0970E10D12A8C9E355D765F2B7BBB7B4CA936008",
        "3435523CB0D57D2B106FD14F94B4EEE79D8AC131CA56AD389C84FE279716F8124A543337FB9EA3D9",
        "88EC5FA63D90A4BA3970E7A39E5C0DE5">>)
    {:ok, dh_prime_bytes} = Base.decode16(
      <<"C71CAEB9C6B1C9048E6C522F70F13F73980D40238E3E21C14934D037563D930F48198A",
        "0AA7C14058229493D22530F4DBFA336F6E0AC925139543AED44CCE7C3720FD51F69458",
        "705AC68CD4FE6B6B13ABDC9746512969328454F18FAF8C595F642477FE96BB2A941D5B",
        "CD1D4AC8CC49880708FA9B378E3C4F3A9060BEE67CF9A4A4A695811051907E162753B5",
        "6B0F6B410DBA74D8A84B2A14B3144E0EF1284754FD17ED950D5965B4B9DD46582DB117",
        "8D169C6BC465B0D6FF9CA3928FEF5B9AE4E418FC15E83EBEA0F87FA9FF5EED70050DED",
        "2849F47BF959D956850CE929851F0D8115F635B105EE2E4E15D04B2454BF6F4FADF034",
        "B10403119CD8E3B92FCC5B">>)
    {:ok, gb_bytes} = Base.decode16(
      <<"73700E7BFC7AEEC828EB8E0DCC04D09A0DD56A1B4B35F72F0B55FCE7DB7EBB72D7C33C",
        "5D4AA59E1C74D09B01AE536B318CFED436AFDB15FE9EB4C70D7F0CB14E46DBBDE9053A",
        "64304361EB358A9BB32E9D5C2843FE87248B89C3F066A7D5876D61657ACC52B0D81CD6",
        "83B2A0FA93E8ADAB20377877F3BC3369BBF57B10F5B589E65A9C27490F30A0C70FFCFD",
        "3453F5B379C1B9727A573CFFDCA8D23C721B135B92E529B1CDD2F7ABD4F34DAC4BE1EE",
        "AF60993DDE8ED45890E4F47C26F2C0B2E037BB502739C8824F2A99E2B1E7E416583417",
        "CC79A8807A4BDAC6A5E9805D4F6186C37D66F6988C9F9C752896F3D34D25529263FAF2",
        "670A09B2A59CE35264511F">>)

    assert gb_bytes == Math.make_g_b(g, b_bytes, dh_prime_bytes)
  end

  test "#make_auth_key" do
    {:ok, b_bytes} = Base.decode16(
      <<"6F620AFA575C9233EB4C014110A7BCAF49464F798A18A0981FEA1E05E8DA67D9681E0FD6DF0EDF02",
        "72AE3492451A84502F2EFC0DA18741A5FB80BD82296919A70FAA6D07CBBBCA2037EA7D3E327B61D5",
        "85ED3373EE0553A91CBD29B01FA9A89D479CA53D57BDE3A76FBD922A923A0A38B922C1D0701F53FF",
        "52D7EA9217080163A64901E766EB6A0F20BC391B64B9D1DD2CD13A7D0C946A3A7DF8CEC9E2236446",
        "F646C42CFE2B60A2A8D776E56C8D7519B08B88ED0970E10D12A8C9E355D765F2B7BBB7B4CA936008",
        "3435523CB0D57D2B106FD14F94B4EEE79D8AC131CA56AD389C84FE279716F8124A543337FB9EA3D9",
        "88EC5FA63D90A4BA3970E7A39E5C0DE5">>)
    {:ok, dh_prime_bytes} = Base.decode16(
      <<"C71CAEB9C6B1C9048E6C522F70F13F73980D40238E3E21C14934D037563D930F48198A",
        "0AA7C14058229493D22530F4DBFA336F6E0AC925139543AED44CCE7C3720FD51F69458",
        "705AC68CD4FE6B6B13ABDC9746512969328454F18FAF8C595F642477FE96BB2A941D5B",
        "CD1D4AC8CC49880708FA9B378E3C4F3A9060BEE67CF9A4A4A695811051907E162753B5",
        "6B0F6B410DBA74D8A84B2A14B3144E0EF1284754FD17ED950D5965B4B9DD46582DB117",
        "8D169C6BC465B0D6FF9CA3928FEF5B9AE4E418FC15E83EBEA0F87FA9FF5EED70050DED",
        "2849F47BF959D956850CE929851F0D8115F635B105EE2E4E15D04B2454BF6F4FADF034",
        "B10403119CD8E3B92FCC5B">>)
    {:ok, g_a_bytes} = Base.decode16(
      <<"262AABA621CC4DF587DC94CF8252258C0B9337DFB47545A49CDD5C9B8EAE7236C6CADC",
        "40B24E88590F1CC2CC762EBF1CF11DCC0B393CAAD6CEE4EE5848001C73ACBB1D127E4C",
        "B93072AA3D1C8151B6FB6AA6124B7CD782EAF981BDCFCE9D7A00E423BD9D194E8AF78E",
        "F6501F415522E44522281C79D906DDB79C72E9C63D83FB2A940FF779DFB5F2FD786FB4",
        "AD71C9F08CF48758E534E9815F634F1E3A80A5E1C2AF210C5AB762755AD4B2126DFA61",
        "A77FA9DA967D65DFD0AFB5CDF26C4D4E1A88B180F4E0D0B45BA1484F95CB2712B50BF3",
        "F5968D9D55C99C0FB9FB67BFF56D7D4481B634514FBA3488C4CDA2FC0659990E8E868B",
        "28632875A9AA703BCDCE8F">>)

    {:ok, auth_key_bytes} = Base.decode16(
      <<"AB96E207C631300986F30EF97DF55E179E63C112675F0CE502EE76D74BBEE6CBD1E957",
        "72818881E9F2FF54BD52C258787474F6A7BEA61EABE49D1D01D55F64FC07BC31685716",
        "EC8FB46FEACF9502E42CFD6B9F45A08E90AA5C2B5933AC767CBE1CD50D8E64F89727CA",
        "4A1A5D32C0DB80A9FCDBDDD4F8D5A1E774198F1A4299F927C484FEEC395F29647E43C3",
        "243986F93609E23538C21871DF50E00070B3B6A8FA9BC15628E8B43FF977409A61CEEC",
        "5A21CF7DFB5A4CC28F5257BC30CD8F2FB92FBF21E28924065F50E0BBD5E11A420300E2",
        "C136B80E9826C6C5609B5371B7850AA628323B6422F3A94F6DFDE4C3DC1EA60F7E11EE",
        "63122B3F39CBD1A8430157">>)

    assert auth_key_bytes
        == Math.make_auth_key(g_a_bytes, b_bytes, dh_prime_bytes)
  end

  test "#make_message_id_time"
  test "#make_message_id"
  test "#binary_bxor"
  test "#bor1"
end