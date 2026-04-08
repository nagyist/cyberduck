package ch.cyberduck.core.cryptomator.impl.uvf;

/*
 * Copyright (c) 2002-2026 iterate GmbH. All rights reserved.
 * https://cyberduck.io/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

import org.junit.Test;

import com.nimbusds.jose.JWEObjectJSON;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;

import static org.junit.Assert.assertArrayEquals;

public class JWKSetUVFVaultMetadataProviderTest {

    final String jwe = "{\n" +
            "  \"ciphertext\": \"eQ2THqVXAK58w_hEaJhjlEOWSO4CDYQnle4mEDb50qSoVsZ8JnKd3wCrhxrjQPzz_T9eIej_eZH8FZ9h6PWUSeraOr5GHiQ_UjRqrRQEHSFRf3OBHFv2vHMljDzR5CDsLtzEcsW07zlAvgTns8D1P9uAFzjcttMcDxHjbywSwySH1v8ZS4mcCmh5AyF1RdzxZaj3hH7n7Aga6rUuPV6kYQu18AZS0OB97mtXpNRjI5is5zefr_Jc5jal1gux6KZ_wvBbmVFde34cVFKyvBHIbRVMvoN-yFTXY0voDw1uOrOOR4u6Bbyy7Xt4UwdrLXlsC97m-XBD6ntZVgfSXY088m7m8Zfr0bHEdU2QlaO4TR-QAKwZV9Pc93vyl9WXlVzrc2eYE3ahl8D8jG8BSMVMu5AiMZBZHOwpg1LCydccZIIby8STTfu4lxfHhqRB1T3Sn-96ys_5VC2ljlsFXr2kZhHXePr3V6TgXJEYtom0C0pnJJOGZ4D1tuV1ATP7HjCl1ZJYjFUXSMDC36QlB_yPbgjV4_yulLMRaRLohazSgOG_Rqp2pYlsZEXsrXIgnJvjmH5XaJS253tioes66swH5med6LY4RddcklZAUgNUwgA6Hrz8gSgeDHNxcZpv3UJtbUVF6i5i_k0b0VfAbH7HhZwE8zfuyaEPhNQeHFCNtP8Cx5Fzmo_BDpDevWhhBsPqg0C4klnBgRJoIrSFOwC2lgDgOU1HqY9D2nIIGB6ydE42e_olx64OF9ejcT8\",\n" +
            "  \"protected\": \"eyJ1dmYuc3BlYy52ZXJzaW9uIjoxLCJjdHkiOiJqc29uIiwiZW5jIjoiQTI1NkdDTSIsImNyaXQiOlsidXZmLnNwZWMudmVyc2lvbiJdLCJqa3UiOiJqd2tzLmpzb24iLCJjbG91ZC5rYXR0YS5vcmlnaW4iOiJodHRwczovL2V4YW1wbGUuY29tL2dhdGV3YXkvYXBpL3ZhdWx0cy9jZTFjMDAyZC01ZTQ4LTQ4MzktOTFhYy05ZDU4NmRmY2EyODAvdXZmL3ZhdWx0LnV2ZiJ9\",\n" +
            "  \"recipients\":\n" +
            "    [\n" +
            "      {\n" +
            "        \"encrypted_key\": \"8D5sicCjOKxZg7s-YhcgBKD2SS5I8vYndoJ-n6QTgZVbR9kKKLF14w\",\n" +
            "        \"header\": { \"alg\": \"A256KW\", \"kid\": \"org.cryptomator.hub.memberkey\" }\n" +
            "      },\n" +
            "      {\n" +
            "        \"encrypted_key\": \"JV7oU02ZNRRE3vBCr5Y4xLxj5FbSvHRJtl4mRCPdq_XvK-M4cO06HQ\",\n" +
            "        \"header\":\n" +
            "          {\n" +
            "            \"epk\":\n" +
            "              {\n" +
            "                \"kty\": \"EC\",\n" +
            "                \"crv\": \"P-384\",\n" +
            "                \"x\": \"R5RmzCeRY9W1Ppne5qzI6LmngOqXn_AWDFecgjM7Czj-LcISnr5-bGakgrG6Tzwq\",\n" +
            "                \"y\": \"u82mFKUdm1tIHR9Odcy61m4OG0okOV22cgTjAxaxKpMdgydLwQgLCFEhO-AsKJ_Q\"\n" +
            "              },\n" +
            "            \"alg\": \"ECDH-ES+A256KW\",\n" +
            "            \"kid\": \"org.cryptomator.hub.recoverykey.Dt9mG3_scsyFbHMo3gEIpsEuseYOVSYnPFp33Wy84f0\"\n" +
            "          }\n" +
            "      }\n" +
            "    ],\n" +
            "  \"tag\": \"74MqMasCFF6I35662Ta8Lw\",\n" +
            "  \"iv\": \"Tj-UdKHo6at0uJ89\"\n" +
            "}\n";

    final String memberKey = "{\"kty\":\"oct\",\"kid\":\"org.cryptomator.hub.memberkey\",\"k\":\"Cef44vELUgYnhdijvVex7_20QsSytylDbvyOR1083uA\",\"alg\":\"A256KW\"}";

    @Test
    public void testMultiDecrypt() throws Exception {
        final JWEObjectJSON jweObject = JWEObjectJSON.parse(jwe);
        final JWKSetUVFVaultMetadataProvider provider = new JWKSetUVFVaultMetadataProvider(jweObject, new JWKSet(JWK.parse(memberKey)));
        final byte[] b1 = provider.decrypt();
        final byte[] b2 = provider.decrypt();
        assertArrayEquals(b1, b2);
    }

}