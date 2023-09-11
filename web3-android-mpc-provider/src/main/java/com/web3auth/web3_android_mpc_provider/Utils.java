package com.web3auth.web3_android_mpc_provider;

import com.web3auth.tss_client_android.client.EndpointsData;

import org.web3j.crypto.Keys;

import java.util.ArrayList;
import java.util.List;

public class Utils {

    public static String generateAddressFromPubKey(String pubKey) {
        return Keys.toChecksumAddress(Keys.getAddress(pubKey));
    }

    public static String stringToHex(String str) {
        char[] chars = str.toCharArray();
        StringBuffer strBuffer = new StringBuffer();
        for (int i = 0; i < chars.length; i++) {
            strBuffer.append(Integer.toHexString((int) chars[i]));
        }
        return strBuffer.toString();
    }

    public static String padLeft(String inputString, Character padChar, int length) {
        if (inputString.length() >= length) return inputString;
        StringBuilder sb = new StringBuilder();
        while (sb.length() < length - inputString.length()) {
            sb.append(padChar);
        }
        sb.append(inputString);
        return sb.toString();
    }

    public static byte[] convertToBytes(String s) {
        String tmp;
        byte[] b = new byte[s.length() / 2];
        int i;
        for (i = 0; i < s.length() / 2; i++) {
            tmp = s.substring(i * 2, i * 2 + 2);
            b[i] = (byte) (Integer.parseInt(tmp, 16) & 0xff);
        }
        return b;
    }

    public static EndpointsData generateEndpoints(int parties, int clientIndex, List<String> tssEndpoints) {
        List<String> endpoints = new ArrayList();
        List<String> tssWSEndpoints = new ArrayList();
        List<Integer> partyIndexes = new ArrayList();

        for (int i = 0; i < parties; ++i) {
            partyIndexes.add(i);
            if (i == clientIndex) {
                endpoints.add(null);
                tssWSEndpoints.add(null);
            } else {
                endpoints.add(tssEndpoints.get(i));
                tssWSEndpoints.add(tssEndpoints.get(i).replace("/tss", ""));
            }
        }

        return new EndpointsData(endpoints, tssWSEndpoints, partyIndexes);
    }
}
