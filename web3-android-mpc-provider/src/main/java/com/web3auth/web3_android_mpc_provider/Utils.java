package com.web3auth.web3_android_mpc_provider;

public class Utils {
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
}
