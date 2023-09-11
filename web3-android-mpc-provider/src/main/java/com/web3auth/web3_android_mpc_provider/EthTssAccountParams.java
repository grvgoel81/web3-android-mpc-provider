package com.web3auth.web3_android_mpc_provider;

import java.math.BigInteger;

public final class EthTssAccountParams {
    final String publicKey;
    final String factorKey;
    final int tssNonce;
    final String tssShare;
    final String tssIndex;
    final String selectedTag;
    final String verifier;
    final String verifierID;
    final BigInteger[] nodeIndexes;
    final String[] tssEndpoints;
    final String[] authSigs;

    public EthTssAccountParams(String publicKey, String factorKey, int tssNonce, String tssShare, String tssIndex, String selectedTag, String verifier, String verifierID, BigInteger[] nodeIndexes, String[] tssEndpoints, String[] authSigs) {
        this.publicKey = publicKey;
        this.factorKey = factorKey;
        this.tssNonce = tssNonce;
        this.tssShare = tssShare;
        this.tssIndex = tssIndex;
        this.selectedTag = selectedTag;
        this.verifier = verifier;
        this.verifierID = verifierID;
        this.nodeIndexes = nodeIndexes;
        this.tssEndpoints = tssEndpoints;
        this.authSigs = authSigs;
    }
}

