package com.web3auth.web3_android_mpc_provider;

import java.math.BigInteger;

public final class EthTssAccountParams {
    private String publicKey;
    private String factorKey;
    private int tssNonce;
    private String tssShare;
    private String tssIndex;
    private String selectedTag;
    private String verifier;
    private String verifierID;
    private BigInteger[] nodeIndexes;
    private String[] tssEndpoints;
    private String[] authSigs;

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

    public String getPublicKey() {
        return publicKey;
    }

    public String getFactorKey() {
        return factorKey;
    }

    public int getTssNonce() {
        return tssNonce;
    }

    public String getTssShare() {
        return tssShare;
    }

    public String getTssIndex() {
        return tssIndex;
    }

    public String getSelectedTag() {
        return selectedTag;
    }

    public String getVerifier() {
        return verifier;
    }

    public String getVerifierID() {
        return verifierID;
    }

    public BigInteger[] getNodeIndexes() {
        return nodeIndexes;
    }

    public String[] getTssEndpoints() {
        return tssEndpoints;
    }

    public String[] getAuthSigs() {
        return authSigs;
    }
}

