package com.web3auth.web3_android_mpc_provider;

public class CustomSigningError extends Exception {
    private final String message;

    public CustomSigningError(String message) {
        this.message = message;
    }

    @Override
    public String getMessage() {
        return message;
    }
}
