package com.web3auth.web3_android_mpc_provider;

public class EthereumSignerError extends Error {
    private ErrorType errorType;

    public EthereumSignerError(ErrorType errorType) {
        this.errorType = errorType;
    }

    public String getErrorDescription() {
        switch (errorType) {
            case EMPTY_RAW_TRANSACTION:
                return "emptyRawTransaction";
            case INSUFFICIENT_Funds:
                return "insufficientFunds";
            case UNKNOWN_ERROR:
                return "unknownError";
            default:
                return "unknown error";
        }
    }

    public enum ErrorType {
        EMPTY_RAW_TRANSACTION,
        INSUFFICIENT_Funds,
        UNKNOWN_ERROR
    }
}

