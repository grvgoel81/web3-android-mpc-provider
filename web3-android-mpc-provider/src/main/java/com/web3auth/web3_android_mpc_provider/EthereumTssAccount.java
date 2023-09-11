package com.web3auth.web3_android_mpc_provider;

import static com.web3auth.web3_android_mpc_provider.Utils.generateEndpoints;
import static org.web3j.utils.Numeric.hexStringToByteArray;

import android.util.Base64;
import android.util.Pair;

import com.web3auth.tss_client_android.client.EndpointsData;
import com.web3auth.tss_client_android.client.TSSClient;
import com.web3auth.tss_client_android.client.TSSClientError;
import com.web3auth.tss_client_android.client.TSSHelpers;
import com.web3auth.tss_client_android.client.util.Secp256k1;
import com.web3auth.tss_client_android.client.util.Triple;
import com.web3auth.tss_client_android.dkls.Precompute;

import org.web3j.crypto.Hash;
import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.Sign;
import org.web3j.crypto.TransactionEncoder;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.response.EthChainId;
import org.web3j.protocol.core.methods.response.EthGasPrice;
import org.web3j.protocol.core.methods.response.EthGetTransactionCount;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.protocol.http.HttpService;
import org.web3j.utils.Convert;
import org.web3j.utils.Numeric;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class EthereumTssAccount {

    public EthTssAccountParams ethAccountParams;
    public String evmAddress;

    public EthereumTssAccount(EthTssAccountParams params) {
        ethAccountParams = params;
        evmAddress = Utils.generateAddressFromPubKey(params.getPublicKey());
    }

    public String signMessage(String message) {
        String signature = null;
        TSSClient client;
        Map<String, String> coeffs;
        Pair<TSSClient, Map<String, String>> clientCoeffsPair;
        try {
            clientCoeffsPair = bootstrapTssClient(ethAccountParams);
            client = clientCoeffsPair.first;
            coeffs = clientCoeffsPair.second;

            boolean connected = client.checkConnected();
            if (!connected) {
                throw new CustomSigningError("Unable to establish connection to TSS server");
            }

            Precompute precompute;
            try {
                precompute = client.precompute(coeffs, Arrays.asList(ethAccountParams.getAuthSigs()));
            } catch (Exception e) {
                e.printStackTrace();
                throw new EthereumSignerError(EthereumSignerError.ErrorType.UNKNOWN_ERROR);
            }

            boolean ready = client.isReady();
            if (!ready) {
                throw new EthereumSignerError(EthereumSignerError.ErrorType.UNKNOWN_ERROR);
            }

            String signingMessage = TSSHelpers.hashMessage(message);

            Triple<BigInteger, BigInteger, Byte> signatureResult;
            try {
                signatureResult = client.sign(signingMessage, true, "", precompute, Arrays.asList(ethAccountParams.getAuthSigs()));
            } catch (TSSClientError e) {
                throw new RuntimeException(e);
            }

            try {
                client.cleanup(ethAccountParams.getAuthSigs());
            } catch (TSSClientError e) {
                throw new RuntimeException(e);
            }

            boolean verified = TSSHelpers.verifySignature(signingMessage, signatureResult.getFirst(),
                    signatureResult.getSecond(), signatureResult.getThird(), Utils.convertToBytes(ethAccountParams.getPublicKey()));

            if (!verified) {
                throw new EthereumSignerError(EthereumSignerError.ErrorType.UNKNOWN_ERROR);
            }

            signature = TSSHelpers.hexSignature(signatureResult.getFirst(), signatureResult.getSecond(), signatureResult.getThird());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return signature;
    }

    public String signAndSendTransaction(String url, Double amount, String fromAddress, String toAddress) {
        String transactionHash;
        TSSClient client;
        Map<String, String> coeffs;
        Pair<TSSClient, Map<String, String>> clientCoeffsPair;
        try {
            //setup Web3j
            Web3j web3j = Web3j.build(new HttpService(url));
            EthGetTransactionCount ethGetTransactionCount = web3j.ethGetTransactionCount(
                    fromAddress,
                    DefaultBlockParameterName.LATEST
            ).send();
            BigInteger nonce = ethGetTransactionCount.getTransactionCount();
            BigInteger value = Convert.toWei(Double.toString(amount), Convert.Unit.ETHER).toBigInteger();
            BigInteger gasLimit = BigInteger.valueOf(21000);
            EthGasPrice gasPriceResponse = web3j.ethGasPrice().send();
            BigInteger gasPrice = gasPriceResponse.getGasPrice();
            EthChainId chainIdResponse = web3j.ethChainId().sendAsync().get();
            BigInteger chainId = chainIdResponse.getChainId();

            RawTransaction rawTransaction = RawTransaction.createTransaction(
                    chainId.longValue(),
                    nonce,
                    gasLimit,
                    toAddress,
                    value,
                    "",
                    gasPrice,
                    gasPrice
            );

            clientCoeffsPair = bootstrapTssClient(ethAccountParams);
            client = clientCoeffsPair.first;
            coeffs = clientCoeffsPair.second;

            boolean connected = client.checkConnected();
            if (!connected) {
                throw new CustomSigningError("Unable to establish connection to TSS server");
            }

            Precompute precompute;
            try {
                precompute = client.precompute(coeffs, Arrays.asList(ethAccountParams.getAuthSigs()));
            } catch (Exception e) {
                e.printStackTrace();
                throw new EthereumSignerError(EthereumSignerError.ErrorType.UNKNOWN_ERROR);
            }

            boolean ready = client.isReady();
            if (!ready) {
                throw new EthereumSignerError(EthereumSignerError.ErrorType.UNKNOWN_ERROR);
            }

            byte[] encodedTransaction = TransactionEncoder.encode(rawTransaction);
            String encodedTransactionString = Base64.encodeToString(Hash.sha3(encodedTransaction), Base64.NO_WRAP);


            Triple<BigInteger, BigInteger, Byte> signatureResult;
            try {
                signatureResult = client.sign(encodedTransactionString, true, "", precompute, Arrays.asList(ethAccountParams.getAuthSigs()));
            } catch (TSSClientError e) {
                throw new RuntimeException(e);
            }

            try {
                client.cleanup(ethAccountParams.getAuthSigs());
            } catch (TSSClientError e) {
                throw new RuntimeException(e);
            }

            try {
                Sign.SignatureData signatureData = new Sign.SignatureData((byte) (signatureResult.getThird() + 27),
                        signatureResult.getSecond().toByteArray(),
                        signatureResult.getFirst().toByteArray());
                byte[] signedMsg = TransactionEncoder.encode(rawTransaction, signatureData);

                String finalSig = Numeric.toHexString(signedMsg);

                EthSendTransaction ethSendTransaction = web3j.ethSendRawTransaction(finalSig).send();
                if (ethSendTransaction.getError() != null) {
                    transactionHash = ethSendTransaction.getError().getMessage();
                } else {
                    transactionHash = ethSendTransaction.getTransactionHash();
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return transactionHash;
    }


    private Pair<TSSClient, Map<String, String>> bootstrapTssClient(EthTssAccountParams params) throws CustomSigningError, TSSClientError {
        if (params.getPublicKey().length() < 128 || params.getPublicKey().length() > 130) {
            throw new CustomSigningError("Public Key should be in uncompressed format");
        }

        BigInteger randomKey = new BigInteger(1, Secp256k1.GenerateECKey());
        BigInteger random = randomKey.add(BigInteger.valueOf(System.currentTimeMillis() / 1000));
        String sessionNonce = TSSHelpers.base64ToBase64url(TSSHelpers.hashMessage(random.toByteArray().toString()));
        String session = TSSHelpers.assembleFullSession(params.getVerifier(), params.getVerifierID(),
                params.getSelectedTag(), String.valueOf(params.getTssNonce()), sessionNonce);

        BigInteger userTssIndex = new BigInteger(params.getTssIndex(), 16);
        int parties = 4;
        int clientIndex = parties - 1;

        EndpointsData endpointsData = generateEndpoints(parties, clientIndex, Arrays.asList(params.getTssEndpoints()));
        List<String> endpoints = endpointsData.getEndpoints();
        List<String> socketUrls = endpointsData.getTssWSEndpoints();
        List<Integer> partyIndexes = endpointsData.getPartyIndexes();
        List<BigInteger> nodeInd = new ArrayList<>();
        nodeInd.add(new BigInteger("1"));
        nodeInd.add(new BigInteger("2"));
        nodeInd.add(new BigInteger("3"));

        Map<String, String> coeffs = TSSHelpers.getServerCoefficients(nodeInd.toArray(new BigInteger[0]), userTssIndex);

        BigInteger shareUnsigned = new BigInteger(params.getTssShare(), 16);
        BigInteger share = shareUnsigned;
        BigInteger denormalizeShare = TSSHelpers.denormalizeShare(nodeInd.toArray(new BigInteger[0]), userTssIndex, share);

        TSSClient client = new TSSClient(session, clientIndex, partyIndexes.stream().mapToInt(Integer::intValue).toArray(),
                endpoints.toArray(new String[0]), socketUrls.toArray(new String[0]), TSSHelpers.base64Share(denormalizeShare),
                TSSHelpers.base64PublicKey(hexStringToByteArray(params.getPublicKey())));

        return new Pair<>(client, coeffs);
    }
}
