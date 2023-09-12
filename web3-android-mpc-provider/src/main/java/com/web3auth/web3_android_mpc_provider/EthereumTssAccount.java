package com.web3auth.web3_android_mpc_provider;

import static org.web3j.utils.Numeric.hexStringToByteArray;

import android.util.Base64;
import android.util.Pair;

import androidx.annotation.Nullable;

import com.web3auth.tss_client_android.client.EndpointsData;
import com.web3auth.tss_client_android.client.TSSClient;
import com.web3auth.tss_client_android.client.TSSClientError;
import com.web3auth.tss_client_android.client.TSSHelpers;
import com.web3auth.tss_client_android.client.util.Secp256k1;
import com.web3auth.tss_client_android.client.util.Triple;
import com.web3auth.tss_client_android.dkls.Precompute;

import org.web3j.crypto.Hash;
import org.web3j.crypto.Keys;
import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.Sign;
import org.web3j.crypto.StructuredDataEncoder;
import org.web3j.crypto.TransactionEncoder;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.utils.Convert;
import org.web3j.utils.Numeric;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class EthereumTssAccount {

    public EthTssAccountParams ethAccountParams;
    public String evmAddress;

    public EthereumTssAccount(EthTssAccountParams params) {
        ethAccountParams = params;
        String prefix = "04";
        String key;
        if (params.publicKey.startsWith(prefix)) {
            key = params.publicKey.substring(prefix.length());
        } else {
            key = params.publicKey;
        }
        evmAddress = Keys.toChecksumAddress(Keys.getAddress(key));
    }

    public String signMessage(String message) throws TSSClientError, CustomSigningError {
        String hash = TSSHelpers.hashMessage(message);
        Triple<BigInteger, BigInteger, Byte> signatureResult = sign(hash);
        Byte v = signatureResult.getThird();
        if (v < 27) {
            v = (byte) (v + 27);
        }
        return TSSHelpers.hexSignature(signatureResult.getFirst(), signatureResult.getSecond(), v);
    }

    public String signTypedData(String jsonData) throws IOException, TSSClientError, CustomSigningError {
        StructuredDataEncoder dataEncoder = new StructuredDataEncoder(jsonData);
        byte[] hashStructuredData = dataEncoder.hashStructuredData();
        String structuredData = android.util.Base64.encodeToString(hashStructuredData, Base64.NO_WRAP);
        Triple<BigInteger, BigInteger, Byte> signatureResult = sign(structuredData);
        Byte v = signatureResult.getThird();
        if (v < 27) {
            v = (byte) (v + 27);
        }
        return TSSHelpers.hexSignature(signatureResult.getFirst(), signatureResult.getSecond(), v);
    }


    public String signLegacyTransaction(BigInteger chainID, String toAddress, Double amount, @Nullable String data, BigInteger nonce, BigInteger gasLimit) throws TSSClientError, CustomSigningError {
        BigInteger value = Convert.toWei(Double.toString(amount), Convert.Unit.ETHER).toBigInteger();

        // todo: this appears to be a bug in web3j, if data is null it throws but is marked as nullable
        String txData = "";
        if (data != null) {
            txData = data;
        }

        RawTransaction rawTransaction = RawTransaction.createTransaction(
                chainID,
                nonce,
                gasLimit,
                toAddress,
                value,
                txData
        );

        byte[] encodedTransaction = TransactionEncoder.encode(rawTransaction);
        String encodedTransactionString = Base64.encodeToString(Hash.sha3(encodedTransaction), Base64.NO_WRAP);

        Triple<BigInteger, BigInteger, Byte> signatureResult = sign(encodedTransactionString);

        Byte v = signatureResult.getThird();
        if (v < 27) {
            v = (byte) ((chainID.byteValue() * 2) + (v + 35));
        }

        Sign.SignatureData signatureData = new Sign.SignatureData(v,
                signatureResult.getSecond().toByteArray(),
                signatureResult.getFirst().toByteArray());

        byte[] signedMsg = TransactionEncoder.encode(rawTransaction, signatureData);

        return Numeric.toHexString(signedMsg);
    }

    public String signTransaction(BigInteger chainID, String toAddress, Double amount, @Nullable String data, BigInteger nonce, BigInteger gasLimit, BigInteger maxPriorityFeePerGas, BigInteger maxFeePerGas) throws TSSClientError, CustomSigningError, SignatureException {
        BigInteger value = Convert.toWei(Double.toString(amount), Convert.Unit.ETHER).toBigInteger();

        String txData = "";
        if (data != null) {
            txData = data;
        }

        RawTransaction rawTransaction = RawTransaction.createTransaction(
                chainID.longValue(),
                nonce,
                gasLimit,
                toAddress,
                value,
                txData,
                maxPriorityFeePerGas,
                maxFeePerGas
        );

        byte[] encodedTransaction = TransactionEncoder.encode(rawTransaction);
        String encodedTransactionString = Base64.encodeToString(Hash.sha3(encodedTransaction), Base64.NO_WRAP);

        Triple<BigInteger, BigInteger, Byte> signatureResult = sign(encodedTransactionString);

        Byte v = signatureResult.getThird();
        if (v < 27) {
            v = (byte) ((chainID.byteValue() * 2) + (v + 35));
        }

        Sign.SignatureData signatureData = new Sign.SignatureData(v,
                signatureResult.getSecond().toByteArray(),
                signatureResult.getFirst().toByteArray());

        byte[] signedMsg = TransactionEncoder.encode(rawTransaction, signatureData);

        return Numeric.toHexString(signedMsg);
    }

    public void sendTransaction(Web3j web3j, String signedTx) throws IOException, CustomSigningError {
        EthSendTransaction ethSendTransaction = web3j.ethSendRawTransaction(signedTx).send();
        if (ethSendTransaction.getError() != null) {
            throw new CustomSigningError(ethSendTransaction.getError().getMessage());
        }
    }

    private Triple<BigInteger, BigInteger, Byte> sign(String hash) throws TSSClientError, CustomSigningError {
        TSSClient client;
        Map<String, String> coeffs;
        Pair<TSSClient, Map<String, String>> clientCoeffsPair;

        clientCoeffsPair = bootstrapTssClient(ethAccountParams);
        client = clientCoeffsPair.first;
        coeffs = clientCoeffsPair.second;

        boolean connected = client.checkConnected();
        if (!connected) {
            throw new CustomSigningError("Unable to establish connection to TSS server");
        }

        Precompute precompute;
        precompute = client.precompute(coeffs, Arrays.asList(ethAccountParams.authSigs));

        boolean ready = client.isReady();
        if (!ready) {
            throw new EthereumSignerError(EthereumSignerError.ErrorType.UNKNOWN_ERROR);
        }

        Triple<BigInteger, BigInteger, Byte> signatureResult;
        signatureResult = client.sign(hash, true, null, precompute, Arrays.asList(ethAccountParams.authSigs));

        client.cleanup(ethAccountParams.authSigs);

        boolean verified = TSSHelpers.verifySignature(hash, signatureResult.getFirst(),
                signatureResult.getSecond(), signatureResult.getThird(), Utils.convertToBytes(ethAccountParams.publicKey));

        if (!verified) {
            throw new EthereumSignerError(EthereumSignerError.ErrorType.UNKNOWN_ERROR);
        }

        return signatureResult;
    }

    private Pair<TSSClient, Map<String, String>> bootstrapTssClient(EthTssAccountParams params) throws CustomSigningError, TSSClientError {
        if (params.publicKey.length() < 128 || params.publicKey.length() > 130) {
            throw new CustomSigningError("Public Key should be in uncompressed format");
        }

        BigInteger randomKey = new BigInteger(1, Secp256k1.GenerateECKey());
        BigInteger random = randomKey.add(BigInteger.valueOf(System.currentTimeMillis() / 1000));
        String sessionNonce = TSSHelpers.base64ToBase64url(TSSHelpers.hashMessage(Arrays.toString(random.toByteArray())));
        String session = TSSHelpers.assembleFullSession(params.verifier, params.verifierID,
                params.selectedTag, String.valueOf(params.tssNonce), sessionNonce);

        BigInteger userTssIndex = new BigInteger(params.tssIndex, 16);
        int parties = 4;
        int clientIndex = parties - 1;

        EndpointsData endpointsData = generateEndpoints(parties, clientIndex, Arrays.asList(params.tssEndpoints));
        List<String> endpoints = endpointsData.getEndpoints();
        List<String> socketUrls = endpointsData.getTssWSEndpoints();
        List<Integer> partyIndexes = endpointsData.getPartyIndexes();
        List<BigInteger> nodeInd = new ArrayList<>();
        nodeInd.add(new BigInteger("1"));
        nodeInd.add(new BigInteger("2"));
        nodeInd.add(new BigInteger("3"));

        Map<String, String> coeffs = TSSHelpers.getServerCoefficients(nodeInd.toArray(new BigInteger[0]), userTssIndex);

        BigInteger share = new BigInteger(params.tssShare, 16);
        BigInteger denormalizeShare = TSSHelpers.denormalizeShare(nodeInd.toArray(new BigInteger[0]), userTssIndex, share);

        TSSClient client = new TSSClient(session, clientIndex, partyIndexes.stream().mapToInt(Integer::intValue).toArray(),
                endpoints.toArray(new String[0]), socketUrls.toArray(new String[0]), TSSHelpers.base64Share(denormalizeShare),
                TSSHelpers.base64PublicKey(hexStringToByteArray(params.publicKey)));

        return new Pair<>(client, coeffs);
    }


    private EndpointsData generateEndpoints(int parties, int clientIndex, List<String> tssEndpoints) {
        List<String> endpoints = new ArrayList<>();
        List<String> tssWSEndpoints = new ArrayList<>();
        List<Integer> partyIndexes = new ArrayList<>();

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
