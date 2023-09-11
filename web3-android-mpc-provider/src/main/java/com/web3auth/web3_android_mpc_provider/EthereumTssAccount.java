package com.web3auth.web3_android_mpc_provider;

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
import org.web3j.crypto.Keys;
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
import java.util.concurrent.ExecutionException;

public class EthereumTssAccount {

    public EthTssAccountParams ethAccountParams;
    public String evmAddress;

    public EthereumTssAccount(EthTssAccountParams params) {
        ethAccountParams = params;
        evmAddress = Keys.toChecksumAddress(Keys.getAddress(params.publicKey));
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

    public String signAndSendTransaction(String url, Double amount, String toAddress) throws TSSClientError, CustomSigningError, IOException, ExecutionException, InterruptedException {
        //setup Web3j
        Web3j web3j = Web3j.build(new HttpService(url));
        EthGetTransactionCount ethGetTransactionCount = web3j.ethGetTransactionCount(
                evmAddress,
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

        byte[] encodedTransaction = TransactionEncoder.encode(rawTransaction);
        String encodedTransactionString = Base64.encodeToString(Hash.sha3(encodedTransaction), Base64.NO_WRAP);

        Triple<BigInteger, BigInteger, Byte> signatureResult = sign(encodedTransactionString);

        Sign.SignatureData signatureData = new Sign.SignatureData((byte) (signatureResult.getThird() + 27),
                signatureResult.getSecond().toByteArray(),
                signatureResult.getFirst().toByteArray());
        byte[] signedMsg = TransactionEncoder.encode(rawTransaction, signatureData);

        String finalSig = Numeric.toHexString(signedMsg);

        EthSendTransaction ethSendTransaction = web3j.ethSendRawTransaction(finalSig).send();

        if (ethSendTransaction.getError() != null) {
            throw new CustomSigningError(ethSendTransaction.getError().getMessage());
        } else {
            return ethSendTransaction.getTransactionHash();
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
