package com.web3auth.web3_android_mpc_provider;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.web3auth.tss_client_android.client.TSSClientError;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.response.EthChainId;
import org.web3j.protocol.core.methods.response.EthGasPrice;
import org.web3j.protocol.core.methods.response.EthGetTransactionCount;
import org.web3j.protocol.http.HttpService;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SignatureException;
import java.util.concurrent.ExecutionException;

@RunWith(AndroidJUnit4.class)
public class MpcProviderTests {

    static {
        System.loadLibrary("dkls-native");
    }

    final String example1 = "{\"types\":{\"EIP712Domain\":[{\"name\":\"name\",\"type\":\"string\"},{\"name\":\"version\",\"type\":\"string\"},{\"name\":\"chainId\",\"type\":\"uint256\"},{\"name\":\"verifyingContract\",\"type\":\"address\"}],\"Person\":[{\"name\":\"name\",\"type\":\"string\"},{\"name\":\"wallet\",\"type\":\"address\"}],\"Mail\":[{\"name\":\"from\",\"type\":\"Person\"},{\"name\":\"to\",\"type\":\"Person\"},{\"name\":\"contents\",\"type\":\"string\"}]},\"primaryType\":\"Mail\",\"domain\":{\"name\":\"EtherMail\",\"version\":\"1\",\"chainId\":1,\"verifyingContract\":\"0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC\"},\"message\":{\"from\":{\"name\":\"Account\",\"wallet\":\"0x048975d4997d7578a3419851639c10318db430b6\"},\"to\":{\"name\":\"Bob\",\"wallet\":\"0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB\"},\"contents\":\"Hello,Bob!\"}}";

    final String fullAddress = "04238569d5e12caf57d34fb5b2a0679c7775b5f61fd18cd69db9cc600a651749c3ec13a9367380b7a024a67f5e663f3afd40175c3223da63f6024b05d0bd9f292e";
    final String factorKey = "3b4af35bc4838471f94825f34c4f649904a258c0907d348bed653eb0c94ec6c0";
    final int tssNonce = 0;
    final String tssShare = "4f62ddd962fab8b0777bd18a2e6f3992c7e15ff929df79a15a7046da46af5a05";
    final String tssIndex = "2";
    final String selected_tag = "default";
    final String verifier = "google-lrc";
    final String verifierId = "hqjang95@gmail.com";

    String[] tssEndpoints = {"https://sapphire-1.auth.network/tss",
            "https://sapphire-2.auth.network/tss",
            "https://sapphire-3.auth.network/tss",
            "https://sapphire-4.auth.network/tss",
            "https://sapphire-5.auth.network/tss"};

    String[] sigs = {
            "{\"sig\":\"16de7c5812aedf492e7afe4a9c0607dba6d8d908d30ef1eb2e4761bc300bb3fc62bfbd0e94b03aa5eb496b5ed7adfa4203fa9745d90673cf789d3a989f872ae41b\",\"data\":\"eyJleHAiOjE2OTM0NjYxMTAsInRlbXBfa2V5X3giOiI2MTg3NTM3ZTc1YThhNWQ3NWQzZjhkMGZmYzE4NjMwNTRjYjEzNmE3YzRjYWVjNWRkYjUyZjViNmY1MTcyZDEwIiwidGVtcF9rZXlfeSI6ImFhNTNhNmE2N2YzOTE1NzNmYTA1YTVkZWViZjM2MDVkM2MzODljNjhjMDhlOGI5YzllNDQyODU1ZWYyYWE2ZTkiLCJ2ZXJpZmllcl9uYW1lIjoiZ29vZ2xlLWxyYyIsInZlcmlmaWVyX2lkIjoiaHFqYW5nOTVAZ21haWwuY29tIiwic2NvcGUiOiIifQ==\"}",
            "{\"sig\":\"50a7451f2a8af5f3e193b3e53768e3107f8d606ef5e9ee70aba15fba8e67a1be279d71f8d3b6a954beef5e5119a10195c3017e48b3f0a93b557ed9366ce38f171c\",\"data\":\"eyJleHAiOjE2OTM0NjYxMTAsInRlbXBfa2V5X3giOiI2MTg3NTM3ZTc1YThhNWQ3NWQzZjhkMGZmYzE4NjMwNTRjYjEzNmE3YzRjYWVjNWRkYjUyZjViNmY1MTcyZDEwIiwidGVtcF9rZXlfeSI6ImFhNTNhNmE2N2YzOTE1NzNmYTA1YTVkZWViZjM2MDVkM2MzODljNjhjMDhlOGI5YzllNDQyODU1ZWYyYWE2ZTkiLCJ2ZXJpZmllcl9uYW1lIjoiZ29vZ2xlLWxyYyIsInZlcmlmaWVyX2lkIjoiaHFqYW5nOTVAZ21haWwuY29tIiwic2NvcGUiOiIifQ==\"}",
            "{\"sig\":\"d94979a0f743a8a41630167622c5b443b148f231bb2293e60a17ab4ea7ebdf38713b81b0bc9161ecd3949ddcf8cfca9734f136ba02c2e4e670fb4b8523299ab01b\",\"data\":\"eyJleHAiOjE2OTM0NjYxMTAsInRlbXBfa2V5X3giOiI2MTg3NTM3ZTc1YThhNWQ3NWQzZjhkMGZmYzE4NjMwNTRjYjEzNmE3YzRjYWVjNWRkYjUyZjViNmY1MTcyZDEwIiwidGVtcF9rZXlfeSI6ImFhNTNhNmE2N2YzOTE1NzNmYTA1YTVkZWViZjM2MDVkM2MzODljNjhjMDhlOGI5YzllNDQyODU1ZWYyYWE2ZTkiLCJ2ZXJpZmllcl9uYW1lIjoiZ29vZ2xlLWxyYyIsInZlcmlmaWVyX2lkIjoiaHFqYW5nOTVAZ21haWwuY29tIiwic2NvcGUiOiIifQ==\"}"
    };

    BigInteger[] nodeIndexs = {new BigInteger("1"), new BigInteger("2"), new BigInteger("3")};

    @Test
    public void testSigningMessage() throws TSSClientError, CustomSigningError {
        EthTssAccountParams params = new EthTssAccountParams(
                fullAddress, factorKey, tssNonce, tssShare, tssIndex, selected_tag, verifier, verifierId,
                nodeIndexs, tssEndpoints, sigs);

        EthereumTssAccount account = new EthereumTssAccount(params);

        String msg = "hello world";
        account.signMessage(msg);
    }

    @Test
    public void testSignTypedData() throws TSSClientError, IOException, CustomSigningError {
        EthTssAccountParams params = new EthTssAccountParams(
                fullAddress, factorKey, tssNonce, tssShare, tssIndex, selected_tag, verifier, verifierId,
                nodeIndexs, tssEndpoints, sigs);

        EthereumTssAccount account = new EthereumTssAccount(params);

        account.signTypedData(example1);
    }

    @Test
    public void testSigningLegacyTransaction() throws TSSClientError, CustomSigningError, ExecutionException, InterruptedException, IOException {
        EthTssAccountParams params = new EthTssAccountParams(
                fullAddress, factorKey, tssNonce, tssShare, tssIndex, selected_tag, verifier, verifierId,
                nodeIndexs, tssEndpoints, sigs);
        EthereumTssAccount account = new EthereumTssAccount(params);
        // setup Web3j
        String url = "https://rpc.ankr.com/eth_goerli";
        Web3j web3j = Web3j.build(new HttpService(url));
        EthGetTransactionCount ethGetTransactionCount = web3j.ethGetTransactionCount(
                account.evmAddress,
                DefaultBlockParameterName.LATEST
        ).send();
        BigInteger nonce = ethGetTransactionCount.getTransactionCount();
        BigInteger gasLimit = BigInteger.valueOf(21000);
        EthChainId chainIdResponse = web3j.ethChainId().sendAsync().get();
        BigInteger chainId = chainIdResponse.getChainId();

        String toAddress = "0xE09543f1974732F5D6ad442dDf176D9FA54a5Be0";
        account.signLegacyTransaction(chainId, toAddress, 0.001, null, nonce, gasLimit);
    }

    @Test
    public void testSigningTransaction() throws TSSClientError, CustomSigningError, SignatureException, ExecutionException, InterruptedException, IOException {
        EthTssAccountParams params = new EthTssAccountParams(
                fullAddress, factorKey, tssNonce, tssShare, tssIndex, selected_tag, verifier, verifierId,
                nodeIndexs, tssEndpoints, sigs);
        EthereumTssAccount account = new EthereumTssAccount(params);
        // setup Web3j
        String url = "https://rpc.ankr.com/eth_goerli";
        Web3j web3j = Web3j.build(new HttpService(url));
        EthGetTransactionCount ethGetTransactionCount = web3j.ethGetTransactionCount(
                account.evmAddress,
                DefaultBlockParameterName.LATEST
        ).send();
        BigInteger nonce = ethGetTransactionCount.getTransactionCount();
        BigInteger gasLimit = BigInteger.valueOf(21000);
        EthChainId chainIdResponse = web3j.ethChainId().sendAsync().get();
        BigInteger chainId = chainIdResponse.getChainId();
        EthGasPrice gasPriceResponse = web3j.ethGasPrice().send();
        BigInteger gasPrice = gasPriceResponse.getGasPrice();

        String toAddress = "0xE09543f1974732F5D6ad442dDf176D9FA54a5Be0";
        account.signTransaction(chainId, toAddress, 0.001, null, nonce, gasLimit, gasPrice, gasPrice);
    }
}
