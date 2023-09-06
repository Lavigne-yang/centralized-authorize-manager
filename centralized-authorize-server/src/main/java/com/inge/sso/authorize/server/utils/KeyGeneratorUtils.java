package com.inge.sso.authorize.server.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

/**
 * @author lavyoung1325
 */
final class KeyGeneratorUtils {

    private static final String SECRET_KEY = "cam-authorize-server";

    private static final Logger logger = LoggerFactory.getLogger(KeyGeneratorUtils.class);

    private KeyGeneratorUtils() {

    }

    static SecretKey generateSecretKey() {
        SecretKey hmacKey;
        try {
            hmacKey = KeyGenerator.getInstance(SECRET_KEY).generateKey();
        } catch (NoSuchAlgorithmException e) {
            logger.error("generateSecretKey error: ", e);
            throw new RuntimeException("generateSecretKey error");
        }
        return hmacKey;
    }


    static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            logger.error("generateSecretKey error: ", e);
            throw new RuntimeException("generateSecretKey error");
        }
        return keyPair;
    }


    static KeyPair generateEcKey() {
        EllipticCurve ellipticCurve = new EllipticCurve(
                new ECFieldFp(new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853951")),
                new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853948"),
                new BigInteger("41058363725152142129326129780047268409114441015993725554835256314039467401291"));
        ECPoint ecPoint = new ECPoint(
                new BigInteger("48439561293906451759052585252797914202762949526041747995844080717082404635286"),
                new BigInteger("36134250956749795798585127919587881956611106672985015071877198253568414405109"));
        ECParameterSpec ecParameterSpec = new ECParameterSpec(ellipticCurve, ecPoint, new BigInteger(""), 1);
        KeyPair keyPair;

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(SECRET_KEY);
            keyPairGenerator.initialize(ecParameterSpec);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception e) {
            logger.error("error: ", e);
            throw new RuntimeException(e);
        }
        return keyPair;
    }

}
