package org.hypoport.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static java.util.stream.Collectors.joining;

public class Ep2JwtFactory {

  public static final String BEGIN_PUBLIC_KEY_STRING = "-----BEGIN PRIVATE KEY-----";
  public static final String END_PUBLIC_KEY_STRING = "-----END PRIVATE KEY-----";

  public static void main(String[] args) throws IOException, JOSEException {

    if (args.length < 2 || args.length > 3) {
      System.out.println("usage: <private-key.pem> <sub> [issuer]");
      System.out.println("jwt ist immer 60 Sekunden gültig.");
      System.exit(1);
    }

    Path pemFile = Paths.get(args[0]);
    String pem = Files.readAllLines(pemFile).stream().collect(joining());
    String sub = args[1];
    String iss = args.length > 2 ? args[2] : sub;
    Date exp = new Date(new Date().getTime() + 60000);

    String jwt = new Ep2JwtFactory().createEp2Jwt(pem, sub, iss, exp);

    System.out.print(jwt);
  }

  public String createEp2Jwt(String pem, String sub, String iss, Date exp) throws JOSEException {

    String key = pem.replace(BEGIN_PUBLIC_KEY_STRING, "").replace(END_PUBLIC_KEY_STRING, "");

    // Create RSA-signer with the private key
    JWSSigner signer = new RSASSASigner(getPrivateKey(decodeBase64(key)));

    // Prepare JWT with claims set
    JWTClaimsSet claimsSet = new JWTClaimsSet();
    claimsSet.setSubject(sub);
    claimsSet.setExpirationTime(exp);

    Map<String, Object> custom = new HashMap<>();
    custom.put("iss", iss);

    JWSHeader header = new JWSHeader(JWSAlgorithm.RS256, null, null, null, null, null, null, null, null, null, null, custom, null);
    SignedJWT signedJWT = new SignedJWT(header, claimsSet);

    signedJWT.sign(signer);

    return signedJWT.serialize();
  }

  private static byte[] decodeBase64(String base64string) {
    return new Base64(base64string).decode();
  }

  public RSAPrivateKey getPrivateKey(byte[] key) {
    try {
      KeySpec ks = new PKCS8EncodedKeySpec(key);
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      return (RSAPrivateKey) keyFactory.generatePrivate(ks);
    }
    catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new RuntimeException(e);
    }
  }
}
