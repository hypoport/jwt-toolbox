/*
Copyright (c) 2014 Hypoport AG

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
 */

package org.hypoport.jwt.common;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.Base64;
import org.apache.commons.io.IOUtils;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.security.KeyFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class Toolbox {

  public static RSAPrivateKey readRSAPrivateKey(Reader keyReader) throws Exception {
    return (RSAPrivateKey) KeyFactory.getInstance("RSA")
        .generatePrivate(new PKCS8EncodedKeySpec(readPemFile(keyReader)));
  }

  public static RSAPublicKey readRSAPublicKey(FileReader keyReader) throws Exception {
    return (RSAPublicKey) KeyFactory.getInstance("RSA")
        .generatePublic(new X509EncodedKeySpec(readPemFile(keyReader)));
  }

  public static ECPrivateKey readECDSAPrivateKey(Reader keyReader) throws Exception {
    return (ECPrivateKey) KeyFactory.getInstance("EC")
        .generatePrivate(new PKCS8EncodedKeySpec(readPemFile(keyReader)));
  }

  public static ECPublicKey readECDHPublicKey(FileReader keyReader) throws Exception {
    return (ECPublicKey) KeyFactory.getInstance("EC")
        .generatePublic(new X509EncodedKeySpec(readPemFile(keyReader)));
  }

  public static byte[] readPemFile(Reader fileReader) throws IOException {
    BufferedReader reader = new BufferedReader(fileReader);
    StringBuilder sb = new StringBuilder();
    for (String s; (s = reader.readLine()) != null; ) {
      if (s.trim().startsWith("-----BEGIN")) { continue; }
      if (s.trim().startsWith("-----END")) { continue; }
      sb.append(s).append('\n');
    }
    return decodeBase64(sb.toString());
  }

  private static byte[] decodeBase64(String base64string) {
    return new Base64(base64string).decode();
  }

  public static byte[] readKey(Reader keyReader) throws IOException {
    return IOUtils.toByteArray(keyReader);
  }

  public static Algorithm getAlgorithmWithName(String alg) {
    switch (alg) {
      case "none":
        return Algorithm.NONE;
      case "HS256":
        return JWSAlgorithm.HS256;
      case "HS384":
        return JWSAlgorithm.HS384;
      case "HS512":
        return JWSAlgorithm.HS512;
      case "RS256":
        return JWSAlgorithm.RS256;
      case "RS384":
        return JWSAlgorithm.RS384;
      case "RS512":
        return JWSAlgorithm.RS512;
      case "ES256":
        return JWSAlgorithm.ES256;
      case "ES384":
        return JWSAlgorithm.ES384;
      case "ES512":
        return JWSAlgorithm.ES512;
      case "RSA1_5":
        return JWEAlgorithm.RSA1_5;
      case "RSA-OAEP":
        return JWEAlgorithm.RSA_OAEP;
      case "ECDH-ES":
        return JWEAlgorithm.ECDH_ES;
      case "A128KW":
        return JWEAlgorithm.A128KW;
      case "A256KW":
        return JWEAlgorithm.A256KW;
      case "A128GCM":
        return JWEAlgorithm.A128GCMKW;
      case "A256GCM":
        return JWEAlgorithm.A256GCMKW;
      default:
        throw new IllegalArgumentException("\"alg\" must be one of: \"HS256\",\"HS384\",\"HS512\",\"RS256\",\"RS384\",\"RS512\",\"ES256\",\"ES384\",\"ES512\",\"RSA1_5\",\"RSA-OAEP\",\"ECDH-ES\",\"A128KW\",\"A256KW\",\"A128GCM\",\"A256GCM\"");
    }
  }
}
