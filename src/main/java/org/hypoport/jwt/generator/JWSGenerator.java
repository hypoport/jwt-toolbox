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

package org.hypoport.jwt.generator;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64;
import net.minidev.json.JSONObject;
import org.apache.commons.io.IOUtils;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

public class JWSGenerator {

  static void sign(JSONObject header, JWSAlgorithm algorithm, String payload, String keyFile) throws Exception {
    final JWSObject jwsObject = new JWSObject(new JWSHeader.Builder(algorithm).customParams(header).build(), new Payload(payload));
    jwsObject.sign(getSigner(algorithm, keyFile));
    System.out.println(jwsObject.serialize());
  }

  static JWSSigner getSigner(JWSAlgorithm algorithm, String keyFile) throws Exception {
    final String name = algorithm.getName();
    if (name.startsWith("RS")) {
      return new RSASSASigner(readRSAKey(keyFile));
    }
    if (name.startsWith("ES")) {
      return new ECDSASigner(readECDSAKey(keyFile).getS());
    }
    if (name.startsWith("HS")) {
      return new MACSigner(readKey(keyFile));
    }

    throw new IllegalArgumentException();
  }

  static ECPrivateKey readECDSAKey(String keyFile) throws Exception {
    BufferedReader reader = new BufferedReader(new FileReader(keyFile));
    StringBuilder sb = new StringBuilder();
    for (String s; (s = reader.readLine()) != null; ) {
      if (s.trim().startsWith("-----BEGIN")) { continue; }
      if (s.trim().startsWith("-----END")) { continue; }
      sb.append(s).append('\n');
    }
    System.out.println(sb);
    return (ECPrivateKey) KeyFactory.getInstance("EC")
        .generatePrivate(new PKCS8EncodedKeySpec(new Base64(sb.toString()).decode()));
  }

  static RSAPrivateKey readRSAKey(String keyFile) throws Exception {
    BufferedReader reader = new BufferedReader(new FileReader(keyFile));
    StringBuilder sb = new StringBuilder();
    for (String s; (s = reader.readLine()) != null; ) {
      if (s.trim().startsWith("-----BEGIN")) { continue; }
      if (s.trim().startsWith("-----END")) { continue; }
      sb.append(s).append('\n');
    }
    System.out.println(sb);
    return (RSAPrivateKey) KeyFactory.getInstance("RSA")
        .generatePrivate(new PKCS8EncodedKeySpec(new Base64(sb.toString()).decode()));
  }

  static byte[] readKey(String keyFile) throws IOException {
    return IOUtils.toByteArray(new FileInputStream(keyFile));
  }
}