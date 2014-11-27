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

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.AESEncrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import net.minidev.json.JSONObject;
import org.apache.commons.io.IOUtils;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.interfaces.RSAPublicKey;

public class JWEGenerator {

  static void encrypt(JSONObject header, JWEAlgorithm algorithm, String payload, String keyFile) throws Exception {
    final JWEObject jweObject = new JWEObject(new JWEHeader.Builder(algorithm, getEnc(header)).customParams(header).build(), new Payload(payload));
    jweObject.encrypt(getEncrypter(algorithm, keyFile));
    System.out.println(jweObject.serialize());
  }

  static EncryptionMethod getEnc(JSONObject header) {
    final Object enc = header.get("enc");
    if (enc == null) {
      return EncryptionMethod.A256CBC_HS512;
    }
    if (!(enc instanceof String)) {
      throw new IllegalArgumentException("\"enc\" must be one of: \"A128CBC\",\"A256CBC\",\"A128GCM\",\"A256GCM\"");
    }
    switch ((String) enc) {
      case "A128CBC":
        return EncryptionMethod.A128CBC_HS256;
      case "A256CBC":
        return EncryptionMethod.A256CBC_HS512;
      case "A128GCM":
        return EncryptionMethod.A128GCM;
      case "A256GCM":
        return EncryptionMethod.A256GCM;
      default:
        throw new IllegalArgumentException("\"enc\" must be one of: \"A128CBC\",\"A256CBC\",\"A128GCM\",\"A256GCM\"");
    }
  }

  private static JWEEncrypter getEncrypter(JWEAlgorithm jweAlgorithm, String keyFile) throws Exception {
    final String name = jweAlgorithm.getName();
    if (name.startsWith("RSA")) {
      return new RSAEncrypter(readRSAPublicKey());
    }
    if (name.startsWith("A")) {
      return new AESEncrypter(readKey(keyFile));
    }

    throw new IllegalArgumentException();
  }

  static RSAPublicKey readRSAPublicKey() {
    throw new UnsupportedOperationException();
  }

  private static byte[] readKey(String keyFile) throws IOException {
    return IOUtils.toByteArray(new FileInputStream(keyFile));
  }
}