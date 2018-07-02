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
import net.minidev.json.JSONObject;

import java.io.Reader;

import static org.hypoport.jwt.common.Toolbox.readECDSAPrivateKey;
import static org.hypoport.jwt.common.Toolbox.readKey;
import static org.hypoport.jwt.common.Toolbox.readRSAPrivateKey;

public class JWSGenerator {

  static String sign(JSONObject header, JWSAlgorithm algorithm, String payload, Reader keyReader) throws Exception {
    final JWSObject jwsObject = new JWSObject(new JWSHeader.Builder(algorithm).customParams(header).build(), new Payload(payload));
    jwsObject.sign(getSigner(algorithm, keyReader));
    return jwsObject.serialize();
  }

  static JWSSigner getSigner(JWSAlgorithm algorithm, Reader keyReader) throws Exception {
    final String name = algorithm.getName();
    if (name.startsWith("RS")) {
      return new RSASSASigner(readRSAPrivateKey(keyReader));
    }
    if (name.startsWith("ES")) {
      return new ECDSASigner(readECDSAPrivateKey(keyReader));
    }
    if (name.startsWith("HS")) {
      return new MACSigner(readKey(keyReader));
    }

    throw new IllegalArgumentException();
  }
}