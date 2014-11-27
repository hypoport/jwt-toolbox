package org.hypoport.jwt.generator;

import com.nimbusds.jose.Payload;
import com.nimbusds.jose.PlainHeader;
import com.nimbusds.jose.PlainObject;
import net.minidev.json.JSONObject;

public class PlainGenerator {

  public static String encode(JSONObject header, String payload) {
    final PlainHeader plainHeader = new PlainHeader.Builder().customParams(header).build();
    final PlainObject plainObject = new PlainObject(plainHeader, new Payload(payload));
    return plainObject.serialize();
  }
}
