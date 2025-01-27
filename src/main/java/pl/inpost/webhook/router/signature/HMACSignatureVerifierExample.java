package pl.inpost.webhook.router.signature;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class HMACSignatureVerifierExample {

  private static final String BODY = "{\"customerReference\":\"9000010305\",\"trackingNumber\":\"120000018332540090213375\",\"eventId\":\"76b2262a-4274-40a1-8aac-89b048974d75#MMD.1001\",\"eventCode\":\"MMD.1001\",\"timestamp\":\"2024-11-25T16:51:40.111968200Z\",\"location\":{\"id\":null,\"address\":null,\"city\":null,\"country\":\"PL\",\"name\":null,\"postalCode\":null,\"type\":\"LOGISTIC_CENTER\",\"description\":null},\"delivery\":{\"recipientName\":null,\"deliveryNotes\":null},\"shipment\":{\"type\":null}}";
  private static final String BASE64_ENCODED_DIGITAL_SIGNATURE = "i1PzFQMpGoM3YwjcDUEtBwNMCa01kjCykHLLoA5oZtE=";


  private final String algorithm;
  private final String key;

  public HMACSignatureVerifierExample() {
    this.algorithm = "HmacSHA256";
    this.key = "this is example of the HMAC key";
  }

  public boolean verifySignature(String body, String signatureFromXInPostSignatureHeader) {
    String newSignature = createSignature(body);
    return signatureFromXInPostSignatureHeader.equals(newSignature);
  }

  public String createSignature(String body) {
    try {
      SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), algorithm);
      Mac mac = Mac.getInstance(algorithm);
      mac.init(secretKeySpec);
      byte[] contentToSign = body.getBytes(StandardCharsets.UTF_8);
      return Base64.getEncoder().encodeToString((mac.doFinal(contentToSign)));
    } catch (Exception e) {
      log.error("Exception during signature verification", e);
    }
    return null;
  }

  public static void main(String[] args) {
    var verifier = new HMACSignatureVerifierExample();

    var result = verifier.verifySignature(BODY, BASE64_ENCODED_DIGITAL_SIGNATURE);
    log.info("Signature verification result: " + result);
  }
}