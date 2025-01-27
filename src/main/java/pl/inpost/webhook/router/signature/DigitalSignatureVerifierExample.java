package pl.inpost.webhook.router.signature;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class DigitalSignatureVerifierExample {

  private static final String BODY = "{\"customerReference\":\"9000010305\",\"trackingNumber\":\"120000018332540090213375\",\"eventId\":\"76b2262a-4274-40a1-8aac-89b048974d75#MMD.1001\",\"eventCode\":\"MMD.1001\",\"timestamp\":\"2024-11-25T16:51:40.111968200Z\",\"location\":{\"id\":null,\"address\":null,\"city\":null,\"country\":\"PL\",\"name\":null,\"postalCode\":null,\"type\":\"LOGISTIC_CENTER\",\"description\":null},\"delivery\":{\"recipientName\":null,\"deliveryNotes\":null},\"shipment\":{\"type\":null}}";
  private static final String BASE64_ENCODED_DIGITAL_SIGNATURE = "KoTi4cs4diR380hDIIPOmgc4gLPB/xQisqa2vx0qcbNqJpysGThZ951/sogqKsOnK7zG8Vzh5KgrQlBzThoalsnDYEwJmuVsgf4DhIpxZRzLSWv8oW9+qYLrWtVGGoOx6Uow2AmaAxuV9xt3VmS8FPSM0OKQD8wDLdax/iWO2GM6tE0XWX/H6iIKaQmdVAh+fI3OTKxxgdzXn6nn0YNPTUt7GXxBuJ5pcTBEN7ne72LdIfJtJtX4S+I4I6rVOfPqm2RtX6lQX9ODHoJ6xke14NOwvovCpaKIRB3ktpS1YP4KM7ze+sRdmT2JKRUAce3qiPHemHnGt1vQa3tDN0dsm6uuI0Z9Zq16y9P/vfx58NW8dTgOK8lLRTY06nbNTEvopWT8Oe8JNGMVXWeoeQknpi/qcOKpcA0Oj8rAwq+oHEcHhQCqTGB1jCQNwPvHNSC2nysXvB1qFjge2oW0EvLY1IC4qk0Qqx48l0jdgSZUXqWeldxwnBUwaecrZHP1+sTgtMOWi8zJhofpawc2NuuUgcDDEXEOglYoAZCImXhN1du0tJ9rmMj4xhhIudLr+4Tf5En9k852EBWDvXtSbpxGMFVp1NBYOpfuNmLv30JHrvY40ivnd+Tz2fNlBDpH8yohXtiwHYpMT2px8+L0RPvpN2/O3Bl5Ak166bhWpJhCGNo=";

  private final String publicKeyAsString;

  public DigitalSignatureVerifierExample() {
    PublicKey publicKey = loadPublicKeyFromKeystore();
    publicKeyAsString = encodePublicKeyToString(publicKey);
  }

  public PublicKey loadPublicKeyFromKeystore() {
    KeyStore keyStore;
    try {
      keyStore = KeyStore.getInstance("JKS");
      keyStore.load(
          loadFileFromResources("test_keystore.jks"),
          "testpasswd".toCharArray());
      Certificate certificate = keyStore.getCertificate("your-alias");
      return certificate.getPublicKey();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private InputStream loadFileFromResources(String fileName) {
    ClassLoader classloader = Thread.currentThread().getContextClassLoader();
    return classloader.getResourceAsStream(fileName);
  }

  private String encodePublicKeyToString(PublicKey publicKey) {
    return Base64.getEncoder().encodeToString(publicKey.getEncoded());
  }

  private PublicKey loadPublicKeyFromString(String publicKeyAsString, String keyAlgorithm) {
    try {
      KeyFactory kf = KeyFactory.getInstance(keyAlgorithm);
      byte[] encodedPublicKey = Base64.getDecoder().decode(publicKeyAsString);
      X509EncodedKeySpec keySpecPublicKey = new X509EncodedKeySpec(encodedPublicKey);
      return kf.generatePublic(keySpecPublicKey);
    } catch (Exception e) {
      log.error("Exception during public key loading from String", e);
    }
    return null;
  }

  public boolean verifySignature(String body, PublicKey publicKey, String base64DigitalSignature) {
    try {
      Signature signature = Signature.getInstance("SHA256withRSA");
      signature.initVerify(publicKey);
      signature.update(body.getBytes(StandardCharsets.UTF_8));
      return signature.verify(Base64.getDecoder().decode(base64DigitalSignature));
    } catch (Exception e) {
      log.error("Exception during signature verification", e);
    }
    return false;
  }

  public boolean verifySignatureUsingPublicKeyFromKeystore() {
    var publicKey = loadPublicKeyFromKeystore();
    return verifySignature(BODY, publicKey, BASE64_ENCODED_DIGITAL_SIGNATURE);
  }

  public boolean verifySignatureUsingPublicKeyFromString() {
    var publicKey = loadPublicKeyFromString(publicKeyAsString, "RSA");
    return verifySignature(BODY, publicKey, BASE64_ENCODED_DIGITAL_SIGNATURE);
  }

  public static void main(String[] args) {
    var verifier = new DigitalSignatureVerifierExample();

    var result = verifier.verifySignatureUsingPublicKeyFromKeystore();
    log.info("Signature verification result: " + result);

    result = verifier.verifySignatureUsingPublicKeyFromString();
    log.info("Signature verification result: " + result);
  }
}
