//
//import org.bouncycastle.operator.ContentSigner;
//import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
//
//import org.bouncycastle.asn1.x500.X500Name;
//
//import java.math.BigInteger;
//import java.security.*;
//
//import java.security.cert.X509Certificate;
//import java.security.spec.PKCS8EncodedKeySpec;
//import java.security.spec.X509EncodedKeySpec;
//import java.util.Base64;
//import java.util.Date;
//import java.util.concurrent.ConcurrentHashMap;
//import javax.crypto.Cipher;
//import java.nio.charset.StandardCharsets;
//
//import org.bouncycastle.cert.X509v3CertificateBuilder;
//import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
//
//import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
//import org.bouncycastle.jce.provider.BouncyCastleProvider;
//
//
//public class CryptUtils {
//    private static ConcurrentHashMap<String, KeyPair> userKeyPairs = new ConcurrentHashMap<>();
//
//    public static void generateKeyPairForUser(String userId) throws NoSuchAlgorithmException {
//        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
//        keyPairGen.initialize(2048);
//        KeyPair keyPair = keyPairGen.generateKeyPair();
//        userKeyPairs.put(userId, keyPair);
//    }
//
//    public static String getUserPublicKey(String userId) {
//        KeyPair keyPair = userKeyPairs.get(userId);
//        if (keyPair != null) {
//            return Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
//        }
//        return null;
//    }
//
//    public static String getUserPrivateKey(String userId) {
//        KeyPair keyPair = userKeyPairs.get(userId);
//        if (keyPair != null) {
//            return Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
//        }
//        return null;
//    }
//
//    public static String encrypt(String text, String publicKeyBase64) throws Exception {
//        PublicKey publicKey = decodePublicKey(publicKeyBase64);
//        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
//        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
//        byte[] data = text.getBytes(StandardCharsets.UTF_8);
//        byte[] encryptedData = cipher.doFinal(data);
//        return Base64.getEncoder().encodeToString(encryptedData);
//    }
//
//    public static String decrypt(String encryptedText, String privateKeyBase64) throws Exception {
//        PrivateKey privateKey = decodePrivateKey(privateKeyBase64);
//        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
//        cipher.init(Cipher.DECRYPT_MODE, privateKey);
//        byte[] encryptedData = Base64.getDecoder().decode(encryptedText);
//        byte[] decryptedData = cipher.doFinal(encryptedData);
//        return new String(decryptedData, StandardCharsets.UTF_8);
//    }
//
//    private static PublicKey decodePublicKey(String publicKeyBase64) throws GeneralSecurityException {
//        byte[] publicBytes = Base64.getDecoder().decode(publicKeyBase64);
//        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
//        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//        return keyFactory.generatePublic(keySpec);
//    }
//
//    private static PrivateKey decodePrivateKey(String privateKeyBase64) throws GeneralSecurityException {
//        byte[] privateBytes = Base64.getDecoder().decode(privateKeyBase64);
//        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateBytes);
//        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//        return keyFactory.generatePrivate(keySpec);
//    }
//
//    static {
//        Security.addProvider(new BouncyCastleProvider());
//    }
//
//    public static X509Certificate generateX509CertificateWithPublicKey(String publicKeyBase64) throws Exception {
//        // 解码公钥
//        byte[] publicBytes = Base64.getDecoder().decode(publicKeyBase64);
//        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
//        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//        PublicKey publicKey = keyFactory.generatePublic(keySpec);
//
//        // 生成自签名证书的密钥对
//        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
//        keyPairGen.initialize(2048);
//        KeyPair keyPair = keyPairGen.generateKeyPair();
//
//        // 证书有效期和签发者信息
//        long now = System.currentTimeMillis();
//        Date startDate = new Date(now);
//        X500Name issuerName = new X500Name("O=Telegram");
//        BigInteger serialNumber = BigInteger.valueOf(now);
//        Date endDate = new Date(now + (1000L * 60 * 60 * 24 * 365)); // 1年有效期
//
//        // 构建证书
//        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
//                issuerName, serialNumber, startDate, endDate, issuerName, publicKey);
//        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(keyPair.getPrivate());
//        return new JcaX509CertificateConverter().getCertificate(certBuilder.build(contentSigner));
//    }
//
//    public static String extractPublicKeyFromX509Certificate(X509Certificate certificate) {
//        PublicKey publicKey = certificate.getPublicKey();
//        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
//    }
//}
//
//
