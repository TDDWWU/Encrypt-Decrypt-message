import org.telegram.telegrambots.bots.TelegramLongPollingBot;
import org.telegram.telegrambots.meta.TelegramBotsApi;
import org.telegram.telegrambots.meta.api.methods.send.SendMessage;
import org.telegram.telegrambots.meta.api.objects.Update;
import org.telegram.telegrambots.meta.exceptions.TelegramApiException;
import org.telegram.telegrambots.updatesreceivers.DefaultBotSession;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import org.bouncycastle.asn1.x500.X500Name;

import java.math.BigInteger;
import java.security.*;

import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;

import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.NoSuchAlgorithmException;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.HashMap;
import java.util.Set;


public class Main {

    public static void main(String [] args){
        try {
            TelegramBotsApi botsApi = new TelegramBotsApi(DefaultBotSession.class);
            MemberList.startUpdating();
            botsApi.registerBot(new EncryptBot());
        } catch (TelegramApiException E) {
            E.printStackTrace();
        }
    }
}
class EncryptBot extends TelegramLongPollingBot {


    private final HashMap<String, String> Member_Crypto_Key = new HashMap<>();
    private final HashMap<String, X509Certificate> public_key_map = new HashMap<>();

    private final HashMap<String, String> private_key_map = new HashMap<>();
    String encryptedMessage;
    String Group_ID = "-1002126585788";

    @Override
    public void onUpdateReceived(Update update) {
        if (update.hasMessage() && update.getMessage().hasText()) {
            String UserName = update.getMessage().getChat().getUserName();
            String chatID = update.getMessage().getChatId().toString();

            String messageText = update.getMessage().getText();
            System.out.println("Chat ID:  " + chatID); // get chatID
            String UserID = update.getMessage().getFrom().getFirstName();
            if (messageText.equals("/check")) {
                if (!MemberList.isMember(chatID)) {
                    String welcomeMessage = "Welcome to use this bot, Seems like you're not one of our group member, so your message won't be encrypted";
                    sendMessage(chatID, welcomeMessage);
                    sendMessage(chatID, "You can send Message but Message won't encrypt.");

                } else {
                    if (!Member_Crypto_Key.containsKey(UserID)) {
                        sendMessage(chatID, "Welcome User--> @" + UserName + " \ngood to see you again \nnow you can send message.");
                        sendMessage(chatID, "Your message will encrypt in the group.");
                        Member_Crypto_Key.put(UserID, chatID);
                        try {
                            CryptUtils.generateKeyPairForUser(chatID);
                        } catch (NoSuchAlgorithmException e) {
                            throw new RuntimeException(e);
                        }
                        String PublicKey = CryptUtils.getUserPublicKey(chatID);
                        String PrivateKey = CryptUtils.getUserPrivateKey(chatID);
                        try {
                            X509Certificate X509 = CryptUtils.generateX509CertificateWithPublicKey(PublicKey);
                            public_key_map.put(chatID, X509);
                            System.out.println("Certificate stored for chatID: " + chatID);
                        } catch (Exception e) {
                            System.err.println("Failed to generate or store certificate for chatID: " + chatID);
                            throw new RuntimeException(e);
                        }
                        sendMessage(chatID, "This is Your private key, do not share with other");
                        sendMessage(chatID, PrivateKey);


                    }
                }
            } else if (messageText.contains("+")) {
                String[] parts = messageText.split("\n\\+\n", 2);
                if (parts.length == 2) {
                    String privateKeyBase64 = parts[0];
                    String encryptedMessage = parts[1];
                    try {

                        String decryptedMessage = CryptUtils.decrypt(encryptedMessage, privateKeyBase64);
                        sendMessage(chatID,  decryptedMessage);
                    } catch (Exception e) {
                        sendMessage(chatID, "error message: " + e.getMessage());
                    }
                }

            }else{
                if(!Member_Crypto_Key.containsKey(UserID) || !MemberList.isMember(chatID)){
                    Member_Crypto_Key.remove(UserID);
                    public_key_map.remove(chatID);
                    private_key_map.remove(chatID);
                    sendMessage(chatID,"--Remember: YOU'RE NOT PRIVATE MEMBER--");
                    sendMessage(Group_ID,UserID+" : "+messageText);
                }else {
                    try {
                        X509Certificate certificate = public_key_map.get(chatID);
                        String publicKeyBase64 = CryptUtils.extractPublicKeyFromX509Certificate(certificate);

                        encryptedMessage = CryptUtils.encrypt(messageText, publicKeyBase64);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                    sendMessage(Group_ID, UserID+": \n" + encryptedMessage);
                    forwardMessage(this,chatID,messageText,UserID);
                }

            }

        }

    }

    public void forwardMessage(TelegramLongPollingBot bot, String ChatID, String messageText, String userID) {
        Set<String> memberList = MemberList.getMemberList();
        for (String chatID : memberList) {
            if (!chatID.equals(ChatID)) {
                try {
                    X509Certificate certificate = public_key_map.get(chatID);
                    String publicKeyBase64 = CryptUtils.extractPublicKeyFromX509Certificate(certificate);
                    encryptedMessage = CryptUtils.encrypt(userID + ": \n" + messageText, publicKeyBase64);
                    System.out.println("Forwarding message to chatID: " + chatID);
                } catch (Exception e) {
                    System.err.println("Encryption failed for chatID: " + chatID + " Error: " + e.getMessage());
                    continue;
                }
                sendMessage(chatID, encryptedMessage);
            }
        }
    }


    private void sendMessage(String chatId, String messageText) {
        SendMessage message = new SendMessage();
        message.setChatId(chatId);
        message.setText(messageText);

        try {
            execute(message);
        } catch (TelegramApiException e) {
            e.printStackTrace();
        }
    }

    @Override
    public String getBotUsername() {
       
        return "Encrypt_Message_bot";
    }

    @Override
    public String getBotToken() {
        
        return "6881200103:AAHPohGZeWLK2JoP3pm7-bEOGR0Od23x3BQ";
    }
}


class CryptUtils {
    private static ConcurrentHashMap<String, KeyPair> userKeyPairs = new ConcurrentHashMap<>();

    public static void generateKeyPairForUser(String userId) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        userKeyPairs.put(userId, keyPair);
    }

    public static String getUserPublicKey(String userId) {
        KeyPair keyPair = userKeyPairs.get(userId);
        if (keyPair != null) {
            return Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        }
        return null;
    }

    public static String getUserPrivateKey(String userId) {
        KeyPair keyPair = userKeyPairs.get(userId);
        if (keyPair != null) {
            return Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
        }
        return null;
    }

    public static String encrypt(String text, String publicKeyBase64) throws Exception {
        PublicKey publicKey = decodePublicKey(publicKeyBase64);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] data = text.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedData = cipher.doFinal(data);
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    public static String decrypt(String encryptedText, String privateKeyBase64) throws Exception {
        PrivateKey privateKey = decodePrivateKey(privateKeyBase64);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] encryptedData = Base64.getDecoder().decode(encryptedText);
        byte[] decryptedData = cipher.doFinal(encryptedData);
        return new String(decryptedData, StandardCharsets.UTF_8);
    }

    private static PublicKey decodePublicKey(String publicKeyBase64) throws GeneralSecurityException {
        byte[] publicBytes = Base64.getDecoder().decode(publicKeyBase64);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    private static PrivateKey decodePrivateKey(String privateKeyBase64) throws GeneralSecurityException {
        byte[] privateBytes = Base64.getDecoder().decode(privateKeyBase64);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static X509Certificate generateX509CertificateWithPublicKey(String publicKeyBase64) throws Exception {
        
        byte[] publicBytes = Base64.getDecoder().decode(publicKeyBase64);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);

        
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        
        long now = System.currentTimeMillis();
        Date startDate = new Date(now);
        X500Name issuerName = new X500Name("O=Telegram");
        BigInteger serialNumber = BigInteger.valueOf(now);
        Date endDate = new Date(now + (1000L * 60 * 60 * 24 * 365)); 

       
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuerName, serialNumber, startDate, endDate, issuerName, publicKey);
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(certBuilder.build(contentSigner));
    }

    public static String extractPublicKeyFromX509Certificate(X509Certificate certificate) {
        PublicKey publicKey = certificate.getPublicKey();
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }
}

class MemberList {
    private static final Set<String> notMemberList = ConcurrentHashMap.newKeySet();
    private static final String Member_FILE = "Member.txt";
    private static final long UPDATE_INTERVAL = 1; // renew time

    static void startUpdating() {
        new Thread(() -> {
            while (!Thread.interrupted()) {
                update();
                try {
                    Thread.sleep(UPDATE_INTERVAL);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }).start();
    }

    private static void update() {
        Set<String> newBlockedUrls = new HashSet<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(Member_FILE))) {
            String line;
            while ((line = reader.readLine()) != null) {
                // Split the line by '|' and trim each ID
                String[] ID_List = line.split("\\|");
                for (String ID : ID_List) {
                    newBlockedUrls.add(ID.trim()); // Remove any leading and trailing spaces
                }
            }

        } catch (IOException e) {
            System.err.println("Error reading blocked URLs: " + e.getMessage());
        }
        notMemberList.clear();
        notMemberList.addAll(newBlockedUrls);
    }

    static boolean isMember(String ID) {
        return notMemberList.stream().anyMatch(ID::contains);
    }

    static Set<String> getMemberList() {
        return Collections.unmodifiableSet(notMemberList);
    }


}


