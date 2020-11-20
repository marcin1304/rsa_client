package com.example;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

public class TestClientCommunicator {
    static RSAPublicKeySpec rsaPublicKeySpecServer = new RSAPublicKeySpec(new BigInteger("133885750983503924813560084191898957467948617787030617926847063933865983793730790813229413158916149619776051771921597327934688757532301749441384613786787475339928159339607695885390130996423969265590592696704333158718839870043215062148257323134693455951801086347381933592822061537035148083748320398862875204439"), new BigInteger("65537"));

    static RSAPublicKeySpec rsaPublicKeySpecUser = new RSAPublicKeySpec(new BigInteger("138775352164611560276599448255717387353595817342882809606467762599323485078191214332573126072097283348936216865388004862504001868404400155581743245338004453900324011333069125116896928035312797721245842342345805964184483295307837732737872790647802722081044223800866466760908874777946362284268428373514586701587"), new BigInteger( "65537"));
    static RSAPrivateKeySpec rsaPrivateKeySpecUser = new RSAPrivateKeySpec(new BigInteger("138775352164611560276599448255717387353595817342882809606467762599323485078191214332573126072097283348936216865388004862504001868404400155581743245338004453900324011333069125116896928035312797721245842342345805964184483295307837732737872790647802722081044223800866466760908874777946362284268428373514586701587"), new BigInteger( "106773400637019901969685072231659879761321322210316657637617383482739329105432256458270401590848427843611392026188637825761047808297961051696809762468888343784463402510586651163533994780357876335085272502685540386406286048446502065417221087587193405713858951550394914868723541997084887788325733452398013809473"));

    static Scanner scanner = new Scanner(System.in);

    public static void main(String[] args) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        System.out.println("Choose option:\n1. Encrypt\n2. Decrypt");
        if(scanner.nextLine().equals("1")) {
            RSAPublicKey rsaPublicKey = (RSAPublicKey) keyFactory.generatePublic(rsaPublicKeySpecServer);

            System.out.println("Provide message you want to encode: ");
            String message = scanner.nextLine();
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(1024);

            String encrypted = encryptMessage(rsaPublicKey, message);
            System.out.println(encrypted);
        }
        else {
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyFactory.generatePrivate(rsaPrivateKeySpecUser);

            System.out.println("Provide encrypted message you want to decode: ");
            String message = scanner.nextLine();

            System.out.println(decryptMessage(rsaPrivateKey, message));
        }
    }

    public static String encryptMessage(RSAPublicKey rsaPublicKey, String message) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey);
        byte[] encryptedMessage = new byte[0];
        String[] messageBlocks = message.split("(?<=\\G.{117})");
        for (String messageBlock : messageBlocks) {
            byte[] encryptedBlock = encryptBlock(cipher, messageBlock);
            encryptedMessage = joinBlocks(encryptedMessage, encryptedBlock);
        }
        return new String(Base64.getEncoder().encode(encryptedMessage));
    }

    private static byte[] encryptBlock(Cipher cipher, String messageBlock) throws BadPaddingException, IllegalBlockSizeException {
        cipher.update(messageBlock.getBytes());
        return cipher.doFinal();
    }

    private static byte[] joinBlocks(byte[] block1, byte[] block2) {
        byte[] joinedBlocks = new byte[block1.length + block2.length];
        System.arraycopy(block1,0, joinedBlocks,0, block1.length);
        System.arraycopy(block2,0, joinedBlocks, block1.length, block2.length);
        return joinedBlocks;
    }

    public static String decryptMessage(RSAPrivateKey rsaPrivateKey, String encodedMessage) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
        byte[] rawEncodedMessage = Base64.getDecoder().decode(encodedMessage);
        StringBuilder decodedMessageBuilder = new StringBuilder("");
        for(int blockStart = 0; blockStart < rawEncodedMessage.length; blockStart += 128) {
            byte[] block =  Arrays.copyOfRange(rawEncodedMessage, blockStart, blockStart + 128);
            decodedMessageBuilder.append(decryptBlock(cipher, block));
        }
        return decodedMessageBuilder.toString();
    }

    private static String decryptBlock(Cipher cipher, byte[] encodedBlock) throws BadPaddingException, IllegalBlockSizeException {
        cipher.update(encodedBlock);
        return new String(cipher.doFinal());
    }
}
