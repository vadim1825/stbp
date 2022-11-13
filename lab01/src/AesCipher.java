package aesCipher;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

public class AesCipher {
	
	public static String encrypt(String secretKey, String plainText) throws UnsupportedEncodingException,
	NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
	BadPaddingException {
		SecretKeySpec key = new SecretKeySpec(secretKey.getBytes("UTF-8"), "AES");
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		
		return new String(Hex.encodeHex(cipher.doFinal(plainText.getBytes("UTF-8")), false));
	}

	
	public static String decrypt(String secretKey, String cipherText) throws UnsupportedEncodingException,
	InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
	IllegalBlockSizeException, BadPaddingException, DecoderException {
		SecretKeySpec key = new SecretKeySpec(secretKey.getBytes("UTF-8"), "AES");
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, key);
		
		return new String(cipher.doFinal(Hex.decodeHex(cipherText.toCharArray())));
	}
	
	public static void main(String[] args) throws InvalidKeyException, UnsupportedEncodingException,
	NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, 
	DecoderException {
		String secretKey = "secretsecretsecr";
		String plainText = "Hello, world!";
		String encryptedText;
		System.out.println("Encripted text: " + (encryptedText = AesCipher.encrypt(secretKey, plainText)));
		System.out.println("Decrypted text: " + AesCipher.decrypt(secretKey, encryptedText));
	}

}