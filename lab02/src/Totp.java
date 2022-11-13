package totp;


import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Objects;

public class Totp {
	
/*---- Main program ----*/
	
	public static void main(String[] args) {
		
		byte[] secretKey = decodeBase32("ABC234mnop567XYZ");
		String code;
		try {
			long timestamp = Math.floorDiv(System.currentTimeMillis(), 1000);
			code = calcTotp(secretKey, 0, 30, timestamp, 6, "SHA-1", 64);
		} catch (NoSuchAlgorithmException e) {
			// Algorithm "SHA-1" is guaranteed to exist
			throw new AssertionError(e);
		}
		System.out.println(code);
	}
	
	
	private static byte[] decodeBase32(String str) {
		ByteArrayOutputStream result = new ByteArrayOutputStream();
		int bits = 0;
		int bitsLen = 0;
		for (int i = 0; i < str.length(); i++) {
			char c = str.charAt(i);
			if (c == ' ')
				continue;
			int j = BASE32_ALPHABET.indexOf(Character.toUpperCase(c));
			if (j == -1)
				throw new IllegalArgumentException("Invalid Base32 string");
			bits = (bits << 5) | j;
			bitsLen += 5;
			if (bitsLen >= 8) {
				bitsLen -= 8;
				result.write(bits >>> bitsLen);
				bits &= (1 << bitsLen) - 1;
			}
		}
		return result.toByteArray();
	}
	
	
	
	/*---- Library functions ----*/
	
	// Time-based One-Time Password algorithm (RFC 6238)
	public static String calcTotp(
			byte[] secretKey,
			long epoch,
			int timeStep,
			long timestamp,
			int codeLen,
			String hashFunc,
			int blockSize)
			throws NoSuchAlgorithmException {
		
		// Calculate counter and HOTP
		long timeCounter = Math.floorDiv(timestamp - epoch, timeStep);
		byte[] counter = new byte[8];
		for (int i = counter.length - 1; i >= 0; i--, timeCounter >>>= 8)
			counter[i] = (byte)timeCounter;
		return calcHotp(secretKey, counter, codeLen, hashFunc, blockSize);
	}
	
	
	// HMAC-based One-Time Password algorithm (RFC 4226)
	public static String calcHotp(
			byte[] secretKey,
			byte[] counter,
			int codeLen,
			String hashFunc,
			int blockSize)
			throws NoSuchAlgorithmException {
		
		// Check argument, calculate HMAC
		if (!(1 <= codeLen && codeLen <= 9))
			throw new IllegalArgumentException("Invalid number of digits");
		byte[] hash = calcHmac(secretKey, counter, hashFunc, blockSize);
		
		// Dynamically truncate the hash value
		int offset = hash[hash.length - 1] & 0xF;
		int val = 0;
		for (int i = 0; i < 4; i++)
			val |= (hash[offset + i] & 0xFF) << ((3 - i) * 8);
		val &= 0x7FFFFFFF;
		
		// Extract and format base-10 digits
		int tenPow = 1;
		for (int i = 0; i < codeLen; i++)
			tenPow *= 10;
		return String.format("%0" + codeLen + "d", val % tenPow);
	}
	
	
	private static byte[] calcHmac(
			byte[] key,
			byte[] message,
			String hashFunc,
			int blockSize)
			throws NoSuchAlgorithmException {
		
		Objects.requireNonNull(key);
		Objects.requireNonNull(message);
		Objects.requireNonNull(hashFunc);
		if (blockSize < 1)
			throw new IllegalArgumentException("Invalid block size");
		
		if (key.length > blockSize)
			key = MessageDigest.getInstance(hashFunc).digest(key);
		key = Arrays.copyOf(key, blockSize);
		
		byte[] innerMsg = new byte[key.length + message.length];
		for (int i = 0; i < key.length; i++)
			innerMsg[i] = (byte)(key[i] ^ 0x36);
		System.arraycopy(message, 0, innerMsg, key.length, message.length);
		byte[] innerHash = MessageDigest.getInstance(hashFunc).digest(innerMsg);
		
		byte[] outerMsg = new byte[key.length + innerHash.length];
		for (int i = 0; i < key.length; i++)
			outerMsg[i] = (byte)(key[i] ^ 0x5C);
		System.arraycopy(innerHash, 0, outerMsg, key.length, innerHash.length);
		return MessageDigest.getInstance(hashFunc).digest(outerMsg);
	}
	
	
	private static final String BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	

}
