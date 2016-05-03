package test;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;


/**
 * @author chenzuou
 * @time 2016-5-3 下午02:35:01
 */

public class CreateKey {
	 public static final String KEY_ALGORITHM = "RSA";
	    public static final String SIGNATURE_ALGORITHM = "MD5withRSA";
	    private static final String PUBLIC_KEY = "RSAPublicKey";
	    private static final String PRIVATE_KEY = "RSAPrivateKey";
	 
    public static void main(String[] args) {
    	Map<String, String> keyMap;
    	try {
	    	keyMap = initKey();
	    	System.out.println(keyMap.get(PUBLIC_KEY));
	    	System.out.println(keyMap.get(PRIVATE_KEY));
    	} catch (Exception e) { 
    		e.printStackTrace();
    	}
	}	 
	
	public static Map<String, String> initKey() throws Exception {
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
		keyPairGen.initialize(1024);
		KeyPair keyPair = keyPairGen.generateKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		Map<String, String> keyMap = new HashMap<String, String>(2);
		String publicKeyStr = encryptBASE64(publicKey.getEncoded());
		String privateKeyStr = encryptBASE64(privateKey.getEncoded());
		keyMap.put(PUBLIC_KEY, publicKeyStr.replaceAll("\r\n", ""));
		keyMap.put(PRIVATE_KEY, privateKeyStr.replaceAll("\r\n", ""));
		return keyMap;
	}
	
	public static String getPublicKey(Map<String, Object> keyMap) throws Exception {
        Key key = (Key) keyMap.get(PUBLIC_KEY); 
        return encryptBASE64(key.getEncoded());
	}
	public static String getPrivateKey(Map<String, Object> keyMap) throws Exception {
	    Key key = (Key) keyMap.get(PRIVATE_KEY); 
	    return encryptBASE64(key.getEncoded());
	}  
	public static byte[] decryptBASE64(String key) throws Exception {               
        return (new BASE64Decoder()).decodeBuffer(key);               
    }                                 
	               
	public static String encryptBASE64(byte[] key) throws Exception {               
		return (new BASE64Encoder()).encodeBuffer(key);               
	}       
}
