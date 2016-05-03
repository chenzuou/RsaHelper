package test;

import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;

import javax.crypto.Cipher;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;


/**
 * @author chenzuou
 * @time 2016-5-3 下午02:24:37
 */

public class RsaHelper {
	//加密
	public static String toKeySury(String param,String pubKey) throws Exception{
		Key key=getPubKey(pubKey);
		Cipher c=Cipher.getInstance("RSA");
		c.init(Cipher.ENCRYPT_MODE, key);
		byte[] b=param.getBytes();
		byte[] b1=c.doFinal(b);
		BASE64Encoder en=new BASE64Encoder();
		return en.encode(b1 );
	}
	
	//解密
	public static String JM(String param,String priKey) throws Exception{
		BASE64Decoder de = new BASE64Decoder();
		byte[] p= de.decodeBuffer(param);
		Key key=getPriKey(priKey);
		Cipher c=Cipher.getInstance("RSA");
		c.init(Cipher.DECRYPT_MODE, key);
		byte[] b1=c.doFinal(p);
		return new String(b1);
	}
	
	//公钥转换
	public static PublicKey getPubKey(String pubKey) throws Exception{
		BASE64Decoder  be=new BASE64Decoder ();
		KeyFactory keyFactory=KeyFactory.getInstance("RSA");
		EncodedKeySpec  pubKeySpec=new X509EncodedKeySpec(be.decodeBuffer(pubKey));
		return keyFactory.generatePublic(pubKeySpec);
	}
	
//	私钥转换
	public static PrivateKey getPriKey(String priKey) throws Exception{
		BASE64Decoder  be=new BASE64Decoder ();
		KeyFactory keyFactory=KeyFactory.getInstance("RSA");
		PKCS8EncodedKeySpec  priKeySpec=new PKCS8EncodedKeySpec(be.decodeBuffer(priKey));
		return keyFactory.generatePrivate(priKeySpec);
	}
	
	public static void main(String[] args) throws Exception {
		//获得公钥私钥
		Map<String, String> keyMap = CreateKey.initKey();
		String publicKey = keyMap.get("RSAPublicKey");
		String privateKey = keyMap.get("RSAPrivateKey");
		
		//加密123
		String jiami = toKeySury("123",publicKey);
		System.out.println(jiami);
		//解密123
		String jiemi = JM(jiami,privateKey);
		System.out.println(jiemi);
	}
}
