package org.jxq.utility.crypt;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;

/**
 * 经典的数字签名算法RSA
 * 数字签名
 * @author kongqz
 * */
public class RSADigitalSignatureAlgorithm {
	
	//数字签名，密钥算法
	public static final String KEY_ALGORITHM="RSA";
	
	/**
	 * 数字签名
	 * 签名/验证算法
	 */
	public static final String SIGNATURE_ALGORITHM="MD5withRSA";
	
	/**
	 * RSA密钥长度，RSA算法的默认密钥长度是1024
	 * 密钥长度必须是64的倍数，在512到65536位之间
	 * */
	private static final int KEY_SIZE=512;
	//公钥
	private static final String PUBLIC_KEY="RSAPublicKey";
	
	//私钥
	private static final String PRIVATE_KEY="RSAPrivateKey";
	
	/**
	 * 初始化密钥对
	 * @return Map 甲方密钥的Map
	 * */
	public static Map<String,Object> initKeyPair() throws Exception{
		KeyPairGenerator keyPairGenerator=KeyPairGenerator.getInstance(KEY_ALGORITHM);   // 实例化密钥生成器
		keyPairGenerator.initialize(KEY_SIZE);   // 初始化密钥生成器
		KeyPair keyPair=keyPairGenerator.generateKeyPair();   // 生成密钥对
		RSAPublicKey publicKey=(RSAPublicKey) keyPair.getPublic();   // 甲方公钥
		RSAPrivateKey privateKey=(RSAPrivateKey) keyPair.getPrivate();   // 甲方私钥
		
		//将密钥存储在map中
		Map<String,Object> keyMap=new HashMap<String,Object>();
		keyMap.put(PUBLIC_KEY, publicKey);
		keyMap.put(PRIVATE_KEY, privateKey);
		return keyMap;
	}
	
	/**
	 * 签名
	 * @param data待签名数据
	 * @param privateKey 密钥
	 * @return byte[] 数字签名
	 * */
	public static byte[] sign(byte[] data,byte[] privateKey) throws Exception{
		PKCS8EncodedKeySpec pkcs8KeySpec=new PKCS8EncodedKeySpec(privateKey);   //取得私钥
		PrivateKey priKey=KeyFactory.getInstance(KEY_ALGORITHM).generatePrivate(pkcs8KeySpec);   //生成私钥
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);   //实例化Signature
		signature.initSign(priKey);   //初始化Signature
		signature.update(data);   // 私钥加密数据得到数字签名
		return signature.sign();
	}
	
	/**
	 * 校验数字签名
	 * @param data 待校验数据
	 * @param publicKey 公钥
	 * @param sign 数字签名
	 * @return boolean 校验成功返回true，失败返回false
	 * */
	public static boolean verify(byte[] data, byte[] publicKey, byte[] sign) throws Exception{
		KeyFactory keyFactory=KeyFactory.getInstance(KEY_ALGORITHM);
		X509EncodedKeySpec x509KeySpec=new X509EncodedKeySpec(publicKey);   // 初始化公钥
		PublicKey pubKey=keyFactory.generatePublic(x509KeySpec);   // 产生公钥
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);   //实例化Signature
		signature.initVerify(pubKey);   // 初始化Signature
		signature.update(data);   // 更新
		return signature.verify(sign);   // 验证
	}
	
	/**
	 * 取得私钥
	 * @param keyMap 密钥map
	 * @return byte[] 私钥
	 * */
	public static byte[] getPrivateKey(Map<String,Object> keyMap){
		Key key=(Key) keyMap.get(PRIVATE_KEY);
		return key.getEncoded();
	}
	
	/**
	 * 取得公钥
	 * @param keyMap 密钥map
	 * @return byte[] 公钥
	 * */
	public static byte[] getPublicKey(Map<String,Object> keyMap) throws Exception{
		Key key=(Key) keyMap.get(PUBLIC_KEY);
		return key.getEncoded();
	}
	
	/**
	 * @param args
	 * @throws Exception 
	 */
	public static void main(String[] args) throws Exception {
		Map<String,Object> keyMap=RSADigitalSignatureAlgorithm.initKeyPair();    //生成密钥对
		byte[] publicKey=RSADigitalSignatureAlgorithm.getPublicKey(keyMap);     //公钥
		byte[] privateKey=RSADigitalSignatureAlgorithm.getPrivateKey(keyMap);   //私钥
		System.out.println("公钥："+Base64.encodeBase64String(publicKey));
		System.out.println("私钥："+Base64.encodeBase64String(privateKey));
		
		System.out.println("================密钥对构造完毕,甲方将公钥公布给乙方，开始进行加密数据的传输=============");
		
		String data="RSA数字签名算法";
		System.out.println("数据原文：" + data);
		
		// 甲方进行数据的加密
		byte[] sign=RSADigitalSignatureAlgorithm.sign(data.getBytes(), privateKey);
		System.out.println("数字签名：" + Base64.encodeBase64String(sign));
		
		// 验证签名
		boolean status=RSADigitalSignatureAlgorithm.verify(data.getBytes(), publicKey, sign);
		System.out.println("验证结果：" + status);
		
		// 篡改数据
		String tamperedData = data.replace("R", "U");
		status=RSADigitalSignatureAlgorithm.verify(tamperedData.getBytes(), publicKey, sign);
		System.out.println("验证结果（篡改数据后）：" + status);
	}
}