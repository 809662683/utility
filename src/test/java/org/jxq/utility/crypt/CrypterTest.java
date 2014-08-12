package org.jxq.utility.crypt;

import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.junit.Assert;
import org.junit.Test;

import static org.jxq.utility.crypt.Crypter.*;

public class CrypterTest {
	
	@Test
	public void testBase64() {
		String encodedData = base64Encode("hello");
		Assert.assertEquals("hello", base64Decode(encodedData));
		
		encodedData = base64Encode("");
		Assert.assertEquals("", encodedData);
		Assert.assertEquals("", base64Decode(encodedData));
		
		Assert.assertEquals(base64Encode("hello"), base64Encode("hello".getBytes()));
		Assert.assertEquals(base64Encode("hello"), new String(base64EncodeToBytes("hello")));
		Assert.assertArrayEquals(base64EncodeToBytes("hello".getBytes()), base64EncodeToBytes("hello"));
		
		String base64EncodedDataStr = base64Encode("hello");
		Assert.assertEquals(base64Decode(base64EncodedDataStr), base64Decode(base64EncodedDataStr.getBytes()));
		Assert.assertArrayEquals(base64DecodeToBytes(base64EncodedDataStr), base64DecodeToBytes(base64EncodedDataStr.getBytes()));
		
		Assert.assertEquals("", base64Encode(""));
		Assert.assertEquals("", base64Decode(""));
	}
	
	@Test
	public void testMD5() {
		Assert.assertEquals(md5("hello"), md5("hello".getBytes()));
		
		byte[] byteData1 = md5ToBytes("will");
		byte[] byteData2 = md5ToBytes("will".getBytes());
		Assert.assertArrayEquals(byteData1, byteData2);
	}
	
	@Test
	public void testSHA1() {
		Assert.assertEquals(sha1("hello"), sha1("hello".getBytes()));
		
		byte[] byteData1 = sha1ToBytes("will");
		byte[] byteData2 = sha1ToBytes("will".getBytes());
		Assert.assertArrayEquals(byteData1, byteData2);
	}
	
	@Test
	public void testHMACSHA1() throws InvalidKeyException, NoSuchAlgorithmException {
		Assert.assertEquals(hmacSHA1("hello", "abc"), hmacSHA1("hello".getBytes(), "abc".getBytes()));
	}
	
	@Test
	public void testRSA() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, 
		BadPaddingException, IOException, ClassNotFoundException, InvalidKeySpecException {
		KeyPair keyPair = initRSAKeyPair();
		RSAPublicKey rsaPublicKey = getRSAPublicKey(keyPair);
		RSAPrivateKey rsaPrivateKey = getRSAPrivateKey(keyPair);
		
		// 保存公钥私钥到文件
		saveRSAPublicKey(new File("/Users/jiangxiaoqiang/rsa.pub"), rsaPublicKey);
		saveRSAPrivateKey(new File("/Users/jiangxiaoqiang/rsa.private"), rsaPrivateKey);
		
		// 从文件中提取公钥私钥
		Assert.assertEquals(rsaPublicKey.getPublicExponent(), getRSAPublicKey(new File("/Users/jiangxiaoqiang/rsa.pub")).getPublicExponent());
		Assert.assertEquals(rsaPrivateKey.getPrivateExponent(), getRSAPrivateKey(new File("/Users/jiangxiaoqiang/rsa.private")).getPrivateExponent());
		
		// 待加密的数据
		String data = "hello";
		byte[] dataBytes = data.getBytes();
		
		// 加密
		byte[] encryptedBytes = rsaEncrypt(dataBytes, rsaPublicKey);
		
		// 解密
		byte[] decryptedBytes = rsaDecrypt(encryptedBytes, rsaPrivateKey);
		Assert.assertEquals(data, new String(decryptedBytes));
	}
	
	@Test
	public void testAES() throws Exception {
//		Assert.assertNotNull(toAESKey("".getBytes()));
		byte[] data = "hello".getBytes();
		String key = getAESSecretKey();
		byte[] encryptedBytesData = aesEncrypt(data, key);
		Assert.assertNotNull(encryptedBytesData);
		Assert.assertTrue(encryptedBytesData.length > 0);
		
		byte[] decryptedBytesData = aesDecrypt(encryptedBytesData, key);
		Assert.assertArrayEquals(data, decryptedBytesData);
	}

}
