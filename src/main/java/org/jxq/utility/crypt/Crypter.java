package org.jxq.utility.crypt;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;

/**
 * 编解码、数字签名、摘要、加密解密工具类
 * 
 * @author will
 *
 */
public class Crypter{
	
	/*
	 * -------------------------------------------------------------------------------
	 * Base64编码解码算法（注意不是加密解密）
	 * -------------------------------------------------------------------------------
	 */

	/**
	 * Base64编码
	 * @param data 字符串数据
	 * @return
	 */
	public static String base64Encode(String data) {
		if(data == null) {
			return null;
		}
		return Base64.encodeBase64String(data.getBytes());
	}
	
	/**
	 * Base64编码
	 * @param data 字节数组数据
	 * @return
	 */
	public static String base64Encode(byte[] data) {
		if(data == null) {
			return null;
		}
		return Base64.encodeBase64String(data);
	}
	
	/**
	 * Base64编码成字节数组
	 * @param data
	 * @return
	 */
	public static byte[] base64EncodeToBytes(String data) {
		if(data == null) {
			return null;
		}
		return Base64.encodeBase64(data.getBytes());
	}
	
	/**
	 * Base64编码成字节数组
	 * @param data
	 * @return
	 */
	public static byte[] base64EncodeToBytes(byte[] data) {
		if(data == null) {
			return null;
		}
		return Base64.encodeBase64(data);
	}
	
	/**
	 * Base64解码
	 * @param data
	 * @return
	 */
	public static String base64Decode(String data) {
		if(data == null) {
			return null;
		}
		return new String(Base64.decodeBase64(data));
	}
	
	/**
	 * Base64解码
	 * @param data
	 * @return
	 */
	public static String base64Decode(byte[] data) {
		if(data == null) {
			return null;
		}
		return new String(Base64.decodeBase64(data));
	}
	
	/**
	 * Base64解码成字节数组
	 * @param data
	 * @return
	 */
	public static byte[] base64DecodeToBytes(String data) {
		if(data == null) {
			return null;
		}
		return Base64.decodeBase64(data);
	}
	
	/**
	 * Base64解码成字节数组
	 * @param data
	 * @return
	 */
	public static byte[] base64DecodeToBytes(byte[] data) {
		if(data == null) {
			return null;
		}
		return Base64.decodeBase64(data);
	}
	
	/*
	 * -------------------------------------------------------------------------------
	 * MD5摘要算法
	 * -------------------------------------------------------------------------------
	 */
	
	/**
	 * MD5签名，返回32位16进制MD5值
	 * @param data 字节数据
	 * @return
	 */
	public static String md5(byte[] data) {
		if(data == null) {
			return null;
		}
		return DigestUtils.md5Hex(data);
	}
	
	/**
	 * MD5签名，返回32位16进制MD5值
	 * @param data 字符串数据
	 * @return
	 */
	public static String md5(String data) {
		if(data == null) {
			return null;
		}
		return DigestUtils.md5Hex(data);
	}
	
	/**
	 * MD5签名，返回字节数组
	 * @param data
	 * @return
	 */
	public static byte[] md5ToBytes(byte[] data) {
		if(data == null) {
			return null;
		}
		return DigestUtils.md5(data);
	}
	
	/**
	 * MD5签名，返回字节数组
	 * @param data
	 * @return
	 */
	public static byte[] md5ToBytes(String data) {
		if(data == null) {
			return null;
		}
		return DigestUtils.md5(data);
	}
	
	/*
	 * -------------------------------------------------------------------------------
	 * SHA1摘要算法
	 * -------------------------------------------------------------------------------
	 */
	
	/**
	 * 返回16进制的SHA1摘要字符串值
	 * @param data 字节数据
	 * @return
	 */
	public static String sha1(byte[] data) {
		if(data == null) {
			return null;
		}
		return DigestUtils.sha1Hex(data);
	}
	
	/**
	 * 返回16进制的SHA1摘要字符串值
	 * @param data 字符串数据
	 * @return
	 */
	public static String sha1(String data) {
		if(data == null) {
			return null;
		}
		return DigestUtils.sha1Hex(data);
	}
	
	/**
	 * SHA1摘要，返回字节数组
	 * @param data
	 * @return
	 */
	public static byte[] sha1ToBytes(byte[] data) {
		if(data == null) {
			return null;
		}
		return DigestUtils.sha1(data);
	}
	
	/**
	 * SHA1摘要，返回字节数组
	 * @param data
	 * @return
	 */
	public static byte[] sha1ToBytes(String data) {
		if(data == null) {
			return null;
		}
		return DigestUtils.sha1(data);
	}
	
	/*
	 * -------------------------------------------------------------------------------
	 * HMAC SHA1摘要算法，该算法特点是：
	 * <li>对于相似度较高的字符串得到的签名值差异比较大</li>
	 * <li>常用作签名算法</li>
	 * -------------------------------------------------------------------------------
	 */
	
	private static final String HMAC_SHA1 = "HmacSHA1";
	
	/**
	 * HMAC SHA1签名或摘要算法，
	 * @param data 待摘要的字节数据
	 * @param key  使用的key
	 * @return
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	public static String hmacSHA1(byte[] data, byte[] key) throws NoSuchAlgorithmException, InvalidKeyException  {
		if(data == null || key == null) {
			return null;
		}
		
		SecretKeySpec signingKey = new SecretKeySpec(key, HMAC_SHA1);
		byte[] rawHmac = null;
		Mac mac = Mac.getInstance(HMAC_SHA1);
		mac.init(signingKey);
		rawHmac = mac.doFinal(data);
		return DigestUtils.md5Hex(rawHmac);
	}
	
	/**
	 * HMAC SHA1签名或摘要算法
	 * @param data
	 * @param key
	 * @return
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 */
	public static String hmacSHA1(String data, String key) throws InvalidKeyException, NoSuchAlgorithmException {
		if(data == null || key == null) {
			return null;
		}
		
		return hmacSHA1(data.getBytes(), key.getBytes());
	}
	
	/*
	 * -------------------------------------------------------------------------------
	 * AES加密解密，是一种常见的对称加密解密算法
	 * -------------------------------------------------------------------------------
	 */
	
	private static final String AES = "AES";
    private static final int AES_KEY_SIZE = 128;
    private static final int AES_CACHE_SIZE = 1024;
    
    /**
     * 生成AES随机密钥
     * 
     * @return
     * @throws Exception
     */
    public static String getAESSecretKey() throws Exception {
        return getAESSecretKey(null);
    }
    
    /**
     * 生成密钥
     * 
     * @param seed 密钥种子
     * @return
     * @throws Exception
     */
    public static String getAESSecretKey(String seed) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(AES);
        SecureRandom secureRandom = null;
        if (!StringUtils.isEmpty(seed)) {
            secureRandom = new SecureRandom(seed.getBytes());
        } 
        else {
            secureRandom = new SecureRandom();
        }
        keyGenerator.init(AES_KEY_SIZE, secureRandom); 
        SecretKey secretKey = keyGenerator.generateKey(); 
        return base64Encode(secretKey.getEncoded());
    }
    
    /**
     * AES加密得到加密数据的字节数组
     * 
     * @param data 原始数据的字节数组
     * @param key  AES Key，通过<code>getAESSecretKey</code>生成
     * @return
     * @throws Exception
     */
    public static byte[] aesEncrypt(byte[] data, String key) throws Exception {
    	if(data == null || key == null) {
    		return null;
    	}
    	
        Key k = toAESKey(base64DecodeToBytes(key));
        byte[] raw = k.getEncoded();
        SecretKeySpec secretKeySpec = new SecretKeySpec(raw, AES); 
        Cipher cipher = Cipher.getInstance(AES); 
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        return cipher.doFinal(data);
    }
    
    /**
     * AES解密得到原始数据的字节数组
     * 
     * @param encryptedBytesData 加密数据的字节数组
     * @param key
     * @return 原始数据字节数组
     * @throws Exception
     */
    public static byte[] aesDecrypt(byte[] encryptedBytesData, String key) throws Exception {
    	if(encryptedBytesData == null || key == null) {
    		return null;
    	}
    	
        Key k = toAESKey(base64DecodeToBytes(key));
        byte[] raw = k.getEncoded(); 
        SecretKeySpec secretKeySpec = new SecretKeySpec(raw, AES); 
        Cipher cipher = Cipher.getInstance(AES); 
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        return cipher.doFinal(encryptedBytesData);
    }
    
    /**
     * 文件AES加密
     * 
     * @param key
     * @param sourceFilePath
     * @param destFilePath
     * @throws Exception
     */
    public static void aesEncryptFile(String key, String sourceFilePath, String destFilePath) throws Exception {
    	if(key == null || StringUtils.isEmpty(sourceFilePath) || StringUtils.isEmpty(destFilePath)) {
    		return;
    	}
    	
        File sourceFile = new File(sourceFilePath);
        File destFile = new File(destFilePath); 
        if (sourceFile.exists() && sourceFile.isFile()) {
            if (!destFile.getParentFile().exists()) {
                destFile.getParentFile().mkdirs();
            }
            destFile.createNewFile();
            InputStream in = new FileInputStream(sourceFile);
            OutputStream out = new FileOutputStream(destFile);
            Key k = toAESKey(base64DecodeToBytes(key));
            byte[] raw = k.getEncoded(); 
            SecretKeySpec secretKeySpec = new SecretKeySpec(raw, AES); 
            Cipher cipher = Cipher.getInstance(AES); 
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            CipherInputStream cin = new CipherInputStream(in, cipher);
            byte[] cache = new byte[AES_CACHE_SIZE];
            int nRead = 0;
            while ((nRead = cin.read(cache)) != -1) {
                out.write(cache, 0, nRead);
                out.flush();
            }
            
            // 关闭流
            if(out != null) {
            	out.close();
            }
            if(cin != null) {
            	cin.close();
            }
            if(in != null) {
            	in.close();
            }
        }
    }
    
    /**
     * 文件AES解密
     * 
     * @param key
     * @param sourceFilePath
     * @param destFilePath
     * @throws Exception
     */
    public static void aesDecryptFile(String key, String sourceFilePath, String destFilePath) throws Exception {
    	if(key == null || StringUtils.isEmpty(sourceFilePath) || StringUtils.isEmpty(destFilePath)) {
    		return;
    	}
    	
        File sourceFile = new File(sourceFilePath);
        File destFile = new File(destFilePath); 
        if (sourceFile.exists() && sourceFile.isFile()) {
            if (!destFile.getParentFile().exists()) {
                destFile.getParentFile().mkdirs();
            }
            destFile.createNewFile();
            FileInputStream in = new FileInputStream(sourceFile);
            FileOutputStream out = new FileOutputStream(destFile);
            Key k = toAESKey(base64DecodeToBytes(key));
            byte[] raw = k.getEncoded(); 
            SecretKeySpec secretKeySpec = new SecretKeySpec(raw, AES); 
            Cipher cipher = Cipher.getInstance(AES); 
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
            CipherOutputStream cout = new CipherOutputStream(out, cipher);
            byte[] cache = new byte[AES_CACHE_SIZE];
            int nRead = 0;
            while ((nRead = in.read(cache)) != -1) {
                cout.write(cache, 0, nRead);
                cout.flush();
            }
            
            // 关闭流
            if(cout != null) {
            	cout.close();
            }
            if(out != null) {
            	out.close();
            }
            if(in != null) {
            	in.close();
            }
        }
    }
    
    /**
     * 转换得到AES密钥
     * 
     * @param key
     * @return
     * @throws Exception
     */
    private static Key toAESKey(byte[] key) throws Exception {
    	if(key == null) {
    		return null;
    	}
    	
        SecretKey secretKey = new SecretKeySpec(key, AES);
        return secretKey;
    }
	
	/*
	 * -------------------------------------------------------------------------------
	 * RSA加密解密，RSA是一种非对称加密解密算法
	 * -------------------------------------------------------------------------------
	 */
	
	private int RSA_ORIGIN_LEN = 128;                    // 明文块的长度 它必须小于密文块的长度-11
	private static final int RSA_ENCRYPT_LEN = 256;   // RSA密文块长度
	
	/**
	 * 生成RAS公钥密钥对
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 */
	public static KeyPair initRSAKeyPair() throws NoSuchAlgorithmException, NoSuchPaddingException {
		// RSA加密算法：创建密钥对，长度采用2048
		KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA");
		kg.initialize(RSA_ENCRYPT_LEN * 8);
		return kg.generateKeyPair();
	}
	
	/**
	 * 从密钥对中提取RSA公钥
	 * @param keyPair
	 * @return
	 */
	public static RSAPublicKey getRSAPublicKey(KeyPair keyPair) {
		return (RSAPublicKey) keyPair.getPublic();
	}
	
	/**
	 * 从密钥对中提取RSA私钥
	 * @param keyPair
	 * @return
	 */
	public static RSAPrivateKey getRSAPrivateKey(KeyPair keyPair) {
		return (RSAPrivateKey) keyPair.getPrivate();
	}
	
	/**
	 * RSA数据加密
	 * 
	 * @param data      原始数据字节数组
	 * @param publicKey 公钥
	 * @return 密文
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 */
	public static byte[] rsaEncrypt(byte[] data, RSAPublicKey publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, 
		InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		if(data == null || publicKey == null) {
			return null;
		}
		
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		return cipher.doFinal(data);
	}
	
	/**
	 * 数据RSA解密
	 * 
	 * @param encryptedBytesData RSA加密数据的字节数组
	 * @return 原始明文数据的字节数组
	 * @throws InvalidKeyException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 */
	public static byte[] rsaDecrypt(byte[] encryptedBytesData, RSAPrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, 
		InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
	    Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		return cipher.doFinal(encryptedBytesData);
	}
	
	/**
	 * 文件RSA加密
	 * 
	 * @param sourceFilePath
	 * @param destFilePath
	 * @param publicKey
	 * @throws IOException
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	public void rsaEncryptFile(String sourceFilePath, String destFilePath, RSAPublicKey publicKey) throws IOException, InvalidKeyException, 
		NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		// 读入
		FileInputStream fis = new FileInputStream(sourceFilePath);
		BufferedInputStream bis = new BufferedInputStream(fis);
		byte[] originbyte = new byte[RSA_ORIGIN_LEN];
		
		// 写出
		FileOutputStream fos = new FileOutputStream(new File(destFilePath));
		BufferedOutputStream bos = new BufferedOutputStream(fos);
		byte[] encryptbyte;
		
		// 分段加密
		while (bis.read(originbyte) > 0) {
			encryptbyte = rsaEncrypt(originbyte, publicKey);
			bos.write(encryptbyte);
			originbyte = new byte[RSA_ORIGIN_LEN];
		}
		
		bos.flush();   // 刷到磁盘
		
		// 关闭资源
		if (fis != null) {
			fis.close();
		}
		if (fos != null) {
			fos.close();
		}
		if(bos != null) {
			bos.close();
		}
	}

	/**
	 * 文件RSA解密
	 * 
	 * @param sourceFilePath
	 * @param destFilePath
	 * @param privateKey
	 * @throws IOException
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	public void rsaDecryptFile(String sourceFilePath, String destFilePath, RSAPrivateKey privateKey) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		// 读入
		FileInputStream fis = new FileInputStream(sourceFilePath);
		BufferedInputStream bis = new BufferedInputStream(fis);
		byte[] encryptbyte = new byte[RSA_ENCRYPT_LEN];
		
		// 写出
		FileOutputStream fos = new FileOutputStream(new File(destFilePath));
		BufferedOutputStream bos = new BufferedOutputStream(fos);
		byte[] originbyte = null;
		while (bis.read(encryptbyte) > 0) {
			originbyte = rsaDecrypt(encryptbyte, privateKey);
			bos.write(originbyte);
			encryptbyte = new byte[RSA_ENCRYPT_LEN];
		}
		
		bos.flush();
		
		if(fis != null) {
			fis.close();
		}
		if(fos != null) {
			fos.close();
		}
		if(bos != null) {
			bos.close();
		}
	}
	
	/**
	 * 从文件中得到RSA公钥
	 * 
	 * @param file
	 * @return 公钥
	 * @throws ClassNotFoundException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws IOException
	 */
	public static RSAPublicKey getRSAPublicKey(File file) throws ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, 
		IOException {
		return (RSAPublicKey) getRSAKey(file, 0);
	}

	/**
	 * 从文件中得到RSA私钥
	 * 
	 * @param file 保存私钥的文件
	 * @return 私钥
	 * @throws IOException 
	 * @throws InvalidKeySpecException 
	 * @throws NoSuchAlgorithmException 
	 * @throws ClassNotFoundException 
	 */
	public static RSAPrivateKey getRSAPrivateKey(File file) throws ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, 
		IOException {
		return (RSAPrivateKey) getRSAKey(file, 1);
	}
	
	/**
	 * 将RSA公钥保存至文件
	 * 
	 * @param file  待写入的文件
	 * @return true 写入成功;false 写入失败
	 * @throws IOException 
	 */
	public static boolean saveRSAPublicKey(File file, RSAPublicKey publicKey) throws IOException {
		return saveRSAKey(publicKey, file);
	}

	/**
	 * 将RSA私钥保持至文件
	 * 
	 * @param file  待写入的文件
	 * @return true 写入成功;false 写入失败
	 * @throws IOException 
	 */
	public static boolean saveRSAPrivateKey(File file, RSAPrivateKey privateKey) throws IOException {
		return saveRSAKey(privateKey, file);
	}

	/**
	 * 将RSA Key保存到文件
	 * 
	 * @param key
	 * @param file
	 * @return
	 * @throws IOException 
	 */
	private static boolean saveRSAKey(Key key, File file) throws IOException {
		boolean result;
		FileOutputStream fos = null;
		ObjectOutputStream oos = null;
		try {
			fos = new FileOutputStream(file);
			oos = new ObjectOutputStream(fos);
			// 公钥默认使用的是X.509编码，私钥默认采用的是PKCS #8编码
			byte[] encode = key.getEncoded();
			// 注意，此处采用writeObject方法，读取时也要采用readObject方法
			oos.writeObject(encode);
			result = true;
		} 
		catch (IOException e) {
			result = false;
		} 
		finally {
			if(fos != null) {
				try {
						fos.close();
				} 
				catch (IOException e) {
					throw e;
				}
			}
			if(oos != null) {
				try {
					oos.close();
				}
				catch(IOException e) {
					throw e;
				}
			}
		}
		return result;
	}
	
	private static Key getRSAKey(File file, int mode) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, 
		InvalidKeySpecException {
		FileInputStream fis = new FileInputStream(file);
		ObjectInputStream ois = new ObjectInputStream(fis);
		byte[] keybyte = (byte[]) ois.readObject();
		ois.close();   // 关闭资源
		
		KeyFactory keyfactory = KeyFactory.getInstance("RSA");
		// 得到公钥或是私钥
		Key key = null;
		if (mode == 0) {
			X509EncodedKeySpec x509eks = new X509EncodedKeySpec(keybyte);
			key = keyfactory.generatePublic(x509eks);
		} else {
			PKCS8EncodedKeySpec pkcs8eks = new PKCS8EncodedKeySpec(keybyte);
			key = keyfactory.generatePrivate(pkcs8eks);
		}
		return key;
	}
	
}