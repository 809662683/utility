package org.jxq.utility.csrf;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.TreeMap;

import org.jxq.utility.crypt.Crypter;
import org.jxq.utility.date.DateUtil;
import org.jxq.utility.string.StringUtil;


/**
 * 安全CSRF Token生成器
 * @author will
 *
 */
public class SecureCSRFTokenGenerator {
	
	/**
	 * 生成CSRF Token
	 * @param dataMap 数据Map，比如{ "uid": "1001", "browser": "chrome", "ip": "xxx.xx.xx.xx" ... }
	 *         最好能唯一标识该Token
	 * @param key 签名用的key
	 * @param tokenTimeoutSeconds CSRF Token过期秒数
	 * @return CSRF Token
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	public static String createCSRFToken(Map<String, String> dataMap, String key, long tokenTimeoutSeconds) 
			throws InvalidKeyException, NoSuchAlgorithmException {
		if(dataMap == null || dataMap.isEmpty() || StringUtil.isEmpty(key) || tokenTimeoutSeconds <= 0) {
			throw new IllegalArgumentException("dataMap should not empty, key not blank or empty and csrfTokenTimeoutSeconds should > 0");
		}
		
		if(!(dataMap instanceof TreeMap<?, ?>)) {
			dataMap = new TreeMap<String, String>(dataMap);   // 转成TreeMap，使按Key排序
		}
		
		long hashTimeInSeconds = DateUtil.getCurrentTimeInSeconds();   // 进行哈希计算时的时间
		String hashedStr = getHashedStr(dataMap, hashTimeInSeconds, tokenTimeoutSeconds, key);   // 用HMAC-SHA1进行不可逆哈希
		String csrfTokenRawStr = hashedStr + "|" + hashTimeInSeconds + "|" + tokenTimeoutSeconds;
		return Crypter.base64Encode(csrfTokenRawStr);
	}
	
	/**
	 * 验证CSRF Token是否有效
	 * @param dataMap   数据Map
	 * @param csrfToken 待验证的CSRF Token
	 * @param key
	 * @return
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	public static boolean verifyCSRFToken(Map<String, String> dataMap, String csrfToken, String key) 
			throws InvalidKeyException, NoSuchAlgorithmException {
		if(dataMap == null || dataMap.isEmpty() || StringUtil.isEmpty(csrfToken) || StringUtil.isEmpty(key)) {
			return false;
		}
		
		// 解拆Token
		String[] dataArray = Crypter.base64Decode(csrfToken).split("\\|");
		String hashedStr = dataArray[0];
		long hashTimeInSeconds = Long.parseLong(dataArray[1]);
		long tokenTimeoutSeconds = Integer.parseInt(dataArray[2]);
		
		// 判断CSRF Token是否已过期
		long curTimeInSeconds = DateUtil.getCurrentTimeInSeconds();
		if(curTimeInSeconds - hashTimeInSeconds > tokenTimeoutSeconds) {   // CSRF Token已过期
			return false;
		}
		
		// 验证Token是否有效
		if(hashedStr.equals(getHashedStr(dataMap, hashTimeInSeconds, tokenTimeoutSeconds, key))) {
			return true;
		}
		
		return false;
	}
	
	private static String getHashedStr(Map<String, String> dataMap, long hashTimeInSeconds, long tokenTimeoutSeconds, String key) 
			throws InvalidKeyException, NoSuchAlgorithmException {
		if(!(dataMap instanceof TreeMap<?, ?>)) {
			dataMap = new TreeMap<String, String>(dataMap);   // 转成TreeMap，使按Key排序
		}
		
		// 拼接待进行签名的数据
		StringBuilder rawDataBuilder = new StringBuilder();
		for(Map.Entry<String, String> entry: dataMap.entrySet()) {
			rawDataBuilder.append(entry.getKey());
			rawDataBuilder.append(":");
			rawDataBuilder.append(entry.getValue());
			rawDataBuilder.append("|");
		}
		rawDataBuilder.append(hashTimeInSeconds);   // 拼接当前时间秒数
		rawDataBuilder.append("|");
		rawDataBuilder.append(tokenTimeoutSeconds);   // 拼接CSRF Token过期秒数
		return Crypter.hmacSHA1(rawDataBuilder.toString(), key);
	}
	
	public static void main(String[] args) throws Exception {
		Map<String, String> dataMap = new TreeMap<String, String>();
		dataMap.put("uid", "1000");
		dataMap.put("ip", "127.0.0.1");
		dataMap.put("browser", "chrome");
		String key = "abc";
		int csrfTokenTimeoutSeconds = 600;
		
		String csrfToken = createCSRFToken(dataMap, key, csrfTokenTimeoutSeconds);
		System.out.println(verifyCSRFToken(dataMap, csrfToken, key));
	}

}
