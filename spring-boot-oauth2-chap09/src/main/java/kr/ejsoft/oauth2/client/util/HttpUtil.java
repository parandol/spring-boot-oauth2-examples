package kr.ejsoft.oauth2.client.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Base64.Encoder;

import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;

public class HttpUtil {
	private static final Logger log = LoggerFactory.getLogger(HttpUtil.class);

	public static HttpPost buildHttpPost(String url, Map<String, String> paramMap, String authorizationHeader) {
		//
		log.debug("BuildHttpPost() url : {}, Header : {}", url, authorizationHeader);
		HttpPost post = new HttpPost(url);
		if (authorizationHeader != null) {
			post.addHeader("Authorization", authorizationHeader);
		}
		
		List<NameValuePair> urlParameters = new ArrayList<>();
		for (Map.Entry<String, String> entry : paramMap.entrySet()) {
			urlParameters.add(new BasicNameValuePair(entry.getKey(), entry.getValue()));
		}
		
		try {
			post.setEntity(new UrlEncodedFormEntity(urlParameters));
		} catch (UnsupportedEncodingException e) {
			log.error(e.getMessage(), e);
		}
		return post;
	}

	public static String executeHttp(HttpPost post) {
		//
		String result = null;
		try {
			HttpClient client = HttpClientBuilder.create().build();
			
			HttpResponse response = client.execute(post);
			BufferedReader rd = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
	
			StringBuffer resultBuffer = new StringBuffer();
			String line = "";
			while ((line = rd.readLine()) != null) {
				resultBuffer.append(line);
			}
			
			log.debug("Response body : '{}'", resultBuffer.toString());
			result = resultBuffer.toString();
			
			// response.getStatusLine().getStatusCode();
		} catch (IOException e) {
			log.error(e.getMessage(), e);
		}
		
		return result;
	}
	public static <T> T executePostAndParseResult(HttpPost post, Class<T> clazz) {
		//
		T result = null;
		try {
			String res = HttpUtil.executeHttp(post);
			
			ObjectMapper mapper = new ObjectMapper();
			result = mapper.readValue(res, clazz);
		} catch (IOException e) {
			log.error(e.getMessage(), e);
		}
		
		return result;
	}
	
	public static String makeAuthroizationBasicHeader(String clientId, String clientSecret) {
		String ret = null;
		try {
			Encoder encoder = Base64.getEncoder();
			String toEncodeString = String.format("%s:%s", clientId, clientSecret);
			ret = "Basic " + encoder.encodeToString(toEncodeString.getBytes("UTF-8"));
		} catch (UnsupportedEncodingException e) {
			log.error(e.getMessage(), e);
		}
		return ret;
	}
	
	public static String makeAuthroizationTokenHeader(String type, String token) {
		return String.format("%s %s", type, token);
	}
	
	public static String extractTokenId(String value) {
		//
		if (value == null) {
			//
			return null;
		}
		
		try {
			//
			MessageDigest digest = MessageDigest.getInstance("MD5");
			
			byte[] bytes = digest.digest(value.getBytes("UTF-8"));
			return String.format("%032x", new BigInteger(1, bytes));
		}
		catch (NoSuchAlgorithmException e) {
			//
			throw new IllegalStateException("MD5 algorithm not available.  Fatal (should be in the JDK).");
		}
		catch (UnsupportedEncodingException e) {
			//
			throw new IllegalStateException("UTF-8 encoding not available.  Fatal (should be in the JDK).");
		}
	}
}
