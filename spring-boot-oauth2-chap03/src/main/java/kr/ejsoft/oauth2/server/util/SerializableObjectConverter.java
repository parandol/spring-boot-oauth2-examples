package kr.ejsoft.oauth2.server.util;

import java.util.Base64;

import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.util.SerializationUtils;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

public class SerializableObjectConverter {
	public static String serializeAccessToken(OAuth2AccessToken object) {
		try {
			byte[] bytes = SerializationUtils.serialize(object);
			return Base64.getEncoder().encodeToString(bytes);
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}
	}

	public static OAuth2AccessToken deserializeAccessToken(String encodedObject) {
		try {
			byte[] bytes = Base64.getDecoder().decode(encodedObject);
			return (OAuth2AccessToken) SerializationUtils.deserialize(bytes);
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}
	}

	public static String serializeRefreshToken(OAuth2RefreshToken object) {
		try {
			byte[] bytes = SerializationUtils.serialize(object);
			return Base64.getEncoder().encodeToString(bytes);
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}
	}

	public static OAuth2RefreshToken deserializeRefreshToken(String encodedObject) {
		try {
			byte[] bytes = Base64.getDecoder().decode(encodedObject);
			return (OAuth2RefreshToken) SerializationUtils.deserialize(bytes);
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}
	}
	
	public static String serializeAuthentication(OAuth2Authentication object) {
		try {
			byte[] bytes = SerializationUtils.serialize(object);
			return Base64.getEncoder().encodeToString(bytes);
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}
	}

	public static OAuth2Authentication deserializeAuthentication(String encodedObject) {
		try {
			byte[] bytes = Base64.getDecoder().decode(encodedObject);
			return (OAuth2Authentication) SerializationUtils.deserialize(bytes);
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}
	}
}
