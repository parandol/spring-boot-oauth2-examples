package kr.ejsoft.oauth2.server.service;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import kr.ejsoft.oauth2.server.dao.OAuthDAO;
import kr.ejsoft.oauth2.server.model.OAuthRefreshToken;

public class OAuthJwtTokenStore extends JwtTokenStore {

	private static final Logger log = LoggerFactory.getLogger(OAuthJwtTokenStore.class);

	@Autowired
	@Qualifier("oauthDAO")
	private OAuthDAO dao;

	/**
	 * Create a JwtTokenStore with this token enhancer (should be shared with the DefaultTokenServices if used).
	 * 
	 * @param jwtTokenEnhancer
	 */
	public OAuthJwtTokenStore(JwtAccessTokenConverter jwtTokenEnhancer) {
		super(jwtTokenEnhancer);
	}


	@Override
	public void storeRefreshToken(OAuth2RefreshToken refreshToken, OAuth2Authentication authentication) {
		OAuthRefreshToken crt = new OAuthRefreshToken();
		crt.setId(UUID.randomUUID().toString() + UUID.randomUUID().toString());
		crt.setTokenId(extractTokenKey(refreshToken.getValue()));
		crt.setTokenObject(refreshToken);
		crt.setAuthenticationObject(authentication);
		crt.setUsername(authentication.isClientOnly() ? null : authentication.getName());
		crt.setClientId(authentication.getOAuth2Request().getClientId());
		dao.saveRefreshToken(crt);
	}

	@Override
	public OAuth2RefreshToken readRefreshToken(String tokenValue) {
		OAuth2RefreshToken token = super.readRefreshToken(tokenValue);
		if(token != null) {
			OAuthRefreshToken refreshToken = dao.findRefreshTokenByTokenId(extractTokenKey(tokenValue));
			return refreshToken != null ? refreshToken.getTokenObject() : null;
		}
		return token;
	}

	@Override
	public OAuth2Authentication readAuthenticationForRefreshToken(OAuth2RefreshToken refreshToken) {
		OAuth2Authentication oauth = super.readAuthenticationForRefreshToken(refreshToken);
		if(oauth != null) {
			OAuthRefreshToken rtk = dao.findRefreshTokenByTokenId(extractTokenKey(refreshToken.getValue()));
			return rtk != null ? rtk.getAuthenticationObject() : null;
		}
		return oauth;
	}

	@Override
	public void removeRefreshToken(OAuth2RefreshToken refreshToken) {
		super.removeRefreshToken(refreshToken);
		
		OAuthRefreshToken rtk = dao.findRefreshTokenByTokenId(extractTokenKey(refreshToken.getValue()));
		if (rtk != null) {
			dao.deleteRefreshToken(rtk);
		}
	}

//	@Override
//	public void removeAccessTokenUsingRefreshToken(OAuth2RefreshToken refreshToken) {
//		OAuthAccessToken token = tokenStoreDAO.findByRefreshToken(extractTokenKey(refreshToken.getValue()));
//		if (token != null) {
//			tokenStoreDAO.deleteAccessToken(token);
//		}
//	}

	
	
	

	private String extractTokenKey(String value) {
		if (value == null) {
			return null;
		} else {
			MessageDigest digest;
			try {
				digest = MessageDigest.getInstance("MD5");
			} catch (NoSuchAlgorithmException var5) {
				throw new IllegalStateException("MD5 algorithm not available.  Fatal (should be in the JDK).");
			}

			try {
				byte[] e = digest.digest(value.getBytes("UTF-8"));
				return String.format("%032x", new Object[] { new BigInteger(1, e) });
			} catch (UnsupportedEncodingException var4) {
				throw new IllegalStateException("UTF-8 encoding not available.  Fatal (should be in the JDK).");
			}
		}
	}
	
}
