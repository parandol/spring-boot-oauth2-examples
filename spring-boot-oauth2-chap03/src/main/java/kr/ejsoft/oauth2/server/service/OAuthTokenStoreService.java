package kr.ejsoft.oauth2.server.service;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.DefaultAuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.stereotype.Service;

import kr.ejsoft.oauth2.server.dao.OAuthTokenStoreDAO;
import kr.ejsoft.oauth2.server.model.OAuthAccessToken;
import kr.ejsoft.oauth2.server.model.OAuthRefreshToken;

@Service("oauthTokenStoreService")
public class OAuthTokenStoreService implements TokenStore {

	private static final Logger log = LoggerFactory.getLogger(OAuthTokenStoreService.class);

	@Autowired
	@Qualifier("oauthTokenStoreDAO")
	private OAuthTokenStoreDAO tokenStoreDAO;

	private AuthenticationKeyGenerator authenticationKeyGenerator = new DefaultAuthenticationKeyGenerator();

	@Override
	public OAuth2Authentication readAuthentication(OAuth2AccessToken accessToken) {
		return readAuthentication(accessToken.getValue());
	}

	@Override
	public OAuth2Authentication readAuthentication(String token) {
		OAuthAccessToken accessToken = tokenStoreDAO.findByTokenId(extractTokenKey(token));
		if (accessToken != null) {
			return accessToken.getAuthenticationObject();
		}
		return null;
	}

	@Override
	public void storeAccessToken(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
		String refreshToken = null;
		if (accessToken.getRefreshToken() != null) {
			refreshToken = accessToken.getRefreshToken().getValue();
		}

		if (readAccessToken(accessToken.getValue()) != null) {
			this.removeAccessToken(accessToken);
		}

		OAuthAccessToken cat = new OAuthAccessToken();
		cat.setId(UUID.randomUUID().toString() + UUID.randomUUID().toString());
		cat.setTokenId(extractTokenKey(accessToken.getValue()));
		cat.setTokenObject(accessToken);
		cat.setAuthenticationId(authenticationKeyGenerator.extractKey(authentication));
		cat.setUsername(authentication.isClientOnly() ? null : authentication.getName());
		cat.setClientId(authentication.getOAuth2Request().getClientId());
		cat.setAuthenticationObject(authentication);
		cat.setRefreshToken(extractTokenKey(refreshToken));

		tokenStoreDAO.saveAccessToken(cat);
	}

	@Override
	public OAuth2AccessToken readAccessToken(String tokenValue) {
		OAuthAccessToken accessToken = tokenStoreDAO.findByTokenId(extractTokenKey(tokenValue));
		if (accessToken != null) {
			return accessToken.getTokenObject();
		}
		return null;
	}

	@Override
	public void removeAccessToken(OAuth2AccessToken oAuth2AccessToken) {
		OAuthAccessToken accessToken = tokenStoreDAO.findByTokenId(extractTokenKey(oAuth2AccessToken.getValue()));
		if (accessToken != null) {
			tokenStoreDAO.deleteAccessToken(accessToken);
		}
	}

	@Override
	public void storeRefreshToken(OAuth2RefreshToken refreshToken, OAuth2Authentication authentication) {
		OAuthRefreshToken crt = new OAuthRefreshToken();
		crt.setId(UUID.randomUUID().toString() + UUID.randomUUID().toString());
		crt.setTokenId(extractTokenKey(refreshToken.getValue()));
		crt.setTokenObject(refreshToken);
		crt.setAuthenticationObject(authentication);
		tokenStoreDAO.saveRefreshToken(crt);
	}

	@Override
	public OAuth2RefreshToken readRefreshToken(String tokenValue) {
		OAuthRefreshToken refreshToken = tokenStoreDAO.findRefreshTokenByTokenId(extractTokenKey(tokenValue));
		return refreshToken != null ? refreshToken.getTokenObject() : null;
	}

	@Override
	public OAuth2Authentication readAuthenticationForRefreshToken(OAuth2RefreshToken refreshToken) {
		OAuthRefreshToken rtk = tokenStoreDAO.findRefreshTokenByTokenId(extractTokenKey(refreshToken.getValue()));
		return rtk != null ? rtk.getAuthenticationObject() : null;
	}

	@Override
	public void removeRefreshToken(OAuth2RefreshToken refreshToken) {
		OAuthRefreshToken rtk = tokenStoreDAO.findRefreshTokenByTokenId(extractTokenKey(refreshToken.getValue()));
		if (rtk != null) {
			tokenStoreDAO.deleteRefreshToken(rtk);
		}
	}

	@Override
	public void removeAccessTokenUsingRefreshToken(OAuth2RefreshToken refreshToken) {
		OAuthAccessToken token = tokenStoreDAO.findByRefreshToken(extractTokenKey(refreshToken.getValue()));
		if (token != null) {
			tokenStoreDAO.deleteAccessToken(token);
		}
	}

	@Override
	public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {
		OAuth2AccessToken accessToken = null;
		String authenticationId = authenticationKeyGenerator.extractKey(authentication);
		OAuthAccessToken token = tokenStoreDAO.findByAuthenticationId(authenticationId);

		if (token != null) {
			accessToken = token.getTokenObject();
			if (accessToken != null && !authenticationId.equals(this.authenticationKeyGenerator.extractKey(this.readAuthentication(accessToken)))) {
				this.removeAccessToken(accessToken);
				this.storeAccessToken(accessToken, authentication);
			}
		}
		return accessToken;
	}

	@Override
	public Collection<OAuth2AccessToken> findTokensByClientIdAndUserName(String clientId, String userName) {
		Collection<OAuth2AccessToken> tokens = new ArrayList<OAuth2AccessToken>();
		List<OAuthAccessToken> result = tokenStoreDAO.findByClientIdAndUsername(clientId, userName);
		result.forEach(e -> tokens.add(e.getTokenObject()));
		return tokens;
	}

	@Override
	public Collection<OAuth2AccessToken> findTokensByClientId(String clientId) {
		Collection<OAuth2AccessToken> tokens = new ArrayList<OAuth2AccessToken>();
		List<OAuthAccessToken> result = tokenStoreDAO.findByClientId(clientId);
		result.forEach(e -> tokens.add(e.getTokenObject()));
		return tokens;
	}

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