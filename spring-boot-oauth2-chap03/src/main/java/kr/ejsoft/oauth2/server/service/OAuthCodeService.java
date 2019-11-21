package kr.ejsoft.oauth2.server.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.code.RandomValueAuthorizationCodeServices;
import org.springframework.stereotype.Service;

import kr.ejsoft.oauth2.server.dao.OAuthTokenStoreDAO;
import kr.ejsoft.oauth2.server.model.OAuthCode;

@Service("oauthCodeService")
public class OAuthCodeService extends RandomValueAuthorizationCodeServices {

	@Autowired
	@Qualifier("oauthTokenStoreDAO")
	private OAuthTokenStoreDAO dao;

	@Override
	protected void store(String code, OAuth2Authentication authentication) {
		OAuthCode approval = new OAuthCode();
		approval.setCode(code);
		approval.setAuthenticationObject(authentication);
		dao.save(approval);
	}

	public OAuth2Authentication remove(String code) {
		OAuth2Authentication authentication = null;

		try {
			OAuthCode oauthcode = dao.findByCode(code);
			authentication = oauthcode != null ? oauthcode.getAuthenticationObject() : null;
		} catch (Exception e) {
			return null;
		}

		if (authentication != null) {
			dao.delete(code);
		}

		return authentication;
	}
}