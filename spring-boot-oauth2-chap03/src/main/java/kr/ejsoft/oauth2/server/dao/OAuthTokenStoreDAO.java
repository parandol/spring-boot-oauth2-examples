package kr.ejsoft.oauth2.server.dao;

import java.util.List;

import org.mybatis.spring.SqlSessionTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import kr.ejsoft.oauth2.server.model.OAuthAccessToken;
import kr.ejsoft.oauth2.server.model.OAuthApproval;
import kr.ejsoft.oauth2.server.model.OAuthCode;
import kr.ejsoft.oauth2.server.model.OAuthRefreshToken;

@Repository("oauthTokenStoreDAO")
public class OAuthTokenStoreDAO{
	@Autowired
	private SqlSessionTemplate sqlSession;

	public List<OAuthAccessToken> findByClientId(String clientId) {
		return sqlSession.selectList("oauth.findTokenByClientId", clientId);
	}

	public List<OAuthAccessToken> findByClientIdAndUsername(String clientId, String username) {
		OAuthAccessToken token = new OAuthAccessToken();
		token.setClientId(clientId);
		token.setUsername(username);
		return sqlSession.selectList("oauth.findTokenByClientIdAndUsername", token);
	}

	public OAuthAccessToken findByTokenId(String tokenId) {
		return sqlSession.selectOne("oauth.findTokenByTokenId", tokenId);
	}

	public OAuthAccessToken findByRefreshToken(String refreshToken) {
		return sqlSession.selectOne("oauth.findTokenByRefreshToken", refreshToken);
	}

	public OAuthAccessToken findByAuthenticationId(String authenticationId) {
		return sqlSession.selectOne("oauth.findTokenByAuthenticationId", authenticationId);
	}

	public int saveAccessToken(OAuthAccessToken oauthAccessToken) {
		return sqlSession.insert("oauth.saveAccessToken", oauthAccessToken);
	}

	public int deleteAccessToken(OAuthAccessToken oauthAccessToken) {
		return sqlSession.delete("oauth.deleteAccessToken", oauthAccessToken);
	}

	public OAuthRefreshToken findRefreshTokenByTokenId(String tokenId) {
		return sqlSession.selectOne("oauth.findRefreshTokenByTokenId", tokenId);
	}

	public int saveRefreshToken(OAuthRefreshToken refreshToken) {
		return sqlSession.insert("oauth.saveRefreshToken", refreshToken);
	}

	public int deleteRefreshToken(OAuthRefreshToken refreshToken) {
		return sqlSession.delete("oauth.deleteRefreshToken", refreshToken);
	}

	
	
	
	public OAuthCode findByCode(String code) {
		return sqlSession.selectOne("oauth.findAuthenticationByCode", code);
	}

	public int save(OAuthCode approval) {
		return sqlSession.insert("oauth.saveCode", approval);
	}

	public int delete(String code) {
		return sqlSession.delete("oauth.deleteCode", code);
	}
	
	

	public List<OAuthApproval> findByUserIdAndClientId(String userId, String clientId) {
		OAuthApproval approval = new OAuthApproval();
		approval.setClientId(clientId);
		approval.setUserId(userId);
		return sqlSession.selectList("oauth.findByUserIdAndClientId", approval);
	}

	public int saveApproval(OAuthApproval approval) {
		return sqlSession.insert("oauth.saveApproval", approval);
	}

	public int refreshApproval(OAuthApproval approval) {
		return sqlSession.update("oauth.refreshApproval", approval);
	}

	public int expireApproval(OAuthApproval approval) {
		return sqlSession.update("oauth.expireApproval", approval);
	}

	public int deleteApproval(OAuthApproval approval) {
		return sqlSession.delete("oauth.deleteApproval", approval);
	}
}
