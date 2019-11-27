package kr.ejsoft.oauth2.server.dao;

import java.util.List;

import org.mybatis.spring.SqlSessionTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import kr.ejsoft.oauth2.server.model.OAuthApproval;
import kr.ejsoft.oauth2.server.model.OAuthAuthenticationCode;

@Repository("oauthDAO")
public class OAuthDAO{
	@Autowired
	private SqlSessionTemplate sqlSession;
	public OAuthAuthenticationCode findAuthenticationByCode(String code) {
		return sqlSession.selectOne("oauth.findAuthenticationByCode", code);
	}

	public int saveAuthorizationCode(OAuthAuthenticationCode approval) {
		return sqlSession.insert("oauth.saveCode", approval);
	}

	public int deleteAuthorizationCode(String code) {
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
