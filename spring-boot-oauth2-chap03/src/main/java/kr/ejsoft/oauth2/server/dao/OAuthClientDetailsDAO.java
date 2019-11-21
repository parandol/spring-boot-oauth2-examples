package kr.ejsoft.oauth2.server.dao;

import org.mybatis.spring.SqlSessionTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import kr.ejsoft.oauth2.server.model.OAuthClientDetails;
import kr.ejsoft.oauth2.server.model.OAuthUserDetails;

@Repository("oauthClientDetailsDAO")
public class OAuthClientDetailsDAO {
	@Autowired
	private SqlSessionTemplate sqlSession;
	
	public OAuthClientDetails getClientById(String username) {
		return sqlSession.selectOne("client.selectClientById", username);
	}
}