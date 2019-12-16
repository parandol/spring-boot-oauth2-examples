package kr.ejsoft.oauth2.server.dao;

import org.mybatis.spring.SqlSessionTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import kr.ejsoft.oauth2.server.model.OAuthUserDetails;

@Repository("oauthUserDetailsDAO")
public class OAuthUserDetailsDAO {
	@Autowired
	private SqlSessionTemplate sqlSession;
	
	public OAuthUserDetails getUserById(String username) {
		return sqlSession.selectOne("user.selectUserById", username);
	}
}