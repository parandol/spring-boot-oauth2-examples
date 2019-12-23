package kr.ejsoft.oauth2.client.dao;

import org.mybatis.spring.SqlSessionTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import kr.ejsoft.oauth2.client.model.User;

@Repository("userDAO")
public class UserDao {
	@Autowired
	private SqlSessionTemplate sqlSession;
	public User selectUserById(String username) {
		return sqlSession.selectOne("user.selectUserById", username);
	}

	public int insertUser(User user) {
		return sqlSession.insert("user.insertUser", user);
	}

	public int updateUser(User user) {
		return sqlSession.insert("user.updateUser", user);
	}

	public int deleteUser(String username) {
		return sqlSession.delete("user.deleteUser", username);
	}
	

}
