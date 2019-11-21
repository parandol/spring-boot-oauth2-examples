package kr.ejsoft.oauth2.server.config;

import java.io.UnsupportedEncodingException;
import java.util.Base64;
import java.util.Base64.Encoder;

import javax.sql.DataSource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;

import lombok.AllArgsConstructor;

@Configuration
@EnableWebSecurity
@AllArgsConstructor
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	//
	private static final Logger log = LoggerFactory.getLogger(WebSecurityConfig.class);
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.csrf().disable()
			.authorizeRequests().anyRequest().authenticated()
			.and()
			.formLogin()
			.and()
			.httpBasic();
		
		makeAuthorizationRequestHeader();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

	/*
	@Bean
	public UserDetailsService userDetailsService() {
		PasswordEncoder encoder = passwordEncoder();
		String password = encoder.encode("pass");
		log.debug("PasswordEncoder password : [{}] ", password);					// {bcrypt}$2a$10$q6JJMlG7Q7Gt4n/76ydvp.Vk9pWVcTfCQ4NtWyBzNtWOmefYNw/wO

		InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
		manager.createUser(User.withUsername("user").password(password).roles("USER").build());
		manager.createUser(User.withUsername("admin").password("{noop}pass").roles("USER", "ADMIN").build());
		return manager;
	}
	*/


	@Autowired
	DataSource dataSource;
	private JdbcUserDetailsManager userDetailsManager;

	// Enable jdbc authentication
	@Autowired
	public void configAuthentication(AuthenticationManagerBuilder auth) throws Exception {
		this.userDetailsManager = auth
		.jdbcAuthentication()
		.dataSource(dataSource)
		.usersByUsernameQuery("select username, password, enabled from oauth_user_details where username = ?")
		.authoritiesByUsernameQuery("select username, authority from oauth_user_authorities where username = ?")
//		.rolePrefix("ROLE_")
		.getUserDetailsService();
//		.userExistsSql("select username from oauth_user_details where username = ?")
//		.createUserSql("insert into oauth_user_details (username, password, enabled) values (?,?,?)")
//		.createAuthoritySql("insert into oauth_user_authorities (username, authority) values (?,?)")
//		.updateUserSql("update oauth_user_details set password = ?, enabled = ? where username = ?")
//		.deleteUserSql("delete from oauth_user_details where username = ?")
//		.deleteUserAuthoritiesSql("delete from oauth_user_authorities where username = ?");
	}
	
	@Bean
	public JdbcUserDetailsManager jdbcUserDetailsManager() throws Exception {
//		JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager();
//		jdbcUserDetailsManager.setDataSource(dataSource);
//		
//		this.userDetailsManager.setUsersByUsernameQuery("select username, password, enabled from oauth_user_details where username = ?");
		this.userDetailsManager.setUserExistsSql("select username from oauth_user_details where username = ?");
		this.userDetailsManager.setCreateUserSql("insert into oauth_user_details (username, password, enabled) values (?,?,?)");
		this.userDetailsManager.setCreateAuthoritySql("insert into oauth_user_authorities (username, authority) values (?,?)");
		this.userDetailsManager.setUpdateUserSql("update oauth_user_details set password = ?, enabled = ? where username = ?");
		this.userDetailsManager.setDeleteUserSql("delete from oauth_user_details where username = ?");
		this.userDetailsManager.setDeleteUserAuthoritiesSql("delete from oauth_user_authorities where username = ?");
//		
//		return jdbcUserDetailsManager;
		return this.userDetailsManager;
	}

	
	private static void makeAuthorizationRequestHeader() {
		String oauthClientId = "client";
		String oauthClientSecret = "secret";

		Encoder encoder = Base64.getEncoder();
		try {
			String toEncodeString = String.format("%s:%s", oauthClientId, oauthClientSecret);
			String authorizationRequestHeader = "Basic " + encoder.encodeToString(toEncodeString.getBytes("UTF-8"));
			log.debug("AuthorizationRequestHeader : [{}] ", authorizationRequestHeader);			// Y2xpZW50OnNlY3JldA==
		} catch (UnsupportedEncodingException e) {
			log.error(e.getMessage(), e);
		}
	}


	/**
	 * Need to configure this support password mode support password grant type
	 * 
	 * @return
	 * @throws Exception
	 */
	@Override
	@Bean
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}
}
