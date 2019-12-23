package kr.ejsoft.oauth2.client.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

//import kr.ejsoft.oauth2.server.handler.AuthenticationHandler;
import lombok.AllArgsConstructor;

@Configuration
@EnableWebSecurity
@AllArgsConstructor
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	private static final Logger logger = LoggerFactory.getLogger(WebSecurityConfig.class);
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.csrf().disable()
			.authorizeRequests()
				.antMatchers("/", "/home", "/js/**", "/css/**", "/img/**", "/favicon.ico").permitAll()
				.antMatchers("/auth/**").permitAll()
//				.anyRequest().authenticated()
//			.and()
//				.formLogin()
//				.loginPage("/login").permitAll()
//				.successForwardUrl("/login?success")
//				.failureUrl("/login?failure")
//				.successHandler(authenticationHandler())
//				.failureHandler(authenticationHandler())
			.and()
				.logout().permitAll()
			.and()
				.httpBasic()
			;
//		.authorizeRequests().antMatchers("/api/**").access("@oauth2.clientHasRole('READ')")

	}
}