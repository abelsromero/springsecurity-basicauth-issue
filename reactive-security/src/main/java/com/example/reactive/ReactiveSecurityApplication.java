package com.example.reactive;

import java.util.List;

import reactor.core.publisher.Mono;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.server.SecurityWebFilterChain;

@SpringBootApplication
public class ReactiveSecurityApplication {

	@Bean
	public SecurityWebFilterChain securityFilterChain(ServerHttpSecurity http) {
		return http
				.csrf().disable()
				.authorizeExchange()
				.pathMatchers("/").permitAll()
				.anyExchange().authenticated()
				.and()
				.httpBasic()
				.authenticationEntryPoint((exchange, ex) -> {
					exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
					return Mono.empty();
				})
				.authenticationManager(authentication -> {
					final Object principal = authentication.getPrincipal();
					if (isValidUser(authentication)) {
						List<SimpleGrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_BasicAuthUser"));
						return Mono.just(new UsernamePasswordAuthenticationToken(principal, null, authorities));
					}
					assert authentication.isAuthenticated() == false;
					return Mono.just(authentication);
				})
				.and()
				.formLogin().disable()
				.build();
	}

	private boolean isValidUser(Authentication authentication) {
		return authentication.getPrincipal().equals("user") &&
				authentication.getCredentials().equals("pass");
	}

	public static void main(String[] args) {
		SpringApplication.run(ReactiveSecurityApplication.class, args);
	}

}
