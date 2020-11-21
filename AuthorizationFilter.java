package com.home.app.ws.fullstackappws.security;

import java.io.IOException;
import java.util.ArrayList;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.home.app.ws.fullstackappws.SpringApplicationContext;
import com.home.app.ws.fullstackappws.Exceptions.UserServiceException;
import com.home.app.ws.fullstackappws.io.entity.UserEntity;
import com.home.app.ws.fullstackappws.repository.UserRepository;

import io.jsonwebtoken.Jwts;

public class AuthorizationFilter extends BasicAuthenticationFilter {
	private final UserRepository userRepo;
	public AuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepo) {
		super(authenticationManager);
		this.userRepo = userRepo;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
			throws IOException, ServletException {

		String header = req.getHeader(SecurityConstants.HEADER_STRING);

		if (header == null || !header.startsWith(SecurityConstants.TOKEN_PREFIX)) {
			chain.doFilter(req, res);
			return;
		}

		UsernamePasswordAuthenticationToken authentication = getAuthentication(req);
		SecurityContextHolder.getContext().setAuthentication(authentication);
		chain.doFilter(req, res);
	}

	private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
		String token = request.getHeader(SecurityConstants.HEADER_STRING);

		if (token != null) {

			token = token.replace(SecurityConstants.TOKEN_PREFIX, "");
			String user = Jwts.parser().setSigningKey(SecurityConstants.TOKEN_SECRET).parseClaimsJws(token).getBody()
					.getSubject();
			if (user != null) {
				//return new UsernamePasswordAuthenticationToken(user, null, new ArrayList<>());
				UserEntity uerEntity = userRepo.findByEmail(user);
				UserPrincipal userPrincipal = new UserPrincipal(uerEntity);
				System.out.println("Hi "+ userPrincipal.getAuthorities());
				return new UsernamePasswordAuthenticationToken(userPrincipal, null, userPrincipal.getAuthorities());
			}

			return null;
		}

		return null;
	}
}
