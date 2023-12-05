package com.example.demo.config;

import java.io.IOException;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.demo.token.TokenRepository;
import com.example.service.JwtService;

import io.micrometer.common.lang.NonNull;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.var;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter{
	
	private final com.example.demo.config.JwtService jwtService;
	
	private final UserDetailsService userDetailsService;
	
	private final TokenRepository tokenRepository;

	@Override
	protected void doFilterInternal(@NonNull HttpServletRequest request,@NonNull  HttpServletResponse response,@NonNull FilterChain filterChain)
			throws ServletException, IOException {
		
		final String authHeader=request.getHeader("Authorixation");
		final String jwt;
		final String userEmail;
		if(authHeader == null || authHeader.startsWith("Bearer "))
		{
			filterChain.doFilter(request, response);
			return;
		}
		jwt = authHeader.substring(7);
		userEmail=jwtService.extractUsername(jwt);
		if(userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null)
		{
			UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
			var isTokenValid=tokenRepository.findByToken(jwt)
					.map(t -> !t.isExpired() && !t.isRevoked())
					.orElse(false);
			if(jwtService.isTokenValid(jwt, userDetails) && isTokenValid)
			{
				UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());
				authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				SecurityContextHolder.getContext().setAuthentication(authToken);
			}
		}
		filterChain.doFilter(request, response);
	}

}
