package com.example.demo.config;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;


@Service
public class JwtService {
	
	private static final String SECRET_KEY="16cab5ff3e90239bb506fd91c147e27cf53a8d7b708454c2eb870dc349b0e0c8";
	
	public String extractUsername(String jwt)
	{
		return extractClaim(jwt, Claims::getSubject);
	}
	
	public <T> T extractClaim(String jwt,Function<Claims, T> claimsResolver)
	{
		final Claims claims=extractAllClaims(jwt);
		return claimsResolver.apply(claims);
	}
	
	public String generateToken(UserDetails userDetails)
	{
		return generateToken(new HashMap<>(), userDetails);
	}
	
	public String generateToken(Map<String, Object> extraClaims,UserDetails userDetails)
	{
		return Jwts
				.builder()
				.setClaims(extraClaims)
				.setSubject(userDetails.getUsername())
				.setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
				.signWith(getSignInKey(),SignatureAlgorithm.HS256)
				.compact();
	}
	
	public boolean isTokenValid(String jwt,UserDetails userDetails)
	{
		final String username =extractUsername(jwt);
		return (username.equals(userDetails.getUsername())) && !isTokenExpired(jwt);
	}
	
	private boolean isTokenExpired(String jwt) {
		return extractExpiration(jwt).before(new Date());
	}

	private Date extractExpiration(String jwt) {
		
		return extractClaim(jwt, Claims::getExpiration);
	}

	private Claims extractAllClaims(String jwt)
	{
		return Jwts
				.parserBuilder()
				.setSigningKey(getSignInKey())
				.build()
				.parseClaimsJws(jwt)
				.getBody();
	}

	private Key getSignInKey() {
		byte [] keybytes = Decoders.BASE64.decode(SECRET_KEY);
		return Keys.hmacShaKeyFor(keybytes);
	}
}
