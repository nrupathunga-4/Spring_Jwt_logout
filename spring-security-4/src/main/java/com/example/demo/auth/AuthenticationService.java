package com.example.demo.auth;

import java.util.Optional;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.User.UserBuilder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.demo.config.JwtService;
import com.example.demo.model.Role;
import com.example.demo.model.User;
import com.example.demo.model.UserRepository;
import com.example.demo.token.Token;
import com.example.demo.token.TokenRepository;
import com.example.demo.token.TokenType;

import lombok.RequiredArgsConstructor;
import lombok.var;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
	
	private final UserRepository repository;
	
	private final PasswordEncoder encoder;
	
	private final JwtService jwtService;
	
	private final AuthenticationManager authenticationManager;
	
	private final TokenRepository tokenRepository;
	
	public AuthenticationResponse register(RegisterRequest request) {
		
	       User user=new User();
	       user.setFirstname(request.getFirstname());
	       user.setLastname(request.getLastname());
	       user.setEmail(request.getEmail());
	       user.setPassword(encoder.encode(request.getPassword()));
	       user.setRole(Role.USER);
	  var savedUser=repository.save(user);
		      var jwtToken = jwtService.generateToken(user) ;
		      saveUserToken(savedUser, jwtToken);
		        return AuthenticationResponse.builder()
		        		.token(jwtToken)
		        		.build() ;
	}

	 private void revokeAllUserToken(User user)
	 {
		 var validUserToken = tokenRepository.findAllValidTokensByUser(user.getId());
		 if(validUserToken.isEmpty())
		  return;
		 validUserToken.forEach(t ->{
		     t.setExpired(true);
		     t.setRevoked(true);
		 });
		 tokenRepository.saveAll(validUserToken);
	 }
	
	public AuthenticationResponse authenticate(AuthenticationRequest request) {
		authenticationManager.authenticate(
			new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
		
		   User user =repository.findByEmail(request.getEmail()).orElseThrow();
	      var jwtToken = jwtService.generateToken(user) ;
	         revokeAllUserToken(user);
	            saveUserToken(user,jwtToken);
	        return AuthenticationResponse.builder()
	        		.token(jwtToken)
	        		.build() ;
	}

	private void saveUserToken(com.example.demo.model.User user, java.lang.String jwtToken) {
		var token = Token.builder()
				  .user(user)
				  .token(jwtToken)
				  .tokentype(TokenType.BEARER)
				  .revoked(false)
				  .expired(false)
				  .build();
		       tokenRepository.save(token);
	}
}
