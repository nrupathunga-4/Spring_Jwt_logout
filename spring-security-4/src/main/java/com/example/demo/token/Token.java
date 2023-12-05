package com.example.demo.token;

import com.example.demo.model.User;

import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class Token {

	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	private int id;
	
	private String token;
	
	@Enumerated(EnumType.STRING)
	private TokenType tokentype;
	
	private boolean expired;
	
	private boolean revoked;
	
	@ManyToOne
	@JoinColumn(name="user_id")
	private User user;
}
