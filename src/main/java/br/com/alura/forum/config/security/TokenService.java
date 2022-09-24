package br.com.alura.forum.config.security;

import java.util.Date;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import br.com.alura.forum.modelo.Usuario;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Service
public class TokenService {

	@Value("${forum.jwt.expiration}")
	private String expiration;

	@Value("${forum.jwt.secret}")
	private String secret;

	public String gerarToken(Authentication authentication) {

		Usuario logado = (Usuario) authentication.getPrincipal();

		Date today = new Date();
		@SuppressWarnings("deprecation")
		Date expirationDate = new Date(today.getTime() + Long.parseLong(expiration));

		return Jwts.builder().setIssuer("APP DE EXEMPLO DE AUTH").setSubject(logado.getId().toString())
				.setIssuedAt(today).setExpiration(expirationDate).signWith(SignatureAlgorithm.HS512, secret).compact();

	}

	public boolean isTokenValid(String token) {

		try {
			Jwts.parser().setSigningKey(secret).parseClaimsJws(token);
			return true;
		} catch (Exception e) {
			return false;
		}
	}

	public Long getIdUsuario(String token) {
		Claims body = Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
		return Long.parseLong(body.getSubject());
	}

}
