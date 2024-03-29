package br.com.alura.forum.config.security;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import br.com.alura.forum.modelo.Usuario;
import br.com.alura.forum.repository.UsuarioRepository;

public class AuthicationViaTokenFilter extends OncePerRequestFilter{
	
	private TokenService tokenService;
	
	private UsuarioRepository repository;

	public AuthicationViaTokenFilter(TokenService tokenService,  UsuarioRepository repository) {
		super();
		this.repository = repository;
		this.tokenService = tokenService;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		String token = recuperarToken(request);
		
		boolean valid = tokenService.isTokenValid(token);
		
		if(valid) {
			authClient(token);
		}
		
		
		
		filterChain.doFilter(request, response);
	}

	private void authClient(String token) {
		
		
		Long userId = tokenService.getIdUsuario(token);
		
		Usuario usuario = repository.findById(userId).get();
		
		UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(usuario, null, usuario.getAuthorities());
		
		SecurityContextHolder.getContext().setAuthentication(authentication);
	}

	private String recuperarToken(HttpServletRequest request) {
		
		String token = request.getHeader("Authorization");
		
		if(token == null || token.isEmpty() || ! token.startsWith("Bearer ")) {
			return null;
			 
		}
	
		return token.substring(7, token.length());
	}
	
	

}
