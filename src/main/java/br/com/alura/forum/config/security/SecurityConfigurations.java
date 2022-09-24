package br.com.alura.forum.config.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import br.com.alura.forum.repository.UsuarioRepository;

@EnableWebSecurity
@Configuration
public class SecurityConfigurations extends WebSecurityConfigurerAdapter {

	@Autowired
	private UserDetailsService authService;

	@Autowired
	private TokenService tokenService;

	@Autowired
	private UsuarioRepository repository;

	@Override // configura acoes de autenticacao - contorles de acesso (login, etc)
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {

		auth.userDetailsService(authService).passwordEncoder(new BCryptPasswordEncoder());

	}

	@Override // Configuracoes de autorizacao - quem pode acessar o que, perfil de acesso, etc
	protected void configure(HttpSecurity http) throws Exception {

		http.authorizeRequests()
				// .antMatchers(HttpMethod.GET,"/topicos").permitAll()
				// .antMatchers(HttpMethod.GET,"/topicos/*").permitAll()
				// .antMatchers(HttpMethod.GET,"/topicos/*").permitAll()
				.antMatchers(HttpMethod.POST, "/auth").permitAll().anyRequest().authenticated().and().csrf().disable()
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
				.addFilterBefore(new AuthicationViaTokenFilter(tokenService, repository),
						UsernamePasswordAuthenticationFilter.class);

	}

	@Override // configuracoes de recursos estaticos - reqs para js, css, imagens, etc
				// (front-end, Nao necessario nesse caso)
	public void configure(WebSecurity web) throws Exception {
	}

	@Override
	@Bean
	protected AuthenticationManager authenticationManager() throws Exception {
		return super.authenticationManager();
	}

	// gera senha encriptada
	public static void main(String[] args) {
		System.out.println(new BCryptPasswordEncoder().encode("123456"));
	}

}
