package com.home.app.ws.fullstackappws.security;

import java.util.Arrays;

import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import com.home.app.ws.fullstackappws.repository.UserRepository;
import com.home.app.ws.fullstackappws.service.UserService;

//To enable method level security
//// securedEnabled= @Secured anno either in class level or method level, prePostEnabled= @PreAuthorized & @PostAuthorized
@EnableGlobalMethodSecurity(securedEnabled = true,prePostEnabled = true)
@EnableWebSecurity
public class WebSecurity extends WebSecurityConfigurerAdapter {
	private UserService userService;
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	private final UserRepository userRepo;

	public WebSecurity(UserService userService, BCryptPasswordEncoder bCryptPasswordEncoder, UserRepository userRepo) {
		super();
		this.userService = userService;
		this.bCryptPasswordEncoder = bCryptPasswordEncoder;
		this.userRepo=userRepo;
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userService).passwordEncoder(bCryptPasswordEncoder);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.cors().and().csrf().disable().authorizeRequests().antMatchers(HttpMethod.POST, SecurityConstants.SIGN_UP_URL)
				.permitAll()
				.antMatchers(SecurityConstants.H2_CONSOLE)
				.permitAll()
				//.antMatchers(HttpMethod.DELETE,"/users/**").hasRole("ADMIN") we will use @Secured in controller instead
				//.access("hasRole('ROLE_ADMIN')")
				.anyRequest()
				.authenticated().and().addFilter(getAuthenticationFilter())
				.addFilter(new AuthorizationFilter(authenticationManager(),userRepo))
				.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS); // to make the REST API Stateless
		//disableing frame options which prevents the browser load the page with html tags/iframs etc. So for security reasons it is
		//enabled by default, just to use h2-console, we are using it
		//after using H2, we can delete this line
		//http.headers().frameOptions().disable();
	}
	
	   protected AuthenticationFilter getAuthenticationFilter() throws Exception {
		    final AuthenticationFilter filter = new AuthenticationFilter(authenticationManager());
		    filter.setFilterProcessesUrl("/users/login");
		    return filter;
		}
	   //Just for CORS
//		 @Bean 
//		 public CorsConfigurationSource corsConfigurationSource() {  
//			 final CorsConfiguration configuration = new CorsConfiguration();
//		  configuration.setAllowedOrigins(Arrays.asList("*"));
//		  configuration.setAllowedOrigins(Arrays.asList("GET","PUT","POST")); 
//		  configuration.setAllowCredentials(true); // *
//		  configuration.setAllowedHeaders(Arrays.asList("Authorization","Cache-Control","Conent-Type")); 
//		  final UrlBasedCorsConfigurationSource source = new  UrlBasedCorsConfigurationSource();
//		  source.registerCorsConfiguration("/**", configuration); 
//		  return source; 
//		  
//		 }

}
