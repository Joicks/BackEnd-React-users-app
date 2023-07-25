package com.jose.backend.usersapp.backendusersapp.auth;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import com.jose.backend.usersapp.backendusersapp.auth.filters.JwtAuthenticationFilter;
import com.jose.backend.usersapp.backendusersapp.auth.filters.JwtValidationFilter;

@Configuration
public class SpringSecurityConfig {

//   @Autowired
//   private AuthenticationConfiguration authenticationConfiguration;

//  @Bean
//   PasswordEncoder passwordEncoder(){
//     return new BCryptPasswordEncoder();
//   }

//   @Bean
//   SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//   return http.authorizeHttpRequests()
//   .requestMatchers(HttpMethod.GET, "/users").permitAll()
//   .anyRequest().authenticated()
//   .and()
//   .addFilter(new JwtAuthenticationFilter(authenticationConfiguration.getAuthenticationManager()))
//   .addFilter(new JwtValidationFilter(authenticationConfiguration.getAuthenticationManager()))
//   .csrf(config -> config.disable())
//   .sessionManagement(managment ->
//   managment.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//   .build();
//   }

  // solucion al eror de arriba

  @Autowired
  private AuthenticationConfiguration authenticationConfiguration;

  @Bean
  PasswordEncoder passwordEncoder(){
    return new BCryptPasswordEncoder();
    //sirve para encriptar contraseñas, solo encripta pero no se puede decodificar
  }

  @Bean
  AuthenticationManager authenticationManager() throws Exception {
    return authenticationConfiguration.getAuthenticationManager();
  }


  @Bean
  SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    return http.authorizeHttpRequests(authRules -> authRules
        .requestMatchers(HttpMethod.GET, "/users", "users/page/{page}").permitAll()
        .requestMatchers(HttpMethod.GET, "/users/{id}").hasAnyRole("USER", "ADMIN")
        .requestMatchers(HttpMethod.POST, "/users").hasRole("ADMIN")
        .requestMatchers("/users/**").hasRole("ADMIN")
        //estas 2 lines es lo mismo que la linea de arriba
        // .requestMatchers(HttpMethod.DELETE, "/users/{id}").hasRole("ADMIN")
        // .requestMatchers(HttpMethod.PUT, "/users/{id}").hasRole("ADMIN")
        .anyRequest().authenticated())
        .addFilter(new JwtAuthenticationFilter(authenticationConfiguration.getAuthenticationManager()))
        .addFilter(new JwtValidationFilter(authenticationConfiguration.getAuthenticationManager()))
        .csrf(config -> config.disable())
        .sessionManagement(managment -> managment.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .cors(cors -> cors.configurationSource(corsConfigurationSource()))
        .build();
  }

  @Bean
  CorsConfigurationSource corsConfigurationSource(){
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowedOrigins(Arrays.asList("http://localhost:5173"));
    config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
    config.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type"));
    config.setAllowCredentials(true);

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", config);
    return source;
  }

  @Bean
  FilterRegistrationBean<CorsFilter> corsFilter(){
    FilterRegistrationBean<CorsFilter> bean = new FilterRegistrationBean<>(
      new CorsFilter(corsConfigurationSource()));
    bean.setOrder(Ordered.HIGHEST_PRECEDENCE);
      return bean;

  }

}
