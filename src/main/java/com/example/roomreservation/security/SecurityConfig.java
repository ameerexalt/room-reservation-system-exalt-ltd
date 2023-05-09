package com.example.roomreservation.security;

import com.example.roomreservation.repository.UserRepository;
import com.example.roomreservation.service.UserDetailsServiceImpl;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableMethodSecurity
@EnableWebSecurity
@Slf4j
public class SecurityConfig{
    private String[] PUBLIC_END_POINTS={"/api/v1/auth/login", "/api/v1/auth/refresh-token", "/api/v1/auth/logout","/api/v1/refreshAccessToken"};

    private String[] AUTH_END_POINTS={"/api/v1/branches","/api/v1/users","/api/v1/reservations","/api/v1/rooms"};
    @Autowired
    private JwtUnAuthResponse jwtUnAuthResponse;

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private  ModelMapper modelMapper;

    @Bean
    public UserDetailsService userDetailsService() {
        return new UserDetailsServiceImpl(modelMapper);
    }
    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());

        return authProvider;
    }
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((authz) -> authz
                        .requestMatchers("/api/v1/branches").hasAuthority("ADMIN")
                        .requestMatchers("/api/v1/branches/**").hasAuthority("ADMIN")
                        .requestMatchers("/api/v1/users/**").hasAuthority("ADMIN")
                        .requestMatchers("/api/v1/users").hasAuthority("ADMIN")
                );

        http.cors(Customizer.withDefaults()).csrf().disable()
                .authorizeHttpRequests().requestMatchers(PUBLIC_END_POINTS).permitAll()
                .anyRequest().authenticated()
                .and().exceptionHandling().authenticationEntryPoint(jwtUnAuthResponse)
                .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
               .and().addFilterBefore(authFilter(), UsernamePasswordAuthenticationFilter.class);



        return http.build();
    }

    @Bean
    public AuthFilter authFilter() {
        return new AuthFilter();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        return http.getSharedObject(AuthenticationManagerBuilder.class)
                .build();
    }

    @Bean
    static MethodSecurityExpressionHandler methodSecurityExpressionHandler() {
        DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();
//        handler.setTrustResolver(myCustomTrustResolver);
        return handler;
    }

}