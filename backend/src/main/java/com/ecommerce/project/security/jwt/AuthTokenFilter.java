package com.ecommerce.project.security.jwt;

import com.ecommerce.project.security.services.UserDetailsServiceImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class AuthTokenFilter extends OncePerRequestFilter {
    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        System.out.println("REQUEST URI = " + request.getRequestURI());
        try {
            String jwt = parseJwt(request);
            if (jwt != null
                    && SecurityContextHolder.getContext().getAuthentication() == null
                    && jwtUtils.validateJwtToken(jwt)) {

                String username = jwtUtils.getUserNameFromJwtToken(jwt);

                System.out.println("JWT TOKEN FOUND");
                System.out.println("JWT USERNAME = " + username);

                UserDetails userDetails =
                        userDetailsService.loadUserByUsername(username);

                System.out.println("USER FOUND = " + userDetails.getUsername());
                System.out.println("AUTHORITIES = " + userDetails.getAuthorities());

                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(userDetails,
                                null,
                                userDetails.getAuthorities());

                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);
                System.out.println("FINAL AUTHORITIES: " + SecurityContextHolder.getContext().getAuthentication().getAuthorities());
            }
        } catch (Exception e) {
            e.printStackTrace(); 
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }

        filterChain.doFilter(request, response);
    }

//    private String parseJwt(HttpServletRequest request) {
//        String jwt = jwtUtils.getJwtFromCookies(request);
//        logger.debug("AuthTokenFilter.java: {}", jwt);
//        return jwt;
//    }

    private String parseJwt(HttpServletRequest request) {
        String jwtFromCookie = jwtUtils.getJwtFromCookies(request);
        if (jwtFromCookie != null) {
            return jwtFromCookie;
        }

        String jwtFromHeader = jwtUtils.getJwtFromHeader(request);
        if (jwtFromHeader != null) {
            return jwtFromHeader;
        }

        return null;
    }
}
