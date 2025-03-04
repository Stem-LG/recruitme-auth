package tn.louay.auth.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

public class JWTAuthorizationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        String jwt = request.getHeader("Authorization");

        if (jwt == null || !jwt.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        JWTVerifier verifier = JWT.require(Algorithm.HMAC256(SecParams.SECRET)).build();
        jwt = jwt.substring(7); // Remove "Bearer "
        DecodedJWT decodedJWT = verifier.verify(jwt);

        String username = decodedJWT.getClaim("username").asString();
        String role = decodedJWT.getClaim("role").asString();

        Collection<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority(role));

        System.out.println("Username: " + username);
        System.out.println("Authorities: " + authorities);

        UsernamePasswordAuthenticationToken user = new UsernamePasswordAuthenticationToken(username, null, authorities);

        SecurityContextHolder.getContext().setAuthentication(user);
        filterChain.doFilter(request, response);
    }
}