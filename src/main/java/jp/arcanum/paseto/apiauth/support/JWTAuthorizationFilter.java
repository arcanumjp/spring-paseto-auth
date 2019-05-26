package jp.arcanum.paseto.apiauth.support;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;

import static jp.arcanum.paseto.apiauth.support.SecurityConstants.HEADER_STRING;
import static jp.arcanum.paseto.apiauth.support.SecurityConstants.SECRET;
import static jp.arcanum.paseto.apiauth.support.SecurityConstants.TOKEN_PREFIX;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {
    private AuthenticationManager authenticationManager;

    public JWTAuthorizationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req,
                                    HttpServletResponse res,
                                    FilterChain chain) throws IOException, ServletException {
        String header = req.getHeader(HEADER_STRING);

        if (header == null || !header.startsWith(TOKEN_PREFIX)) {
            chain.doFilter(req, res);
            return;
        }

        // AuthorizationヘッダのBearer Prefixである場合
        UsernamePasswordAuthenticationToken authentication = getAuthentication(req);

        SecurityContextHolder.getContext().setAuthentication(authentication);
        chain.doFilter(req, res);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
        String token = request.getHeader(HEADER_STRING);
        if (token != null) {
        	
        	token = token.replace(HEADER_STRING, "");
        	token = token.replace(TOKEN_PREFIX, "").trim();
        	
        	System.out.println("token: " + token);
        	
        	JwtParser parser = Jwts.parser().setSigningKey(SECRET.getBytes());
        	Claims claims = parser.parseClaimsJws(token).getBody();
        	
        	String user = claims.getSubject();
        	
        	List grants = (List) claims.get("role");
        	String[] arrayRole = new String[grants.size()];
        	for (int i = 0 ; i < grants.size(); i++) {
        		LinkedHashMap grant = (LinkedHashMap) grants.get(i);
        		String rolestr = (String) grant.get("authority");
        		arrayRole[i] = rolestr;
        	}
        	List<GrantedAuthority> roles = AuthorityUtils.createAuthorityList(arrayRole);

        	if (user != null) {
                return new UsernamePasswordAuthenticationToken(user, null, roles);
            }
            return null;
        }
        return null;
    }

}
