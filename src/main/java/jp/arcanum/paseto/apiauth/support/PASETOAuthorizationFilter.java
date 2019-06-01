package jp.arcanum.paseto.apiauth.support;

import net.aholbrook.paseto.TokenWithFooter;
import net.aholbrook.paseto.meta.PasetoBuilders;
import net.aholbrook.paseto.service.KeyId;
import net.aholbrook.paseto.service.Token;
import net.aholbrook.paseto.service.TokenService;
import net.aholbrook.paseto.service.PublicTokenService.Builder;
import net.aholbrook.paseto.util.Hex;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import jp.arcanum.paseto.apiauth.CustomFooter;
import jp.arcanum.paseto.apiauth.CustomToken;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

import static jp.arcanum.paseto.apiauth.support.SecurityConstants.HEADER_STRING;
import static jp.arcanum.paseto.apiauth.support.SecurityConstants.SECRET;
import static jp.arcanum.paseto.apiauth.support.SecurityConstants.TOKEN_PREFIX;

public class PASETOAuthorizationFilter extends BasicAuthenticationFilter {
    private AuthenticationManager authenticationManager;

    public PASETOAuthorizationFilter(AuthenticationManager authenticationManager) {
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
        	/*
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
			*/
        	
        	//byte[] key = Hex.decode("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f");
        	//TokenService<Token> tokenService = PasetoBuilders.V2.localService(() -> key, Token.class)
        	//	    .build();
        	//Builder<Token> builder = PasetoBuilders.V2.publicService(SecurityConstants.PROVIDER, Token.class);
        	//TokenService<Token> tokenService = builder.build();
        	//Token pToken = tokenService.decode(token);
        	Builder<CustomToken> builder = PasetoBuilders.V2.publicService(SecurityConstants.PROVIDER, CustomToken.class);
        	TokenService<CustomToken> tokenService = builder.build();
        	Token pToken = tokenService.decode(token);
        	//CustomToken pToken = tokenService.decode(token);
        	//String message = pToken.getMessage();
        	String user = pToken.getSubject();
        	
        	//TokenWithFooter<CustomToken, CustomFooter> tokenWithFooter = tokenService.decodeWithFooter(token, CustomFooter.class);
        	//Token pToken = tokenWithFooter.getToken();
        	//CustomFooter footer = tokenWithFooter.getFooter();
        	
            // KeyId kid = tokenService.getFooter(token, KeyId.class);
        	// List<GrantedAuthority> auth = AuthorityUtils.createAuthorityList("ROLE_USER");
        	//CustomFooter footer = tokenService.getFooter(token, CustomFooter.class);
        	//System.out.println(footer.name);
        	//System.out.println(footer.age);
        	//System.out.println(footer.auth);
        	List<GrantedAuthority> auth = new ArrayList<>();//  AuthorityUtils.createAuthorityList(footer.get);
        	
        	if (user != null) {
                return new UsernamePasswordAuthenticationToken(user, null, auth);
            }
            return null;
        }
        return null;
    }

}
