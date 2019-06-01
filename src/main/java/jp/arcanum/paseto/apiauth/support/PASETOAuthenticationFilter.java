package jp.arcanum.paseto.apiauth.support;

import com.fasterxml.jackson.databind.ObjectMapper;

import jp.arcanum.paseto.apiauth.CustomFooter;
import jp.arcanum.paseto.apiauth.CustomToken;
import jp.arcanum.paseto.apiauth.controller.form.UserForm;
import net.aholbrook.paseto.meta.PasetoBuilders;
import net.aholbrook.paseto.service.PublicTokenService.Builder;
import net.aholbrook.paseto.service.Token;
import net.aholbrook.paseto.service.TokenService;
import net.aholbrook.paseto.util.Hex;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;
import java.time.OffsetDateTime;

import static jp.arcanum.paseto.apiauth.support.SecurityConstants.*;

public class PASETOAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(PASETOAuthenticationFilter.class);

    private AuthenticationManager authenticationManager;
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    public PASETOAuthenticationFilter(AuthenticationManager authenticationManager, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.authenticationManager = authenticationManager;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;

        // ログイン用のpathを変更する
        setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher(LOGIN_URL, "POST"));

        // ログイン用のID/PWのパラメータ名を変更する
        setUsernameParameter(LOGIN_ID);
        setPasswordParameter(PASSWORD);

    }

    // 認証の処理
    @Override
    public Authentication attemptAuthentication(HttpServletRequest req,
                                                HttpServletResponse res) throws AuthenticationException {
        try {
            // requestパラメータからユーザ情報を読み取る
            UserForm userForm = new ObjectMapper().readValue(req.getInputStream(), UserForm.class);

            return authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            userForm.getLoginId(),
                            userForm.getPass())
            );
        } catch (IOException e) {
            LOGGER.error(e.getMessage());
            throw new RuntimeException(e);
        }
    }


    // 認証に成功した場合の処理
    @Override
    protected void successfulAuthentication(HttpServletRequest req,
                                            HttpServletResponse res,
                                            FilterChain chain,
                                            Authentication auth) throws IOException, ServletException {
        // loginIdからtokenを設定してヘッダにセットする
    	User user = (User)auth.getPrincipal();
    	/*
        String token = Jwts.builder()
                .setSubject(user.getUsername())
                .claim("role", user.getAuthorities())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(SignatureAlgorithm.HS512, SECRET.getBytes())
                .compact();
		*/
    	//byte[] key = Hex.decode("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f");
    	//TokenService<Token> tokenService = PasetoBuilders.V2.localService(() -> key, Token.class)
    	//	    .withDefaultValidityPeriod(Duration.ofDays(15))
    	//	    .build();
    	//Builder<Token> builder = PasetoBuilders.V2.publicService(SecurityConstants.PROVIDER, Token.class);
    	//TokenService<Token> tokenService = builder.build();
    	Builder<CustomToken> builder = PasetoBuilders.V2.publicService(SecurityConstants.PROVIDER, CustomToken.class);
    	TokenService<CustomToken> tokenService = builder.build();
    	
    	//Token pasetoToken = new Token();
    	CustomToken pasetoToken = new CustomToken();
    	pasetoToken.setMessage("hello paseto world!!");
    	pasetoToken.setIssuer("arcanum.jp");
    	pasetoToken.setSubject(user.getUsername());
    	pasetoToken.setTokenId("uniqu id at JWT");
    	pasetoToken.setExpiration(OffsetDateTime.now().plusHours(8));	// 8 hours
    	//String token = tokenService.encode(pasetoToken);

    	//KeyId kid = new KeyId();
    	//kid.setKeyId("my key id");
    	//String token = tokenService.encode(pasetoToken, kid);
    	
    	CustomFooter footer = new CustomFooter();
    	footer.auth = new String[] {"ROLE_USER", "ROLE_ADMIN"};
    	footer.age = 17;
    	footer.name = "zunko";
    	String token = tokenService.encode(pasetoToken, footer);
    	
        res.addHeader(HEADER_STRING, TOKEN_PREFIX + token);

        // ここでレスポンスを組み立てると個別のパラメータを返せるがFilterの責務の範囲内で実施しなければならない
        // auth.getPrincipal()で取得できるUserDetailsは自分で作ったEntityクラスにもできるのでカスタム属性は追加可能
    }

}
