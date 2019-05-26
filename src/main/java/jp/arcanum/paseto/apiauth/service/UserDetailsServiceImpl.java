package jp.arcanum.paseto.apiauth.service;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private static List<String> usernameList = Arrays.asList("nyasba", "admin");
    private static String ENCRYPTED_PASSWORD = "$2a$10$5DF/j5hHnbeHyh85/0Bdzu1HV1KyJKZRt2GhpsfzQ8387A/9duSuq"; // "password"を暗号化した値

	private static final List<GrantedAuthority> AUTH_USER = AuthorityUtils.createAuthorityList("ROLE_USER");
	private static final List<GrantedAuthority> AUTH_ADMIN = AuthorityUtils.createAuthorityList("ROLE_USER", "ROLE_ADMIN");

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        // 本来ならここでDBなどからユーザを検索することになるが、サンプルのためリストに含まれるかで判定している
        if(!usernameList.contains(username)){
            throw new UsernameNotFoundException(username);
        }
        
        // 本来なら上記のユーザー検索の際にDBから一緒にロール情報などを取得するがここでは固定で処理
        List<GrantedAuthority> auth = AUTH_USER;
        if (username.equals("admin")) {
        	auth = AUTH_ADMIN;
        }

        return User.withUsername(username)
                .password(ENCRYPTED_PASSWORD)
                .authorities(auth)
                .build();
    }

}
