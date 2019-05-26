package jp.arcanum.paseto.apiauth.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import jp.arcanum.paseto.apiauth.controller.form.UserForm;

import javax.validation.Valid;

import static jp.arcanum.paseto.apiauth.support.SecurityConstants.LOGIN_ID;
import static jp.arcanum.paseto.apiauth.support.SecurityConstants.SIGNUP_URL;

@RestController
public class SampleController {

    private static final Logger LOGGER = LoggerFactory.getLogger(SampleController.class);

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping(value = "/public")
    public String publicApi() {
        return "this is public";
    }

    @GetMapping(value = "/private")
    public String privateApi() {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // JWTAuthenticationFilter#successfulAuthenticationで設定したusernameを取り出す
        String username = (String) (authentication.getPrincipal());

        return "this is private for " + username + " auth: " + authentication.getAuthorities();
    }

    @PostMapping(value = SIGNUP_URL)
    public void signup(@Valid @RequestBody UserForm user) {

        // passwordを暗号化する
        user.encrypt(bCryptPasswordEncoder);

        // DBに保存する処理を本来は書く
        LOGGER.info("signup :" + user.toString());
    }
    
    @GetMapping(value = "/user/myurl")
    public String myurl() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = (String) (authentication.getPrincipal());
        return "this is /user/myurl for " + username + " auth: " + authentication.getAuthorities();
    }

    @GetMapping(value = "/admin")
    public String admin() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = (String) (authentication.getPrincipal());
        return "this is /admin for " + username + " auth: " + authentication.getAuthorities();
    }

}
