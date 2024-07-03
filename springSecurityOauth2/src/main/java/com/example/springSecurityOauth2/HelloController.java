package com.example.springSecurityOauth2;

import java.util.HashMap;
import java.util.Map;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpSession;

@RestController
//@RequestMapping("/api")
public class HelloController {
   
	@GetMapping("/login/login/oauth2/code/xtg")
	@ResponseBody
    public String login() {
		System.out.println("login");
        return " login";
    }
	
	
	@GetMapping("/o/oauth2/v2/auth")
	@ResponseBody
    public String authorization() {
		System.out.println("Authorization");
        return "Authorization  ";
    }
	

	@GetMapping("/oauth2/v4/token")
	@ResponseBody
    public String token() {
		System.out.println("token");
        return "token  ";
    }
    

	@GetMapping("/oauth2/v3/userinfo")
	@ResponseBody
    public String userInfo() {
		System.out.println("UserInfo");
        return "UserInfo  ";
    }
	
	
	@GetMapping("/oauth2/v3/certs")
	@ResponseBody
    public String setCredentials() {
		System.out.println("credentials");
        return "set credentials  ";
    }
	
	@GetMapping("/")
    public String home(HttpSession session, @AuthenticationPrincipal OidcUser oidcUser) {
        if (oidcUser != null) {
            session.setAttribute("user", oidcUser.getName());
            session.setAttribute("email", oidcUser.getEmail());
            session.setAttribute("picture", oidcUser.getPicture());
        }
        return "redirect:/home.html";
    }
	
    @GetMapping("/user")
    public Map<String, Object> user(@AuthenticationPrincipal OidcUser oidcUser) {
        Map<String, Object> userInfo = new HashMap<>();
        if (oidcUser != null) {
            userInfo.put("user", oidcUser.getName());
            userInfo.put("email", oidcUser.getEmail());
            userInfo.put("picture", oidcUser.getPicture());
        }
        return userInfo;
    }
}