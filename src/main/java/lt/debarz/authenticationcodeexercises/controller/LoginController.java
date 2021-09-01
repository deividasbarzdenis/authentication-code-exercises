package lt.debarz.authenticationcodeexercises.controller;

import lombok.extern.slf4j.Slf4j;
import lt.debarz.authenticationcodeexercises.dto.LoginForm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.Collection;

import static org.springframework.security.web.context.HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY;

@Slf4j
@Controller
public class LoginController {

    @Autowired
    private UserDetailsService userService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @PostMapping("/login")
    public String loginProcess(HttpServletRequest req, @ModelAttribute("loginForm") LoginForm loginForm, Model model) {
        String username = loginForm.getUsername();
        String password = loginForm.getPassword();

        log.info("Authentication start - user = {}", loginForm.getUsername());
        UserDetails user = null;

        try {
            user = userService.loadUserByUsername(username);
        } catch (UsernameNotFoundException ex) { }

        if (user == null) {
            model.addAttribute("loginError", "Incorrect user/password");
            return "login";
        }

        if (!passwordEncoder.matches(password, user.getPassword())) {
            model.addAttribute("loginError", "Incorrect user/password");
            return "login";
        }

        // set up login session
        Collection<? extends GrantedAuthority> authorities = user.getAuthorities();
        Authentication auth = new UsernamePasswordAuthenticationToken(user, password, authorities);

        SecurityContext sc = SecurityContextHolder.getContext();
        sc.setAuthentication(auth);
        HttpSession session = req.getSession(true);
        session.setAttribute(SPRING_SECURITY_CONTEXT_KEY, sc);

        if (authorities.stream().anyMatch(authority -> authority.getAuthority().equals("ROLE_USER"))) {
            return "redirect:/user";
        } else if (authorities.stream().anyMatch(authority -> authority.getAuthority().equals("ROLE_ADMIN"))) {
            return "redirect:/admin";
        } else {
            return "redirect:/";
        }
    }
}
