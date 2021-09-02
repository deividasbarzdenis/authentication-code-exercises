package lt.debarz.authenticationcodeexercises.controller;

import lombok.extern.slf4j.Slf4j;
import lt.debarz.authenticationcodeexercises.dto.LoginForm;
import lt.debarz.authenticationcodeexercises.service.CaptchaService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
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
    private static final String LOGIN_ERROR_MSG = "Incorrect user/password";
    private static final String LOGIN_ERROR_ATTR = "loginError";

    private static final String DUMMY_PASSWORD_HASH = "$argon2id$v=19$m=4096,t=10,p=1$SD8m0Rk28mlhyVm688wIRA$9ltWxKhQTrD0MKK3tSNHrKyHjkR9dH//nLa6LlD8MHI";

    @Autowired
    private UserDetailsService userService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private CaptchaService captchaService;

    @Value("${app.recaptcha.site-key")
    private String reCaptchaSiteKey;

    @GetMapping("/login")
    public String login(Model model) {
        return "login";
    }

    @PostMapping("/login")
    public String loginProcess(HttpServletRequest req, @ModelAttribute("loginForm") LoginForm loginForm, Model model) {
        long startTime = System.nanoTime();

        String username = loginForm.getUsername();
        String password = loginForm.getPassword();

        String reCaptchaToken = req.getParameter("g-recaptcha-response");
        if (!captchaService.verifyReCaptchaResponse(reCaptchaToken)) {
            log.warn("login failed - suspected automated attack - ip={}, user={}", req.getRemoteAddr(), username);
            model.addAttribute(LOGIN_ERROR_ATTR, LOGIN_ERROR_MSG);
            return "login";
        }

        log.info("Authentication start - User = {}", loginForm.getUsername());
        UserDetails user = null;

        try {
            user = userService.loadUserByUsername(username);
        } catch (UsernameNotFoundException ex) { }

        if (user == null) {
            log.warn("login failed - unknown user - ip={}, user={}", req.getRemoteAddr(), username);

            // dummy step to make the response time similar to the case of incorrect password
            passwordEncoder.matches(password, DUMMY_PASSWORD_HASH);

            model.addAttribute(LOGIN_ERROR_ATTR, LOGIN_ERROR_MSG);
            long endTime = System.nanoTime();
            log.info("Authentication end - Duration = {} ms", (double)(endTime - startTime)/1000000);
            return "login";
        }

        if (!passwordEncoder.matches(password, user.getPassword())) {
            log.warn("login failed - incorrect password - ip={}, user={}", req.getRemoteAddr(), username);
            model.addAttribute(LOGIN_ERROR_ATTR, LOGIN_ERROR_MSG);
            long endTime = System.nanoTime();
            log.info("Authentication end - Duration = {} ms", (double)(endTime - startTime)/1000000);
            return "login";
        }

        log.info("successful login - ip={}, user={}", req.getRemoteAddr(), username);

        // set up login session
        Collection<? extends GrantedAuthority> authorities = user.getAuthorities();
        Authentication auth = new UsernamePasswordAuthenticationToken(user, password, authorities);

        SecurityContext sc = SecurityContextHolder.getContext();
        sc.setAuthentication(auth);
        HttpSession session = req.getSession(true);
        session.setAttribute(SPRING_SECURITY_CONTEXT_KEY, sc);

        String nextPage = "redirect:/";

        if (authorities.stream().anyMatch(authority -> authority.getAuthority().equals("ROLE_USER"))) {
            nextPage = "redirect:/user";
        } else if (authorities.stream().anyMatch(authority -> authority.getAuthority().equals("ROLE_ADMIN"))) {
            nextPage = "redirect:/admin";
        }

        long endTime = System.nanoTime();
        log.info("Authentication end - Duration = {} ms", (double)(endTime - startTime)/1000000);

        return nextPage;
    }
}
