package lt.debarz.authenticationcodeexercises.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private static final int PASSWORD_ENCODER_SALT_LENGTH = 16;
    private static final int PASSWORD_ENCODER_HASH_LENGTH = 32;
    private static final int PASSWORD_ENCODER_PARALLELISM = 1;
    private static final int PASSWORD_ENCODER_MEMORY = 1 << 12;
    private static final int PASSWORD_ENCODER_ITERATIONS = 3;

    @Autowired
    private DataSource datasource;

    @Bean
    public UserDetailsManager initializeJdbcUserDetailManager() {
        return new JdbcUserDetailsManager(datasource);
    }

    @Bean
    public PasswordEncoder initializePasswordEncoder(){
        return new Argon2PasswordEncoder(
                PASSWORD_ENCODER_SALT_LENGTH,
                PASSWORD_ENCODER_HASH_LENGTH,
                PASSWORD_ENCODER_PARALLELISM,
                PASSWORD_ENCODER_MEMORY,
                PASSWORD_ENCODER_ITERATIONS
        );
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers(
                        "/",
                        "/js/**",
                        "/css/**",
                        "/img/**",
                        "/webjars/**",
                        "/login",
                        "/authenticate").permitAll()
                .antMatchers("/user/**").hasRole("USER")
                .antMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
                .and()
                .formLogin().disable();
    }
}
