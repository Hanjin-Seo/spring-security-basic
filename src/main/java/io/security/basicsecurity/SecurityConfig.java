package io.security.basicsecurity;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 인가정책
        http
                .authorizeRequests()
                .anyRequest().authenticated();
        // 인증정책
        http
                .formLogin()
//                .loginPage("/loginPage")                    // 사용자 정의 로그인 페이지
                .defaultSuccessUrl("/")                     // 사용자 성공 후 이동 페이지
                .failureUrl("/login")     // 로그인 실패 후 이동 페이지
                .usernameParameter("userId")                // 아이디 파라미터명 설정
                .passwordParameter("passwd")                // 패스워드 파라미터명 설정
                .loginProcessingUrl("/login_proc")          // 로그인 Form Action Url
                .successHandler(new AuthenticationSuccessHandler() {    // 로그인 성공 후 핸들러
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
                        System.out.println("authentication :" + authentication.getName());
                        httpServletResponse.sendRedirect("/");
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() {    // 로그인 실패 후 핸들러
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
                        System.out.println("exception :" + e.getMessage());
                        httpServletResponse.sendRedirect("/login");
                    }
                })
                .permitAll()
        ;
    }
}
