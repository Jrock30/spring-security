package com.jrock.basicsecurity;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

/**
 * WebSecurityConfigurerAdapter 를 상속 받아 기본 기능들 재정의 한다.
 */
@Configuration
@EnableWebSecurity // 웹 보안 활성화 어노테이션
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().authenticated(); // 어떤 요청에도 인증을 받도록

        // 로그인
        http
                .formLogin()                            // 인증 폼 로그인 방식
//                .loginPage("/loginPage")                // 사용자 정의 로그인 페이지
                .defaultSuccessUrl("/")                 // 로그인 성공 후 이동 페이지, 우선순위가 맨 마지막 ( successHandler 보다 뒤 ), 우선순위 당기려면 두번째 인자에 true 주면 됨 기본은 false
                .failureUrl("/home")                    // 로그인 실패 후 이동 페이지
                .usernameParameter("userId")            // 아이디 파라미터명 설정
                .passwordParameter("password")          // 패스워드 파라미터명 설정
                .loginProcessingUrl("/login_proc")      // 로그인 Form Action Url
                .successHandler(new AuthenticationSuccessHandler() {    // 로그인 성공 후 핸들러
                    @Override // 익명 클래스 생성
                    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
                        System.out.println("authentication : " + authentication.getName());
                        httpServletResponse.sendRedirect("/");
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() {    // 로그인 실패 후 핸들러
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
                        System.out.println("exception : " + e.getMessage());
                        httpServletResponse.sendRedirect("/login");
                    }
                })
        .permitAll() // 위의 페이지에는 모두 접근이 가능하도록 설정 /login (default), /loginPage (주석처리 부분 패스)
        ;

        /**
         * 로그아웃
         * 기본 POST, get 으로 바꿀수도 있음.
         */
        http
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login")
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) {
                        HttpSession session = httpServletRequest.getSession();
                        session.invalidate(); // 세션 무효화
                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() { // .logoutSuccessUrl 보다 좀 더 다양한 행위를 하기 위해 구현
                    @Override
                    public void onLogoutSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
                        httpServletResponse.sendRedirect("/login");
                    }
                })
                .deleteCookies("remember-me") // 쿠키 삭제 명
                ;
    }
}

