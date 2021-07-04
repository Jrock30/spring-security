package com.jrock.basicsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
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

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        /**
         * 메모리 방식으로 USER 생성
         * {noop} 암호화 방식을 prefix 로 지정함, 지정하지 않으면 에러 발생, {noop} 은 평문으로 암호화를 한다. 즉 암호화하지 않음.
         */
        auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
        auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN", "SYS");
    }

    /**
     * 인증 관련 HttpSecurity
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        /**
         * - 인가 API 권한설정
         *   - 선언적 방식
         *     * URL
         *        - http.antMatchers("/users/**).hasRole("USER")
         *     * Method
         *        - @PreAuthorize("hasRole('USER)")
         *   - 동적방식 - DB 연동 프로그래밍
         *     - URL
         *     - Method
         *   **설정 시 구체적인 경로가 먼저 오고 그것 보다 큰 범위의 경로가 뒤에 오도록 하자.**
         */
        http
                // 인가
                .authorizeRequests()
                .antMatchers("/user").hasRole("USER") // /{path} 요청을 하면 USER 인가 처리를 한다.
                .antMatchers("/admin/pay").hasRole("ADMIN")
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')") // SpEL
                .anyRequest().authenticated(); // 어떤 요청에도 인증을 받도록

        // 로그인 인증
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
         * 기본 POST, GET 으로 바꿀수도 있음.
         * LogoutFilter.java
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

        /**
         * rememberMe
         *
         * 처리 조건
         *   - 로그아웃이 세션이 만료 되었을 떄 ( 인증객체가 없을 경우 )
         *   - remember me 쿠키를 가지고 있는 경우
         *   - RememberMeAuthenticationFilter -> RememberMeServices (TokenBasedRememberMeServices, PersistentTokenBasedRememberMeServices)
         *      -> Token Cookie 추출 -> Token 존재여부 판단 -> Decode Token(정상 유무 판단) -> Token 이 서로 일치하는가 -> User 계정이 존재하는가 -> 새로운 Authentication 생성 -> AuthenticationManager
         */
        http
                .rememberMe()
                .rememberMeParameter("remember") // 기본 파라미터명 remember-me
                .tokenValiditySeconds(3600) // Default 14일
//                .alwaysRemember(true) // 리벱버 미 기능이 활성화 되지 않아도 항상 실행
                .userDetailsService(userDetailsService)
                ;

        /**
         * 동시 세션 제어
         */
        http
                .sessionManagement()
                .maximumSessions(1) // 세션 최대 허용 개수, -1 -> 무제한 설정
                .maxSessionsPreventsLogin(false); // 허용개수 초과 시 제어 default - false(기존 세션 만료(사용자1 세션만료)), true (사용자2 인증실패, true))
//                .expiredUrl("/path") // 세션이 만료된 경우 이동할 페이지

        /**
         * 세션 고정보호
         *  공격자가 JSESSIONID 를 발급해 놓고 사용자 쿠키에 심어 놓으면 사용자가 심어 놓은 JSESSIONID 를 가지고
         *  로그인을 하게 되면 세션은 공유되어 모든 정보가 공유된다.
         *  - none()            -> 아무것도 사용하지 않음 ( JSESSIONID 로 공격하면 먹힘 )
         *  - changeSessionId() -> 서블릿 3.1 이상 default
         *  - migrateSession()  -> 서블릿 3.1 미만 default
         *  - newSession()
         */
        http
                .sessionManagement()
                .sessionFixation().changeSessionId();
    }
}

