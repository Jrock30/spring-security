package com.jrock.basicsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

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
//@Order(0) SecurityConfig2 등 여러개를 만들 시 @Order 를 통해 순서를 지정해야한다.
// 여거래의 SecurityConfig 를 만들 시 SecurityFilterChains 에 배열로 여러개가 만들어 진다.
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
                .antMatchers("/login").permitAll() // login 페이지 모두 접근 permitAll
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
                .successHandler(new AuthenticationSuccessHandler() {    // 로그인 성공 후 핸들러, new CustomAuthenticationHandler(){} 커스텀
                    @Override // 익명 클래스 생성
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        System.out.println("authentication : " + authentication.getName());
//                        httpServletResponse.sendRedirect("/");
//                        httpServletResponse.sendRedirect("/");
                        /**
                         * RequestCache 를 사용
                         *  - 사용자의 이전 요청 정보를 세션에 저장하고 이를 꺼내 오는 캐시 메커니즘
                         *  - HttpSessionRequestCache 객체 저장, 이 구현체가 저장하고 있음.
                         *  - ex- 이전 페이지에서 예외가 발생하면 이전 페이지를 저장(캐싱)하고 있다가 로그인 하면 다시 그 페이지로 갈 수 있게끔 할 수 있다.
                         *  - SavedRequest 객체를 계속 사용할 수 있도록 하는 필터 RequestCacheAwareFilter
                         *  *****
                         *  * 이 필터들은 인증이 필요한 페이지에 인증 및 인가가 되지 않는 사용자가 접근하였을 때 발생한다. 즉 인증이 필요하지 않는 페이지에 접근은 했을 시에는 발생하지 않는다는 점을 명심하자.
                         *  *  - ex) /login 으로 접근했다가 SavedRequest 객체를 불러왔는데 null 이 되어 redirect 시 데이터가 없으므로 에러 발생
                         *  *  - ex) 아래 처럼 null 처리 하는 것도 괜찮을듯
                         *  * *****
                         */
                        RequestCache requestCache = new HttpSessionRequestCache();
                        SavedRequest savedRequest = requestCache.getRequest(request, response); // 이전 정보 꺼내옴
                        if (savedRequest != null) {
                            String redirectUrl = savedRequest.getRedirectUrl();// 사용자가 원래 있던 페이지 정보
                            response.sendRedirect(redirectUrl); // 이전페이지로 이동 redirect
                        } else {
                            response.sendRedirect("/");
                        }
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

        /**
         * 인증, 인가 Exception
         * *****
         * 이 필터들은 인증이 필요한 페이지에 인증 및 인가가 되지 않는 사용자가 접근하였을 때 발생한다. 즉 인증이 필요하지 않는 페이지에 접근은 했을 시에는 발생하지 않는다는 점을 명심하자.
         *  - ex) /login 으로 접근했다가 SavedRequest 객체를 불러왔는데 null 이 되어 redirect 시 데이터가 없으므로 에러 발생
         * *****
         * - 인증/인가 예외 API 필터 - ExceptionTranslationFilter ( 가장 먼저 FilterSecurityInterceptor 를 탄다. 그 다음 ExceptionTranslationFilter)
         *  - AuthenticationException
         *    - 인증 예외처리
         *        1. AuthenticationEntryPoint ( 이 것이 타기 전에 SecurityContext 를 null 로 만듦)
         *            - 로그인 페이지 이동, 401 오류 코드 전달 등
         *        2. 인증 예외가 발생하기 전의 요청 정보를 저장 (ex- 이전 페이지에서 예외가 발생하면 이전 페이지를 저장(캐싱)하고 있다가 로그인 하면 다시 그 페이지로 갈 수 있게끔 할 수 있다.)
         *            - RequestCache -> 사용자의 이전 요청 정보를 세션에 저장하고 이를 꺼내 오는 캐시 메커니즘 (이 구현체가 저장하고 있음., HttpSessionRequestCache 객체 저장)
         *                - SavedRequest -> 사용자가 요청했던 request parameter 값들, 그 당시의 헤더값들 등이 저장
         *                  - SavedRequest 객체를 계속 사용할 수 있도록 하는 필터 RequestCacheAwareFilter
         *  - AccessDeniedException
         *    - 인가 예외처리
         *        - AccessDeniedHandler 에서 예외 처리하도록 제공 (이 다음 보통은 response.redirect(/denied))
         */
        http
                .exceptionHandling()
//                .authenticationEntryPoint(new AuthenticationEntryPoint() {
//                    @Override
//                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {
//                        /**
//                         * 인증에 실패하면 /login 으로 이동
//                         * 여기의 /login 은 시큐리티 페이지가 아니고 사용자가 만든 login 으로 이동한다.
//                         */
//                        response.sendRedirect("/login");
//                    }
//                })
                .accessDeniedHandler(new AccessDeniedHandler() {
                    @Override
                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException e) throws IOException, ServletException {
                        // 인가(권한)에 실패하면 /denied 으로 이동
                        response.sendRedirect("/denied");
                    }
                });

        /**
         * - Form 인증 - CSRF(사이트 간 요청 위조)
         *  - CsrfFilter (.doFilterInternal)
         *    - 모든 요청에 랜덤하게 생성된 토큰을 HTTP Parameter 로 요구
         *    - 요청 시 전달되는 토큰 값과 서버에 저장된 실제 값과 비교한 후 만약 일치하지 않으면 요청은 실패한다.
         *     - Client
         *       - input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"
         *       - X-CSRF-TOKEN=""
         *       - HTTP 메소드 : PATCH, POST, PUT, DELETE
         *     - Spring Security
         *       - http.csrf(): 기본 활성화
         *       - http.csrf().disabled(): 비활성화
         */
//        http.csrf().disable();
    }
}

