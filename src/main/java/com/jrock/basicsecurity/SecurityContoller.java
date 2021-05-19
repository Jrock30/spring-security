package com.jrock.basicsecurity;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityContoller {

    /**
     * Spring Security
     * <p>
     * 1. 서버가 기동되면 스프링 시큐리티의 초기화 작업 및 보안 설정이 이루어진다
     * 2. 별도의 설정이나 구현을 하지 않아도 기본적인 웹 보안 기능이 현재 시스템에 연동되어 작동함
     * - 모든 요청은 인증이 되어야 자원에 접근이 가능하다.
     * - 인증 방식은 폼 로그인 방식과 httpBasic 로그인 방식을 제공한다
     * - 기본 로그인 페이지 제공한다
     * - 기본 계정 한개 제공한다 - username: user // password: 랜덤 문자열(콘솔확인)
     * 즉 시큐리티를 추가하면 로그인 페이지가 자동 제공되고 자격증명에 대한 부분으로 인해 / 접근을 하면 /login 으로 이동한다.
     * <p>
     * 문제점
     * - 계정 추가, 권한 추가, DB연동 등
     * - 기본적인 보안 기능 외에 시스템에서 필요오 하는 더 세부적이고 추가적인 보안기능이 필요.
     */
    @GetMapping("/")
    public String index() {
        return "home";
    }

    @GetMapping("/loginPage")
    public String loginPage() {
        return "loginPage";
    }
}