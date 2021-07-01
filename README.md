# Spring Security

## 소프트웨어 구성
- Spring Web
- Spring Security
- - -

- Securiy Library 추가
> 1. 서버가 기동되면 스프링 시큐리티의 초기화 작업 및 보안 설정이 이루어진다
> 2. 별도의 설정이나 구현을 하지 않아도 기본적인 웹 보안 기능이 현재 시스템에 연동되어 작동함
>   - 모든 요청은 인증이 되어야 자원에 접근이 가능하다.
>   - 인증 방식은 폼 로그인 방식과 httpBasic 로그인 방식을 제공한다
>   - 기본 로그인 페이지 제공한다
>   - 기본 계정 한개 제공한다 - username: user // password: 랜덤 문자열(콘솔확인)  
> * 즉 시큐리티를 추가하면 로그인 페이지가 자동 제공되고 자격증명에 대한 부분으로 인해 / 접근을 하면 /login 으로 이동한다.

- 익명사용자 인증
> 로그인에 인증이 되지 않은 객체도 AnonymousAuthenticationFilter 를 통해 principal : anonymousUser 로 관리된다.  
> 최종적으로는 AbstractSecurityInterceptor 를 통한다.   
> 객체지향의 관점에서 인증된 유저와 같이 객체를 통해 관리 된다.  