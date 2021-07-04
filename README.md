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

- 동시 세션 제어
> http.sessionManagement() : 세션 관리 기능이 작동함
> - 최대 세션 허용 개수 초과    
> > - 이전 사용자 세션만료 (기존 세션 만료(사용자1 세션만료), false)  
> > 동일한 계정 사용자1 이 먼저 로그인 했고 사용자2가 로그인 한 경우 **사용자1의 세션은 만료 설정**
> > - 현재 사용자 인증 실패 (사용자2 인증실패, true)
> > 동일한 계정 사용자1 이 먼저 로그인 했고 사용자2가 로그인 한 경우 **사용자2의 인증 예외 발생 설정**

- 세션 고정 보호
> 공격자가 JSESSIONID 를 발급해 놓고 사용자 쿠키에 심어 놓으면 사용자가 심어 놓은 JSESSIONID 를 가지고 
> 로그인을 하게 되면 세션은 공유되어 모든 정보가 공유된다.   
> 이를 방지 하기 위해 스프링 시큐리티는 JSESSIONID 이 같더라도 서버에 접속하면 새로운 세션을 발급한다.
> > htpp.sessionManagement().sessionFixation().changeSessionId() //none, changeSessionId(), migrateSession(), newSession()   
> > 기본 값은 서블릿 3.1 이상 changeSessionId(), 3.1 이하 migrateSession()

- 세션 정책
> http.sessionManagement().sessionCreationPolicy(sessionCreation.If_Required)
> If_Required -> 스프링 시큐리티가 필요 시 세션 생성 (기본값)
> Always      -> 스프링 시큐리티가 항상 세션 생성
> Never       -> 스프링 시큐리티가 세션을 생성하지 않지만 이미 존재하면 사용
> Stateless   -> 스프링 시큐리티가 세션을 생성하지 않고 존재해도 사용하지 않음 (세션을 사용하지 않고 JWT 같은 것을 사용할 떄)

- 인증 API
> User1 접속 시 
> 1. UsernamePasswordAuthenticationFilter, ConcurrentSessionFilter(세션 만료되었는지 항상 체크)  login
> 2. ConcurrentSessionControlAuthenticationStrategy 에서 session count 0 체크
> 3. ChangeSessionIdAuthenticationStrategy 에서 session.changeSessionId() 새롭게 세션 ID 생성
> 4. RegisterSessionAuthenticationStrategy 세션정보 등록 : session count 1    
>
> User1 과 같은 User2 접속 시 
> 1. 위와 똑같은 과정을 거치면서 ConcurrentSessionControlAuthenticationStrategy 에서 session count 1 (sessionCount == maxSessions )
> 2. 인증 전략에 따라  
> 2.1 인증실패 전략인 경우 SessionAuthenticationException -> user2 인증실패  
> 2.2 세션만료 전략인 경우 session.expireNow(): user1 -> user1 세션 만료 후 위의 user1 과정 실행   
> 2.3 user1 은 요청 시 session.isExpired() 가 ture 가 되어 logout 된다.