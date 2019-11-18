# OAuth2 란

OAuth는 Open Authorization, Open Authentication 뜻하는 것으로 자신의 애플리케이션 서버의 데이터로 다른 Third party에게 자원을 공유하거나 대신 유저 인증을 처리해줄 수 있는 오픈 표준 프로토콜이다.

대표적인 예가 구글인증이나 페이스북인증입니다. 회원가입이나 로그인시에 구글 또는 페이스북으로 연결을 지원하는 방식입니다. 요즘에는 네이버로그인과 카카오로그인도 있습니다.


# OAuth2 승인방식

-   Authorization Code Grant Type : 권한 부여 코드 승인 타입  
    클라이언트가 다른 사용자 대신 특정 리소스에 접근을 요청할 때 사용됩니다. 리소스 접근을 위한 사용자 명과 비밀번호, 권한 서버에 요청해서 받은 권한 코드를 함께 활용하여 리소스에 대한 엑세스 토큰을 받는 방식입니다.  
    클라이언트가 시스템 서버로 구현됩니다.
-   Implicit Grant Type : 암시적 승인  
    권한 부여 코드 승인 타입과 다르게 권한 코드 교환 단계 없이 엑세스 토큰을 즉시 반환받아 이를 인증에 이용하는 방식입니다.  
    클라이언트가 웹브라우저에서 직접 통신을하며 자바스크립트 등의 언어로 구현됩니다.
-   Resource Owner Password Credentials Grant Type : 리소스 소유자 암호 자격 증명 타입  
    클라이언트가 사용자이름과 암호를 직접 Authorization Server에 전달하여 엑세스 토큰에 대한 사용자의 자격 증명을 교환하는 방식입니다. Authorization Server의 로그인화면이 생략됩니다.  
    네트워크를 통하여 사용자의 이름과 암호가 노출이 되는 방식이므로 보안프로토콜(https)를 사용하여 네트워크를 통해 중요정보가 탈취되지 않도록 해야 합니다.
-   Client Credentials Grant Type : 클라이언트 자격 증명 타입  
    클라이언트가 컨텍스트 외부에서 액세스 토큰을 얻어 특정 리소스에 접근을 요청할 때 사용하는 방식입니다.  
    토큰을 요청하면 인증없이 바로 액세스 토큰을 발급합니다. 인증이 없으므로 접근권한 관리에 유의하여 사용해야 합니다.


# Spring Boot with OAuth2 Server
- [Chapter 01 - Spring Boot OAuth2 Server, 4 Types](https://github.com/parandol/spring-boot-oauth2-examples/tree/master/spring-boot-oauth2-server-chap01)

