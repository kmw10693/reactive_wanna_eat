# wanna-eat-BE

Spring WebFlux + R2DBC + PostgreSQL 

---

# Spring WebFlux 도입 이유

- 기존 Spring MVC는 요청이 들어오면 Thread-per-Request 방식으로 작동하여, I/O 작업이 많아질수록 스레드가 블로킹됨.
- 반면, WebFlux는 이벤트 루프 기반(reactor-netty)으로 동작하여, 적은 스레드로 많은 요청을 처리 가능.
- 즉, 트래픽이 많거나, 대기 시간이 긴 API(ex. 외부 API 호출, DB I/O 작업 등) 에서 성능을 극대화할 수 있음.

# R2DBC 도입 이유

- JDBC는 SQL 실행 시 DB 커넥션을 점유하고 결과를 받을 때까지 블로킹됨.
- 반면, R2DBC는 데이터베이스와 비동기 통신하여 블로킹 없이 응답을 받을 수 있음.
- 즉, 대량의 DB 요청이 발생해도 높은 동시성 처리 가능

# PostgreSQL 도입 이유

- PostgreSQL은 R2DBC와의 호환성이 뛰어나고, 확장성이 높음