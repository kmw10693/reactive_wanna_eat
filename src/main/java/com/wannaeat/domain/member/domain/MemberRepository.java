package com.wannaeat.domain.member.domain;


import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

@Repository
public interface MemberRepository extends R2dbcRepository<Member, Long> {
    Mono<Member> findByLoginId(String loginId);
}
