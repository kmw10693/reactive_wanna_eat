package com.wannaeat.domain.member.application;

import com.wannaeat.domain.member.domain.Member;
import com.wannaeat.domain.member.dto.request.MemberCreateRequest;
import com.wannaeat.domain.member.domain.MemberRepository;
import com.wannaeat.domain.member.dto.response.MemberCreateResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
@Slf4j
public class MemberService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    public Mono<MemberCreateResponse> create(MemberCreateRequest memberCreateRequest) {
        String password = passwordEncoder.encode(memberCreateRequest.password());

        log.debug("유저 패스워드 암호화 성공");
        return memberRepository.save(memberCreateRequest.toMember(password))
                .map(MemberCreateResponse::from);
    }

    public Mono<Member> getById(Long id) {
        log.debug("유저 인덱스 검색 userId : {}", id);
        return memberRepository.findById(id);
    }

    public Flux<Member> getAll() {
        log.debug("유저 모두 찾기");
        return memberRepository.findAll();
    }

    public Mono<Void> delete(Long id) {
        log.debug("특정 유저 삭제 {}", id);
        return memberRepository.deleteById(id);
    }
}