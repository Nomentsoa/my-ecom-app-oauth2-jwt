package ca.lazanomentsoa.securityservice.web;


import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class TestRestAPI {

    @GetMapping("/dataTest")
    public Map<String, Object> dataTest(Authentication authentication){
        return Map.of(
                "message", "Data test",
                "usename", authentication.getName(),
                "authorities", authentication.getAuthorities());
    }

}
