package com.yudeep.attacksurface.service;

import com.yudeep.attacksurface.entity.Sonar;
import com.yudeep.attacksurface.entity.SonarIssues;
import com.yudeep.attacksurface.entity.SonarRules;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SonarService {

    @Autowired
    private RestTemplate restTemplate;

    private List<SonarIssues> getAllIssues(){
        Sonar sonar = restTemplate.getForObject("localhost:9000/api/issues/search", Sonar.class);
        List<SonarIssues> issues = sonar.getSonarIssues();
        return issues;
    }
    private SonarRules getSonarRules(String ruleName){
        String url = "language={language}&rule_key={rule}";
        Map<String, String> queryParamMap = new HashMap<>();
        queryParamMap.put("language","Java");
        queryParamMap.put("rule",ruleName);
        HttpHeaders headers = new HttpHeaders();
        HttpEntity requestEntity = new HttpEntity<>(headers);
        UriComponents builder = UriComponentsBuilder.fromHttpUrl("localhost:9000/api/api/rules/search").query(url).buildAndExpand(queryParamMap);
        ResponseEntity<SonarRules> rules = restTemplate.exchange(builder.toUriString(), HttpMethod.GET,requestEntity,SonarRules.class);
        return rules.getBody();
    }

}
