package com.yudeep.attacksurface.service;

import com.yudeep.attacksurface.entity.*;
import org.json.JSONArray;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

@Service
public class ApiService {


    @Value("${api1.address}")
    private String apiAddress;

    @Value("${api2.address}")
    private String nodeAddress;

    @Autowired
    private RestTemplate restTemplate;

    private final static Logger LOGGER =
            Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);

    public List<SonarIssues> getAllIssues(String target,Integer page){
        List<SonarIssues> issues = new ArrayList<>();
        Sonar sonar = restTemplate.getForObject(apiAddress+"/api/issues/search?componentKeys="+target+"&ps=500&p="+page, Sonar.class);
        if(sonar !=null){
            issues.addAll(sonar.getSonarIssues());

        }
        return issues;
    }
    public SonarRuleWrapper getSonarRules(String ruleName){
        String url = "language={language}&rule_key={rule}";
        Map<String, String> queryParamMap = new HashMap<>();
        queryParamMap.put("language","Java");
        queryParamMap.put("rule",ruleName);
        HttpHeaders headers = new HttpHeaders();
        HttpEntity<String> requestEntity = new HttpEntity<>(headers);
        UriComponents builder = UriComponentsBuilder.fromHttpUrl(apiAddress+"/api/rules/search").query(url).buildAndExpand(queryParamMap);
        ResponseEntity<SonarRuleWrapper> rules = restTemplate.exchange(builder.toUriString(), HttpMethod.GET,requestEntity,SonarRuleWrapper.class);
        return rules.getBody();
    }

    public Parent getCWEParent(String id){
        HttpHeaders headers = new HttpHeaders();
        HttpEntity<String> requestEntity = new HttpEntity<>(headers);
        UriComponents builder = UriComponentsBuilder.fromHttpUrl(nodeAddress+"/"+id).buildAndExpand();
        ResponseEntity<Parent> rules = restTemplate.exchange(builder.toUriString(), HttpMethod.GET,requestEntity,Parent.class);
        return rules.getBody();
    }

    public Consequence[] getCWEConsequence(String id){
        try{
            HttpHeaders headers = new HttpHeaders();
            HttpEntity<String> requestEntity = new HttpEntity<>(headers);
            UriComponents builder = UriComponentsBuilder.fromHttpUrl(nodeAddress+"/consequence/"+id).buildAndExpand();
            ResponseEntity<Consequence[]> rules = restTemplate.exchange(builder.toUriString(), HttpMethod.GET,requestEntity,Consequence[].class);
            return rules.getBody();
        }
        catch (Exception e){
            LOGGER.log(Level.SEVERE,() -> String.format("%1$s", e.getMessage()));

            return new Consequence[0];
        }

    }

    public Parent getCWEParent1003(String id){
        HttpHeaders headers = new HttpHeaders();
        HttpEntity<String> requestEntity = new HttpEntity<>(headers);
        UriComponents builder = UriComponentsBuilder.fromHttpUrl(nodeAddress+"/cwe2/"+id).buildAndExpand();
        ResponseEntity<Parent> rules = restTemplate.exchange(builder.toUriString(), HttpMethod.GET,requestEntity,Parent.class);
        return rules.getBody();
    }
    public JSONArray getObservedCVE(String id){
        HttpHeaders headers = new HttpHeaders();
        HttpEntity<String> requestEntity = new HttpEntity<>(headers);
        UriComponents builder = UriComponentsBuilder.fromHttpUrl(nodeAddress+"/observed/"+id).buildAndExpand();
        ResponseEntity<String> rules = restTemplate.exchange(builder.toUriString(), HttpMethod.GET,requestEntity,String.class);
        if(rules.getBody() != null){
            return new JSONArray(rules.getBody());
        }
        return new JSONArray();

    }
}
