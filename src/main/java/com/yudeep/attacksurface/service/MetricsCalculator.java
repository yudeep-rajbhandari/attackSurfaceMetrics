package com.yudeep.attacksurface.service;

import com.yudeep.attacksurface.entity.CVEScore;
import com.yudeep.attacksurface.entity.Consequence;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import javax.annotation.PostConstruct;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class MetricsCalculator {
    Map<String,Integer> accessComplexityMapper = new HashMap<>();
    Map<String,Integer> authenticationMapper = new HashMap<>();

    Map<String,Integer> severityMapper = new HashMap<>();


    @Autowired
    @Qualifier(value = "restbuilder")
    private RestTemplate restTemplate;


    @PostConstruct
    private void setSynonym(){
        accessComplexityMapper.put("HIGH",10);
        accessComplexityMapper.put("MEDIUM",7);
        accessComplexityMapper.put("LOW",4);
        accessComplexityMapper.put("NONE",1);
        authenticationMapper.put("MULTIPLE",10);
        authenticationMapper.put("SINGLE",7);
        authenticationMapper.put("LOW",4);
        authenticationMapper.put("NONE",1);
        severityMapper.put("BLOCKER",10);
        severityMapper.put("CRITICAL",7);
        severityMapper.put("MAJOR",4);
        severityMapper.put("MINOR",2);
        severityMapper.put("INFO",1);
    }


    public int getConsequenceScore(List<Consequence> consequenceList) {
        int finalScore = 0;

        for(Consequence consequence:consequenceList){
            int conImpactScore =0;
            int integrityImpactScore =0;
            int availImpactScore=0;
            int otherImpactScore=0;
            int c=0;
            int i=0;
            int a=0;
            int o=0;
            if(consequence.getScope().contains("Confidentiality")){
                conImpactScore =  getImpact(consequence.getImpact());
               c=1;
            }
            if(consequence.getScope().contains("Integrity")){
                integrityImpactScore =  getImpact(consequence.getImpact());
                i=1;
            }
            if(consequence.getScope().contains("Availability")){
                availImpactScore =  getImpact(consequence.getImpact());
                a=1;
            }
            if(c==0 && i==0 && a ==0){
                otherImpactScore =  getImpact(consequence.getImpact());
                o=1;
            }
            int consequenceScore = c * conImpactScore + i * integrityImpactScore + a * availImpactScore + o *otherImpactScore;
            finalScore = finalScore + consequenceScore;

        }
        return finalScore;

    }
    public int getImpact(List<String> impact){
        if(!impact.stream().filter(i->i.contains("read") || i.contains("Read")).collect(Collectors.toList()).isEmpty()){
            return 4;
        }
        if(!impact.stream().filter(i->i.contains("modify") || i.contains("Modify")).collect(Collectors.toList()).isEmpty()){
            return 7;
        }
        if(!impact.stream().filter(i->i.contains("execute") || i.contains("Execute") || i.contains("Dos")).collect(Collectors.toList()).isEmpty()){
            return 10;
        }
        return 4;
    }
    public CVEScore getCVE(String id){
        try{
            System.out.println(id);
            HttpHeaders headers = new HttpHeaders();
            HttpEntity<String> requestEntity = new HttpEntity<>(headers);
            UriComponents builder = UriComponentsBuilder.fromHttpUrl("http://localhost:8000/api/cve/"+id).buildAndExpand();
            ResponseEntity<String> rules = restTemplate.exchange(builder.toUriString(), HttpMethod.GET,requestEntity, String.class);
            JSONObject object = new JSONObject(rules.getBody());
            JSONObject newObj = object.getJSONObject("raw_nvd_data").getJSONObject("impact").getJSONObject("baseMetricV2").getJSONObject("cvssV2");
            return new CVEScore(newObj.getString("accessComplexity"), newObj.getString("authentication") );
        }
        catch (Exception e){
            return null;
        }

    }



    public int getAccessComplexityScore(String cve){
        return accessComplexityMapper.get(cve);
    }

    public int getAuthenticationScore(String cve){
        return authenticationMapper.get(cve);
    }

    public int getSeverityScore(String severity){
        return severityMapper.get(severity);
    }
}
