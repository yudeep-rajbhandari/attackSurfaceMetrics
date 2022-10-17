package com.yudeep.attacksurface.service;

import com.yudeep.attacksurface.entity.CVEScore;
import com.yudeep.attacksurface.entity.Consequence;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import javax.annotation.PostConstruct;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class MetricsCalculator {
    List<String> executeSynonym  = new ArrayList<>();
    List<String> readSynonym  = new ArrayList<>();
    List<String> modifySynonym  = new ArrayList<>();
    Map<String,Integer> accessComplexityMapper = new HashMap<>();
    Map<String,Integer> authenticationMapper = new HashMap<>();

    Map<String,Integer> severityMapper = new HashMap<>();


    @Autowired
    private RestTemplate restTemplate;


    @PostConstruct
    private void SetSynonym(){
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
            int CimpactScore =0;
            int IimpactScore =0;
            int AimpactScore=0;
            int OimpactScore=0;
            int C=0;
            int I=0;
            int A=0;
            int O=0;
            if(consequence.getScope().contains("Confidentiality")){
               CimpactScore =  getImpact(consequence.getImpact());
               C=1;
            }
            if(consequence.getScope().contains("Integrity")){
                IimpactScore =  getImpact(consequence.getImpact());
                I=1;
            }
            if(consequence.getScope().contains("Availability")){
                AimpactScore =  getImpact(consequence.getImpact());
                A=1;
            }
            if(C==0 && I==0 && A ==0){
                OimpactScore =  1;
                O=1;
            }
            int ConsequenceScore = C * CimpactScore + I * IimpactScore + A * AimpactScore + O*OimpactScore;
            finalScore = finalScore + ConsequenceScore;

        }
        return finalScore;

    }
    public int getImpact(List<String> impact){
        if(impact.stream().filter(i->i.contains("read") || i.contains("Read")).collect(Collectors.toList()).size() >0){
            return 4;
        }
        if(impact.stream().filter(i->i.contains("modify") || i.contains("Modify")).collect(Collectors.toList()).size() >0){
            return 7;
        }
        if(impact.stream().filter(i->i.contains("execute") || i.contains("Execute") || i.contains("Dos")).collect(Collectors.toList()).size() >0){
            return 10;
        }
        return 4;
    }
    public CVEScore getCVE(String id){
        try{
            HttpHeaders headers = new HttpHeaders();
            headers.add("apiKey","b835f28c-2145-4cb6-aa14-ea0fd15e8c8f");
            HttpEntity requestEntity = new HttpEntity<>(headers);
            UriComponents builder = UriComponentsBuilder.fromHttpUrl("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="+id).buildAndExpand();
            ResponseEntity<String> rules = restTemplate.exchange(builder.toUriString(), HttpMethod.GET,requestEntity, String.class);
            JSONObject object = new JSONObject(rules.getBody());
            JSONObject newObj = object.getJSONArray("vulnerabilities").getJSONObject(0).getJSONObject("cve").getJSONObject("metrics").getJSONArray("cvssMetricV2").getJSONObject(0).getJSONObject("cvssData");
            CVEScore cveScore = new CVEScore(newObj.getString("accessComplexity"), newObj.getString("authentication") );
            return cveScore;
        }
        catch (Exception e){
            return null;
        }

    }



    public int getAccessComplexityScore(String CVE){
        return accessComplexityMapper.get(CVE);
    }

    public int getAuthenticationScore(String CVE){
        return authenticationMapper.get(CVE);
    }

    public int getSeverityScore(String Severity){
        return severityMapper.get(Severity);
    }
}
