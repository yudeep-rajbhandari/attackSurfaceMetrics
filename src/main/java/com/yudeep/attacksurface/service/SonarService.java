package com.yudeep.attacksurface.service;


import com.yudeep.attacksurface.configuration.Mapper;
import com.yudeep.attacksurface.entity.*;
import org.json.JSONArray;
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
import similarity.TextSimilarity;

import javax.annotation.PostConstruct;
import javax.swing.text.html.HTMLDocument;
import javax.swing.text.html.HTMLEditorKit;
import javax.swing.text.html.parser.ParserDelegator;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Service
public class SonarService {

    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    private Mapper mapper;

    @Autowired
    private SimilarityCalculator similarityCalculator;

    Map<String, List<String>> stringListMap = new HashMap<>();

    @PostConstruct
    private void populate(){
        try {
            stringListMap =   mapper.getCVEList();

        }
        catch (Exception e){

        }
    }

    public List<SonarRules> calculate(){
//        String[] tags = {"cert","cwe","owasp"};
        List<String> tags = Arrays.asList(new String[]{"cert", "cwe", "owasp"});
        List<SonarIssues> issues = getAllIssues();
        List<SonarIssues> filteredIssue = issues.stream().filter(i->tags.stream().anyMatch(i.getTags()::contains)).collect(Collectors.toList());
        List<SonarRules> sonarRules = new ArrayList<>();
        for(SonarIssues sonarIssues:filteredIssue){
            SonarRuleWrapper wrapper =  getSonarRules(sonarIssues.getRule());
            SonarRules sonarRules1 = wrapper.getRulesList().get(0);
            Map<String,List<String>> aa= scrapper(sonarRules1.getHtmlDesc());
            sonarRules1.setTitle(aa);
            sonarRules.add(wrapper.getRulesList().get(0));
        }
        processParent(sonarRules);
        getRelatedCVEs(sonarRules);
//        TextSimilarity textSimilarity = similarityCalculator.calculateSimilarity();
//        textSimilarity.addDocument("new",sonarRules.get(0).getName());
//        textSimilarity.calculate();
//        List<String> sim = textSimilarity.getSimilarDocuments("new",10);
//        System.out.println(sim);

        return sonarRules;
    }

    private void getRelatedCVEs(List<SonarRules> sonarRules) {
        for(SonarRules sonarRules1:sonarRules){
            String cwe = sonarRules1.getEffectiveCWE();
            Parent parent1003 = getCWEParent1003(cwe);
            if(parent1003 !=null){
                JSONArray array = getObservedCVE(parent1003.getAttr().getCWEID());
                for(int i = 0; i< array.length();i++){
                    JSONObject jsonObject = array.getJSONObject(i);
                    sonarRules1.getCVEList().add(jsonObject.get("Reference").toString());
                }
            }
            else{
                try {

                    List<String> effectiveCVEs =stringListMap.get("CWE-"+cwe);
                    sonarRules1.setCVEList(effectiveCVEs);
                }
                catch (Exception e){
                    System.out.println(">>>>>>>");
                }

            }
        }
    }

    private List<SonarRules>  processParent(List<SonarRules> sonarRules){
        for(SonarRules sonarRules1:sonarRules){
            Map<String,List<String>> parentMap = new HashMap<>();
            List<String> owasp= sonarRules1.getTitle().get("owasp");
            List<String> cwes= sonarRules1.getTitle().get("cwe");
            List<String> cweList = new ArrayList<>();
            for(String owas:owasp){
                String[] a = owas.split(" ");
                List<String> cweList1 = getAllOwasps(a[a.length-1]);
                cweList.addAll(cweList1);

            }
            for(String c:cwes){
                cweList.add(c.split("-")[1]);
            }
            for(String cwe:cweList){

                String id = cwe;
                List<String> parent = new ArrayList<>();
                Parent a = getCWEParent(id);
                while(a !=null){
                    parent.add(a.getAttr().getCWEID());
                    a = getCWEParent(a.getAttr().getCWEID());

                }
                parentMap.put(id,parent);


            }
           String cc = getCommonParent(parentMap);
            sonarRules1.setEffectiveCWE(cc);
            System.out.println(cc);

        }
        return sonarRules;
    }

    private String getCommonParent(Map<String,List<String>> parentMap){
        if(parentMap.keySet().size() <1){
            return null;
        }
        if(parentMap.keySet().size() ==1){
            List<String> a = new ArrayList<>();
            a.addAll(parentMap.keySet());
            List<String> bb = parentMap.get(a.get(0));
            return bb.get(bb.size()-1);
        }
        Collection<List<String>> parent = parentMap.values();
        List<List<String>> aa = new ArrayList<>();
        aa.addAll(parent);
        List<String> newa = new ArrayList<>();
        newa.addAll(aa.get(0));

        for(int i = 1;i< aa.size();i++){
            newa.retainAll(aa.get(1));
        }
        return newa.get(0);
    }
    public List<SonarIssues> getAllIssues(){
        Sonar sonar = restTemplate.getForObject("http://localhost:9000/api/issues/search", Sonar.class);
        List<SonarIssues> issues = sonar.getSonarIssues();

//        List<SonarIssues> issues = new ArrayList<>();
        return issues;
    }
    public  List<String> getAllOwasps(String Owasp){
        try {
            Map<String,List<String>> listMap = mapper.getOWASPList();
            return listMap.get(Owasp);
        }
        catch (Exception e){
            System.out.println(e);
        }
        return new ArrayList<>();
    }
    private SonarRuleWrapper getSonarRules(String ruleName){
        String url = "language={language}&rule_key={rule}";
        Map<String, String> queryParamMap = new HashMap<>();
        queryParamMap.put("language","Java");
        queryParamMap.put("rule",ruleName);
        HttpHeaders headers = new HttpHeaders();
        HttpEntity requestEntity = new HttpEntity<>(headers);
        UriComponents builder = UriComponentsBuilder.fromHttpUrl("http://localhost:9000/api/rules/search").query(url).buildAndExpand(queryParamMap);
        ResponseEntity<SonarRuleWrapper> rules = restTemplate.exchange(builder.toUriString(), HttpMethod.GET,requestEntity,SonarRuleWrapper.class);
        return rules.getBody();
    }

    private Parent getCWEParent(String id){
        String url = id;
//        Map<String, String> queryParamMap = new HashMap<>();
//        queryParamMap.put("language","Java");
//        queryParamMap.put("rule",ruleName);
        HttpHeaders headers = new HttpHeaders();
        HttpEntity requestEntity = new HttpEntity<>(headers);
        UriComponents builder = UriComponentsBuilder.fromHttpUrl("http://localhost:5000/"+id).buildAndExpand();
        ResponseEntity<Parent> rules = restTemplate.exchange(builder.toUriString(), HttpMethod.GET,requestEntity,Parent.class);
        return rules.getBody();
    }

    private Parent getCWEParent1003(String id){
        String url = id;
        HttpHeaders headers = new HttpHeaders();
        HttpEntity requestEntity = new HttpEntity<>(headers);
        UriComponents builder = UriComponentsBuilder.fromHttpUrl("http://localhost:5000/cwe2/"+id).buildAndExpand();
        ResponseEntity<Parent> rules = restTemplate.exchange(builder.toUriString(), HttpMethod.GET,requestEntity,Parent.class);
        return rules.getBody();
    }

    private JSONArray getObservedCVE(String id){
        String url = id;
        HttpHeaders headers = new HttpHeaders();
        HttpEntity requestEntity = new HttpEntity<>(headers);
        UriComponents builder = UriComponentsBuilder.fromHttpUrl("http://localhost:5000/observed/"+id).buildAndExpand();
        ResponseEntity<String> rules = restTemplate.exchange(builder.toUriString(), HttpMethod.GET,requestEntity,String.class);
        return new JSONArray(rules.getBody());
    }


    private Map<String,List<String>> scrapper(String html){
        List<String> linksList = new ArrayList<>();
        List<String> title = new ArrayList<>();
//        String html = "YOUR HTML";
        String regex = "<a href\\s?-\\s?\"([^\"]+)\">";
        String regex_OWASP = "(?=(OWASP[^\\\\s<]+<))";
        String regex_CWE = "(?=(CWE[^\\\\s<]+<))" ;
        String regex_CERT = "(?=(CERT[^\\\\s<]+<))";
        Map<String,List<String>> vunMap = new HashMap<>();

//        String string = "test";
        String pattern = "(?=(CWE[^\\\\s<]+<))";

// Create a Pattern object
        Pattern r = Pattern.compile(pattern);

// Now create matcher object.
        Matcher m = r.matcher(html);

        List<String> OWASPList = getMatchedString(regex_OWASP,html);
        List<String> CWEList = getMatchedString(regex_CWE,html);
        List<String> CertList = getMatchedString(regex_CERT,html);
        vunMap.put("owasp",OWASPList);
        vunMap.put("cwe",CWEList);
        vunMap.put("CertList",CertList);
        return vunMap;


    }

    private List<String> getMatchedString(String regex,String html){
        List<String> linksList = new ArrayList<>();
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(html);
        int index = 0;
        while (matcher.find()) {
            String wholething = matcher.group(); // includes "<a href" and ">"
            String link = matcher.group(1);
            link = link.substring(0,link.length()-1);// just the link
            linksList.add(link);
            // do something with wholething or link.
            index = matcher.end();
        }
        return linksList;
    }
    private String getTitle(String url)  {
        StringBuilder stringBuilder = new StringBuilder();
        try {
            HTMLEditorKit htmlKit = new HTMLEditorKit();
            HTMLDocument htmlDoc = (HTMLDocument) htmlKit.createDefaultDocument();
            HTMLEditorKit.Parser parser = new ParserDelegator();
            parser.parse(new InputStreamReader(new URL(url).openStream()),
                    htmlDoc.getReader(0), true);


            stringBuilder.append(htmlDoc.getProperty("title"));
        }
        catch (Exception e){

        }
     return  stringBuilder.toString();
    }


}
