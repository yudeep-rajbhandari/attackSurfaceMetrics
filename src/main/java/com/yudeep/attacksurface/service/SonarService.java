package com.yudeep.attacksurface.service;


import com.yudeep.attacksurface.configuration.Mapper;
import com.yudeep.attacksurface.entity.Sonar;
import com.yudeep.attacksurface.entity.SonarIssues;
import com.yudeep.attacksurface.entity.SonarRuleWrapper;
import com.yudeep.attacksurface.entity.SonarRules;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVRecord;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.support.BasicAuthorizationInterceptor;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;
import similarity.TextSimilarity;

import javax.swing.text.html.HTMLDocument;
import javax.swing.text.html.HTMLEditorKit;
import javax.swing.text.html.parser.ParserDelegator;
import java.io.*;
import java.net.MalformedURLException;
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
        TextSimilarity textSimilarity = similarityCalculator.calculateSimilarity();
        textSimilarity.addDocument("new",sonarRules.get(0).getName());
        textSimilarity.calculate();
        List<String> sim = textSimilarity.getSimilarDocuments("new",1);
        System.out.println(sim);
        return sonarRules;
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
