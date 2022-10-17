package com.yudeep.attacksurface.service;


import com.yudeep.attacksurface.configuration.Mapper;
import com.yudeep.attacksurface.entity.*;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.BeanWrapper;
import org.springframework.beans.BeanWrapperImpl;
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
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
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

    @Autowired
    private MetricsCalculator metricsCalculator;
    Map<String, List<String>> stringListMap = new HashMap<>();
    private static final String OWASP = "owasp";
    private final static Logger LOGGER =
            Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);

    @PostConstruct
    private void populate(){
        try {
            stringListMap =   mapper.getCVEList();

        }
        catch (Exception e){
           LOGGER.log(Level.INFO,"error while populate");
        }
    }

    public List<SonarRules> calculate(){
        Map<String,Integer> sonarCount = null;
        List<String> tags = Arrays.asList(new String[]{"cert", "cwe", OWASP});
        List<SonarIssues> issues = getAllIssues();
        List<SonarIssues> filteredIssue = issues.stream().filter(i->tags.stream().anyMatch(i.getTags()::contains)).collect(Collectors.toList());
        List<SonarRules> sonarRules = new ArrayList<>();
        for(SonarIssues sonarIssues:filteredIssue){
            SonarRuleWrapper wrapper =  getSonarRules(sonarIssues.getRule());
            if(wrapper !=null){
                SonarRules sonarRules1 = wrapper.getRulesList().get(0);
                Map<String,List<String>> aa= scrapper(sonarRules1.getHtmlDesc());
                sonarRules1.setTitle(aa);
                sonarRules.add(wrapper.getRulesList().get(0));
            }

        }
        sonarCount = rulesToMap(sonarRules);
        List<SonarRules> uniqueSonarRules = processParent(sonarCount,sonarRules);
        getRelatedCVEs(uniqueSonarRules);

        calculateCWEConsequence(uniqueSonarRules);
        scoreCVE(uniqueSonarRules);

        double finalScore = finalScoreCalculation(uniqueSonarRules,sonarCount);
        LOGGER.log(Level.INFO,"final Score "+finalScore);


        TextSimilarity textSimilarity = similarityCalculator.calculateSimilarity();
        textSimilarity.addDocument("new",sonarRules.get(0).getName());
        textSimilarity.calculate();
        List<String> sim = textSimilarity.getSimilarDocuments("new",10);
        return uniqueSonarRules;
    }

    private double finalScoreCalculation(List<SonarRules> uniqueSonarRules, Map<String, Integer> sonarCount) {
        for(SonarRules sonarRules:uniqueSonarRules){
            Integer damagePotential = sonarRules.getConsequencScore() * metricsCalculator.getSeverityScore(sonarRules.getSeverity());
            double score =  damagePotential/(sonarRules.getCveScore() ==0?1:sonarRules.getCveScore());
            sonarRules.setScore(score);
        }
        double finalScore = 0;
        for(SonarRules sonarRules:uniqueSonarRules){
            double j = sonarRules.getScore();
            finalScore = finalScore+j*sonarCount.get(sonarRules.getKey());
        }
        finalScore = finalScore/sonarCount.values().stream().reduce(0, Integer::sum);
        finalScore = finalScore/300;
        return finalScore;
    }


    private Map<String, Integer> rulesToMap(List<SonarRules> sonarRules) {
        Map<String,Integer> sonarCount = new HashMap<>();
        for(SonarRules sonarRules1:sonarRules){
            if(sonarCount.keySet().stream().filter(j->j.equals(sonarRules1.getKey())).collect(Collectors.toList()).size() >0){
                sonarCount.put(sonarRules1.getKey(),sonarCount.get(sonarRules1.getKey())+1);
            }
            else {
                sonarCount.put(sonarRules1.getKey(),1);
            }
        }
        return sonarCount;
    }

    private void scoreCVE(List<SonarRules> sonarRules) {
        int p = 0;
        for (SonarRules sonarRules1:sonarRules){
            if(sonarRules1.getCVEList() !=null && !sonarRules1.getCVEList().isEmpty()){
                List<String> cveList = new ArrayList<>();
                if(sonarRules1.getCVEList().size() >5){
                     cveList.addAll(sonarRules1.getCVEList().subList(0,4));
                }
                else {
                    cveList.addAll(sonarRules1.getCVEList());
                }
                Double allScore = 0.0;
                for(String s:cveList){
                    System.out.println(p);
                    p++;
                    CVEScore cveScore = metricsCalculator.getCVE(s);
                    try {
                        Integer i = metricsCalculator.getAccessComplexityScore(cveScore.getAccessComplexity())* metricsCalculator.getAuthenticationScore(cveScore.getAuthentication());
                        allScore = allScore+i;
                    }
                    catch (Exception e){
                        LOGGER.log(Level.SEVERE,e.getMessage());
                    }


                }
                allScore = allScore/cveList.size();
                sonarRules1.setCveScore(allScore);
            }
        }
    }

    private void calculateCWEConsequence(List<SonarRules> sonarRules) {
        for (SonarRules sonarRules1:sonarRules){
            List<Consequence> cweConsequence = new ArrayList<>();

            if(sonarRules1.getEffectiveCWE()==null){
                if(sonarRules1.getTitle().get("cwe").size()==1 ) {
                    cweConsequence = Arrays.asList(getCWEConsequence(sonarRules1.getTitle().get("cwe").get(0).split("-")[1]));
                }

            }
            else {
                cweConsequence = Arrays.asList(getCWEConsequence(sonarRules1.getEffectiveCWE()));
            }
            sonarRules1.setConsequenceList(cweConsequence);
            int k = metricsCalculator.getConsequenceScore(cweConsequence);
            sonarRules1.setConsequencScore(k);
            sonarRules1.setHtmlDesc(null);
        }
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
                   LOGGER.log(Level.SEVERE,e.getMessage());
                }

            }
        }
    }

    private List<SonarRules>  processParent(Map<String,Integer> sonarCount,List<SonarRules> sonarRules){
        List<SonarRules> sonarRulesList = new ArrayList<>();
        for(String sonar1:sonarCount.keySet()){
            Optional<SonarRules> sonarRulesOptional = sonarRules.stream().filter(j->j.getKey().equals(sonar1)).findFirst();
            if(sonarRulesOptional.isPresent()){
                SonarRules sonarRules1 = sonarRulesOptional.get();
                SonarRules newSonarRules = new SonarRules();
                copyNonNullProperties(sonarRules1,newSonarRules);
                Map<String,List<String>> parentMap = new HashMap<>();
                List<String> owasp= sonarRules1.getTitle().get(OWASP);
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
                setMap(cweList,parentMap);
                String cc = getCommonParent(parentMap);
                newSonarRules.setEffectiveCWE(cc);
                sonarRulesList.add(newSonarRules);
            }

        }
        return sonarRulesList;
    }

    private void setMap(List<String> cweList,Map<String,List<String>> parentMap){
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
        return newa.size()>0?newa.get(0):null;
    }
    public List<SonarIssues> getAllIssues(){
        List<SonarIssues> issues = new ArrayList<>();
        Sonar sonar = restTemplate.getForObject("http://localhost:9000/api/issues/search", Sonar.class);
        if(sonar !=null){
            issues.addAll(sonar.getSonarIssues());

        }
        return issues;
    }
    public  List<String> getAllOwasps(String Owasp){
        try {
            Map<String,List<String>> listMap = mapper.getOWASPList();
            return listMap.get(Owasp);
        }
        catch (Exception e){
           LOGGER.log(Level.SEVERE,e.getMessage());
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
        HttpHeaders headers = new HttpHeaders();
        HttpEntity requestEntity = new HttpEntity<>(headers);
        UriComponents builder = UriComponentsBuilder.fromHttpUrl("http://localhost:5000/"+id).buildAndExpand();
        ResponseEntity<Parent> rules = restTemplate.exchange(builder.toUriString(), HttpMethod.GET,requestEntity,Parent.class);
        return rules.getBody();
    }

    public Consequence[] getCWEConsequence(String id){
        try{
            HttpHeaders headers = new HttpHeaders();
            HttpEntity requestEntity = new HttpEntity<>(headers);
            UriComponents builder = UriComponentsBuilder.fromHttpUrl("http://localhost:5000/consequence/"+id).buildAndExpand();
            ResponseEntity<Consequence[]> rules = restTemplate.exchange(builder.toUriString(), HttpMethod.GET,requestEntity,Consequence[].class);
            return rules.getBody();
        }
        catch (Exception e){
            LOGGER.log(Level.SEVERE,e.getMessage());
            return new Consequence[0];
        }

    }

    private Parent getCWEParent1003(String id){
        HttpHeaders headers = new HttpHeaders();
        HttpEntity requestEntity = new HttpEntity<>(headers);
        UriComponents builder = UriComponentsBuilder.fromHttpUrl("http://localhost:5000/cwe2/"+id).buildAndExpand();
        ResponseEntity<Parent> rules = restTemplate.exchange(builder.toUriString(), HttpMethod.GET,requestEntity,Parent.class);
        return rules.getBody();
    }

    private JSONArray getObservedCVE(String id){
        HttpHeaders headers = new HttpHeaders();
        HttpEntity requestEntity = new HttpEntity<>(headers);
        UriComponents builder = UriComponentsBuilder.fromHttpUrl("http://localhost:5000/observed/"+id).buildAndExpand();
        ResponseEntity<String> rules = restTemplate.exchange(builder.toUriString(), HttpMethod.GET,requestEntity,String.class);
        return new JSONArray(rules.getBody());
    }


    private Map<String,List<String>> scrapper(String html){
        String regex_OWASP = "(?=(OWASP[^\\\\s<]+<))";
        String regex_CWE = "(?=(CWE[^\\\\s<]+<))" ;
        String regex_CERT = "(?=(CERT[^\\\\s<]+<))";
        Map<String,List<String>> vunMap = new HashMap<>();
        List<String> OWASPList = getMatchedString(regex_OWASP,html);
        List<String> CWEList = getMatchedString(regex_CWE,html);
        List<String> CertList = getMatchedString(regex_CERT,html);
        vunMap.put(OWASP,OWASPList);
        vunMap.put("cwe",CWEList);
        vunMap.put("CertList",CertList);
        return vunMap;


    }

    private List<String> getMatchedString(String regex,String html){
        List<String> linksList = new ArrayList<>();
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(html);
        while (matcher.find()) {
            String link = matcher.group(1);
            link = link.substring(0,link.length()-1);// just the link
            linksList.add(link);
        }
        return linksList;
    }

    public static void copyNonNullProperties(Object src, Object target) {
        BeanUtils.copyProperties(src, target, getNullPropertyNames(src));
    }

    public static String[] getNullPropertyNames (Object source) {
        final BeanWrapper src = new BeanWrapperImpl(source);
        java.beans.PropertyDescriptor[] pds = src.getPropertyDescriptors();

        Set<String> emptyNames = new HashSet<String>();
        for(java.beans.PropertyDescriptor pd : pds) {
            Object srcValue = src.getPropertyValue(pd.getName());
            if (srcValue == null) emptyNames.add(pd.getName());
        }
        String[] result = new String[emptyNames.size()];
        return emptyNames.toArray(result);
    }

}
