package com.yudeep.attacksurface.controller;

import com.yudeep.attacksurface.entity.CVEScore;
import com.yudeep.attacksurface.entity.Consequence;
import com.yudeep.attacksurface.entity.SonarRules;
import com.yudeep.attacksurface.service.MetricsCalculator;
import com.yudeep.attacksurface.service.SonarService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@RestController
public class SuperController {

    @Autowired
    private SonarService sonarService;

    @Autowired
    private MetricsCalculator metricsCalculator;

    @GetMapping("/getAllIssues")
    public List<SonarRules> process(){

        List<SonarRules>  sonarIssues=   sonarService.calculate();
        return sonarIssues;
    }

    @GetMapping("/getOWASP")
    public List<String> process(@RequestParam String owasp){

        List<String>  owaspList=   sonarService.getAllOwasps(owasp);
        return owaspList;
    }
    @GetMapping("/consequence")
    public Integer consequence(@RequestParam String owasp){

        Consequence[] owaspList=   sonarService.getCWEConsequence(owasp);
        List<Consequence> consequenceList = new ArrayList<>();
        consequenceList.addAll(Arrays.asList(owaspList));
        int j = metricsCalculator.getConsequenceScore(consequenceList);
        return j;
    }

    @GetMapping("/cve")
    public CVEScore cve(@RequestParam String owasp){

        CVEScore j = metricsCalculator.getCVE(owasp);
        return j;
    }
}
