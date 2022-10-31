package com.yudeep.attacksurface.controller;

import com.yudeep.attacksurface.entity.CVEScore;
import com.yudeep.attacksurface.entity.Consequence;
import com.yudeep.attacksurface.entity.ResponseFinal;
import com.yudeep.attacksurface.entity.SonarRules;
import com.yudeep.attacksurface.service.ApiService;
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

    @Autowired
    private ApiService apiService;

    @GetMapping("/getAllIssues")
    public ResponseFinal processScore(@RequestParam String projectKey){
        return    sonarService.calculate(projectKey);
    }

    @GetMapping("/getOWASP")
    public List<String> process(@RequestParam String owasp){
        return sonarService.getAllOwasps(owasp);
    }
    @GetMapping("/consequence")
    public Integer consequence(@RequestParam String owasp){

        Consequence[] owaspList=   apiService.getCWEConsequence(owasp);
        List<Consequence> consequenceList = new ArrayList<>();
        consequenceList.addAll(Arrays.asList(owaspList));
        return metricsCalculator.getConsequenceScore(consequenceList);

    }

    @GetMapping("/cve")
    public CVEScore cve(@RequestParam String owasp){
        return metricsCalculator.getCVE(owasp);
    }
}
