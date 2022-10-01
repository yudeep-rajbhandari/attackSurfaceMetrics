package com.yudeep.attacksurface.controller;

import com.yudeep.attacksurface.entity.SonarIssues;
import com.yudeep.attacksurface.entity.SonarRules;
import com.yudeep.attacksurface.service.SonarService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
public class SuperController {

    @Autowired
    private SonarService sonarService;

    @GetMapping("/getAllIssues")
    private List<SonarRules> process(){

        List<SonarRules>  sonarIssues=   sonarService.calculate();
        return sonarIssues;
    }

    @GetMapping("/getOWASP")
    private List<String> process(@RequestParam String owasp){

        List<String>  owaspList=   sonarService.getAllOwasps(owasp);
        return owaspList;
    }
}
