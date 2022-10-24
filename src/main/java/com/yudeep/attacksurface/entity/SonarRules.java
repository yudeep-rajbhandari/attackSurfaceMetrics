package com.yudeep.attacksurface.entity;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SonarRules {
private String key;
private String name;
    Map<String,List<String>> title = new HashMap<>();

    List<String> cveList = new ArrayList<>();
    List<Consequence> consequenceList = new ArrayList<>();
    Integer consequencScore = 1;

    Double cveScore = 1.0;

    Double score = 0.0;

    public Double getScore() {
        return score;
    }

    public void setScore(Double score) {
        this.score = score;
    }

    public Double getCveScore() {
        return cveScore;
    }

    public void setCveScore(Double cveScore) {
        this.cveScore = cveScore;
    }

    public Integer getConsequencScore() {
        return consequencScore;
    }

    public void setConsequencScore(Integer consequencScore) {
        this.consequencScore = consequencScore;
    }

    public List<Consequence> getConsequenceList() {
        return consequenceList;
    }

    public void setConsequenceList(List<Consequence> consequenceList) {
        this.consequenceList = consequenceList;
    }

    public List<String> getCVEList() {
        return cveList;
    }

    public void setCVEList(List<String> cveList) {
        this.cveList = cveList;
    }

    public String getEffectiveCWE() {
        return effectiveCWE;
    }

    public void setEffectiveCWE(String effectiveCWE) {
        this.effectiveCWE = effectiveCWE;
    }

    public String effectiveCWE;

    public Map<String,List<String>> getTitle() {
        return title;
    }

    public void setTitle(Map<String,List<String>> title) {
        this.title = title;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getHtmlDesc() {
        return htmlDesc;
    }

    public void setHtmlDesc(String htmlDesc) {
        this.htmlDesc = htmlDesc;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    private String htmlDesc;
private String severity;
}
