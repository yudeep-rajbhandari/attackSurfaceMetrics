package com.yudeep.attacksurface.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.List;

public class SonarRuleWrapper {

    @JsonProperty("total")
    private String total;
    @JsonProperty("rules")
    List<SonarRules> rulesList = new ArrayList<>();

    public String getTotal() {
        return total;
    }

    public void setTotal(String total) {
        this.total = total;
    }

    public List<SonarRules> getRulesList() {
        return rulesList;
    }

    public void setRulesList(List<SonarRules> rulesList) {
        this.rulesList = rulesList;
    }
}
