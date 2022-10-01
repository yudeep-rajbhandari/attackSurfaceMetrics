package com.yudeep.attacksurface.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class Sonar {
    @JsonProperty("total")
    private Integer total;
    @JsonProperty("issues")
    private List<SonarIssues> issues;

    public Integer getTotal() {
        return total;
    }

    public void setTotal(Integer total) {
        this.total = total;
    }

    public List<SonarIssues> getSonarIssues() {
        return issues;
    }

    public void setSonarIssues(List<SonarIssues> sonarIssues) {
        this.issues = sonarIssues;
    }
}
