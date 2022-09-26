package com.yudeep.attacksurface.entity;

import java.util.List;

public class Sonar {
    private Integer total;
    private List<SonarIssues> sonarIssues;

    public Integer getTotal() {
        return total;
    }

    public void setTotal(Integer total) {
        this.total = total;
    }

    public List<SonarIssues> getSonarIssues() {
        return sonarIssues;
    }

    public void setSonarIssues(List<SonarIssues> sonarIssues) {
        this.sonarIssues = sonarIssues;
    }
}
