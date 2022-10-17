package com.yudeep.attacksurface.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class CVE {
    @JsonProperty("vulnerabilities")
    List<Vulnerability> vulnerabilityList;

    public List<Vulnerability> getVulnerabilityList() {
        return vulnerabilityList;
    }

    public void setVulnerabilityList(List<Vulnerability> vulnerabilityList) {
        this.vulnerabilityList = vulnerabilityList;
    }
}
