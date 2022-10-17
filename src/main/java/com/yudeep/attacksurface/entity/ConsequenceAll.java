package com.yudeep.attacksurface.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class ConsequenceAll {
    @JsonProperty("Consequence")
    List<Consequence> consequenceList;

    public List<Consequence> getConsequenceList() {
        return consequenceList;
    }

    public void setConsequenceList(List<Consequence> consequenceList) {
        this.consequenceList = consequenceList;
    }
}
