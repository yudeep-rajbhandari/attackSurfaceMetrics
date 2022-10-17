package com.yudeep.attacksurface.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;


public class ParentWrapper {



    List<Nature> Related_Weakness;

    @JsonProperty("Related_Weakness")
    public List<Nature> getParent() {
        return Related_Weakness;
    }

    public void setParent(List<Nature> parent) {
        this.Related_Weakness = parent;
    }
}
