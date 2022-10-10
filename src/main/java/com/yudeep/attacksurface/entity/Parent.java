package com.yudeep.attacksurface.entity;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonRootName;

import java.util.List;


public class Parent {

    @JsonProperty("attr")
    Nature attr;

    public Nature getAttr() {
        return attr;
    }

    public void setAttr(Nature attr) {
        this.attr = attr;
    }

//    {
//        "Related_Weakness": [
//        {
//            "attr": {
//            "@_Nature": "ChildOf",
//                    "@_CWE_ID": "664",
//                    "@_View_ID": "1000",
//                    "@_Ordinal": "Primary"
//        }
//        },
//        {
//            "attr": {
//            "@_Nature": "PeerOf",
//                    "@_CWE_ID": "99",
//                    "@_View_ID": "1000"
//        }
//        }
//  ]

}
