package com.yudeep.attacksurface.entity;

import java.util.List;

public class ResponseFinal {
    private double finalScore;

    private double unweightedScore;

    public double getUnweightedScore() {
        return unweightedScore;
    }

    public void setUnweightedScore(double unweightedScore) {
        this.unweightedScore = unweightedScore;
    }

    private List<SonarRules> allRules;

    public double getFinalScore() {
        return finalScore;
    }

    public void setFinalScore(double finalScore) {
        this.finalScore = finalScore;
    }

    public List<SonarRules> getAllRules() {
        return allRules;
    }

    public void setAllRules(List<SonarRules> allRules) {
        this.allRules = allRules;
    }
}
