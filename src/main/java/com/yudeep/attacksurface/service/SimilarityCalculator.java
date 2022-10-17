package com.yudeep.attacksurface.service;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVRecord;
import org.springframework.stereotype.Service;
import similarity.TextSimilarity;

import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.util.HashMap;
import java.util.Map;

@Service
public class SimilarityCalculator {


    private Map<String, String> getAllCSV() {
        Map<String, String> cweMap = new HashMap<>();
        String[] HEADERS = {"CWEID","Name","Weakness Abstraction","Status","Description","Extended Description","Related Weaknesses","Weakness Ordinalities","Applicable Platforms","Background Details","Alternate Terms","Modes Of Introduction","Exploitation Factors","Likelihood of Exploit","Common Consequences","Detection Methods","Potential Mitigations","Observed Examples","Functional Areas","Affected Resources","Taxonomy Mappings","Related Attack Patterns","Notes"};

        try (Reader in = new FileReader("src/main/resources/csv/softwareCWE.csv");){

            Iterable<CSVRecord> records = CSVFormat.DEFAULT
                    .withHeader(HEADERS)
                    .withFirstRecordAsHeader()
                    .parse(in);
            for (CSVRecord record : records) {
                String cweId = record.get("CWEID");
                String name = record.get("Name");
               cweMap.put(cweId,name);

            }
        }
        catch (Exception e){
            return cweMap;
        }
       return cweMap;
    }

    public TextSimilarity calculateSimilarity(){
        Map<String, String> getAllJava = getAllCSV();
        TextSimilarity ts = new TextSimilarity();
        for (String s:getAllJava.keySet()){
            ts.addDocument(s,getAllJava.get(s));
        }
        return ts;
    }
}
