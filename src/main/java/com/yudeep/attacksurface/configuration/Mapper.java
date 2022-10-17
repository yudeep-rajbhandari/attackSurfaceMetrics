package com.yudeep.attacksurface.configuration;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVRecord;
import org.springframework.stereotype.Service;

import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class Mapper {

    private static final String CWEID = "CWEID";


    public Map<String, List<String>> getOWASPList() throws IOException {
        Map<String, List<String>> owaspMap = new HashMap<>();
        String[] HEADERS = {CWEID,"OWASP","Name","Weakness Abstraction","Status","Description","Extended Description","Related Weaknesses","Weakness Ordinalities","Applicable Platforms","Background Details","Alternate Terms","Modes Of Introduction","Exploitation Factors","Likelihood of Exploit","Common Consequences","Detection Methods","Potential Mitigations","Observed Examples","Functional Areas","Affected Resources","Taxonomy Mappings","Related Attack Patterns","Notes"};

        Reader in = new FileReader("src/main/resources/csv/1344.csv");
        Iterable<CSVRecord> records = CSVFormat.DEFAULT
                .withHeader(HEADERS)
                .withFirstRecordAsHeader()
                .parse(in);
        for (CSVRecord record : records) {
            String owasp = record.get("OWASP");
            String cweId = record.get(CWEID);
            if(owaspMap.containsKey(owasp)){
                List<String> cwes = owaspMap.get(owasp);
                cwes.add(cweId);
                owaspMap.put(owasp,cwes);
            }
            else {
                List<String> cwes = new ArrayList<>();
                cwes.add(cweId);
                owaspMap.put(owasp,cwes);
            }

        }
        return owaspMap;
    }


    public Map<String, List<String>> getCVEList() throws IOException {
        Map<String, List<String>> owaspMap = new HashMap<>();
        String[] HEADERS = {CWEID,"CVE-ID"};
        Reader in = new FileReader("src/main/resources/csv/Global_Dataset.csv");
        Iterable<CSVRecord> records = CSVFormat.DEFAULT
                .withHeader(HEADERS)
                .withFirstRecordAsHeader()
                .parse(in);
        for (CSVRecord record : records) {
            String owasp = record.get(CWEID);
            String cweId = record.get("CVE-ID");
            if(owaspMap.containsKey(owasp)){
                List<String> cwes = owaspMap.get(owasp);
                cwes.add(cweId);
                owaspMap.put(owasp,cwes);
            }
            else {
                List<String> cwes = new ArrayList<>();
                cwes.add(cweId);
                owaspMap.put(owasp,cwes);
            }

        }
        return owaspMap;
    }

}
