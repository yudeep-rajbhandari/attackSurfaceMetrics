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

    private static final String DESCRPTION = "DESCRIPTION";

    private static final String CVEID = "CVE-ID";


    public Map<String, List<String>> getOWASPList() throws IOException {
        Map<String, List<String>> owaspMap = new HashMap<>();
        String[] headers = {CWEID,"OWASP","Name","Weakness Abstraction","Status","Description","Extended Description","Related Weaknesses","Weakness Ordinalities","Applicable Platforms","Background Details","Alternate Terms","Modes Of Introduction","Exploitation Factors","Likelihood of Exploit","Common Consequences","Detection Methods","Potential Mitigations","Observed Examples","Functional Areas","Affected Resources","Taxonomy Mappings","Related Attack Patterns","Notes"};

        try (Reader in = new FileReader("src/main/resources/csv/1344.csv");){
            Iterable<CSVRecord> records = CSVFormat.DEFAULT
                    .withHeader(headers)
                    .withFirstRecordAsHeader()
                    .parse(in);
            for (CSVRecord csvRecord : records) {
                String owasp = csvRecord.get("OWASP");
                String cweId = csvRecord.get(CWEID);
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
        }
        return owaspMap;
    }


    public Map<String, List<String>> getCVEList() throws IOException {
        Map<String, List<String>> owaspMap = new HashMap<>();
        String[] headers = {CWEID,CVEID,DESCRPTION};
        try( Reader in = new FileReader("src/main/resources/csv/Global_Dataset.csv");){
            Iterable<CSVRecord> records = CSVFormat.DEFAULT
                    .withHeader(headers)
                    .withFirstRecordAsHeader()
                    .parse(in);
            for (CSVRecord csvRecord : records) {
                String owasp = csvRecord.get(CWEID);
                String cweId = csvRecord.get(CVEID);
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
        }
        return owaspMap;
    }
    public Map<String, String> getCVEDesc() throws IOException {
        Map<String, String> owaspMap = new HashMap<>();
        String[] headers = {DESCRPTION,CVEID};
        try( Reader in = new FileReader("src/main/resources/csv/Global_Dataset.csv");){
            Iterable<CSVRecord> records = CSVFormat.DEFAULT
                    .withHeader(headers)
                    .withFirstRecordAsHeader()
                    .parse(in);
            for (CSVRecord csvrecord : records) {

                String cweId = csvrecord.get(CVEID);
                String owasp = csvrecord.get(DESCRPTION);
                owaspMap.put(cweId,owasp);

            }
        }
        return owaspMap;
    }

}
