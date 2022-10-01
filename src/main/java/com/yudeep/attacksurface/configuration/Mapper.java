package com.yudeep.attacksurface.configuration;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVRecord;
import org.springframework.context.annotation.Bean;
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

    private static final Map<String, String> tensNumberConversion_internal = new HashMap<String, String>()
    {
        {
            put("A01", "CWE-1345");
            put("A02", "CWE-1346");
            put("A03", "CWE-1347");
            put("A04", "CWE-1348");
            put("A05", "CWE-1349");
            put("A06", "CWE-1352");
            put("A07", "CWE-1353");
            put("A08", "CWE-1354");
            put("A09", "CWE-1355");
            put("A10", "CWE-1356");
        };
    };


    public Map<String, List<String>> getOWASPList() throws IOException {
        Map<String, List<String>> owaspMap = new HashMap<>();
        String[] HEADERS = {"CWEID","OWASP","Name","Weakness Abstraction","Status","Description","Extended Description","Related Weaknesses","Weakness Ordinalities","Applicable Platforms","Background Details","Alternate Terms","Modes Of Introduction","Exploitation Factors","Likelihood of Exploit","Common Consequences","Detection Methods","Potential Mitigations","Observed Examples","Functional Areas","Affected Resources","Taxonomy Mappings","Related Attack Patterns","Notes"};

        Reader in = new FileReader("src/main/resources/csv/1344.csv");
        Iterable<CSVRecord> records = CSVFormat.DEFAULT
                .withHeader(HEADERS)
                .withFirstRecordAsHeader()
                .parse(in);
        for (CSVRecord record : records) {
            String owasp = record.get("OWASP");
            String cweId = record.get("CWEID");
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
