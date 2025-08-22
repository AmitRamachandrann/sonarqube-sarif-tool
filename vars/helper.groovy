import groovy.json.JsonOutput
import groovy.json.JsonSlurper


// Map SonarQube hotspots to issues format for SARIF conversion
def mapHotspotsToIssues(hotspots) {
    // check the len of issues array before collecting
    
    def hotspotArray = hotspots.hotspots
    if (!hotspotArray || hotspotArray.size() == 0) {
        return []
    }
    return hotspotArray.collect { hotspot ->
        [
            rule: hotspot.ruleKey,
            message: hotspot.message,
            filePath: hotspot.component.split(":")[1],
            startLine: hotspot.textRange.startLine,
            endLine: hotspot.textRange.endLine,
            startColumn: hotspot.textRange.startOffset,
            endColumn: hotspot.textRange.endOffset,
            impacts: [ "severity" : hotspot.vulnerabilityProbability.toUpperCase() ],
            type: "hotspot"
        ]
    }
}


// Map issues directly to SARIF results format
def mapIssuesToSarif(issues) {
    // check the len of issues array before collecting
    def issuesArray
    if (issues instanceof List) {
        // If issues is already a list (from hotspots), use it directly
        issuesArray = issues
    } else {
        // Otherwise, get issues.issues
        issuesArray = issues.issues
    }
    if (!issuesArray || issuesArray.size() == 0) {
        return []
    }
    return issuesArray.collect { issue ->
        def snippetText = ""
        try {
            snippetText = getVulnerableCodeSnippet(issue.filePath, issue.startLine, issue.endLine)
        } catch (Exception e) {
            snippetText = ""
        }
        [
            ruleId: issue.rule,
            level : issue.impacts.severity,
            message:[
                text: issue.message + issue.type
            ],
            fingerprints: issue.hash ? [ "0" : issue.hash ] : null,
            locations: [
                [
                    physicalLocation: [
                        artifactLocation: [
                            uri: issue.filePath
                        ],
                        region: [
                            startLine: issue.startLine,
                            startColumn: issue.startColumn,
                            endLine: issue.endLine,
                            endColumn: issue.endColumn,
                            snippet: [
                                text: snippetText
                            ]
                        ]
                    ]
                ]
            ]
        ]
    }
}

// Create a function to get the vulnerable code snippet using the physical uri and the start line and end lines
def getVulnerableCodeSnippet(uri, startLine, endLine) {
    def fileContent = new File(uri).text
    def lines = fileContent.split("\n")
    return lines[startLine - 1..endLine - 1].join("\n")
}

// Combine both issues and hotspots into a single SARIF file
def getSarifOutput(issuesJson, hotspotsJson) {
    def jsonSlurper = new JsonSlurper()
    def issuesData = jsonSlurper.parseText(issuesJson)
    def hotspotsData = jsonSlurper.parseText(hotspotsJson)

    def issuesSarif = mapIssuesToSarif(issuesData)
    def hotspotsSarif = mapIssuesToSarif(mapHotspotsToIssues(hotspotsData))

    // Combine both lists
    def combinedResults = issuesSarif + hotspotsSarif

    def sarifData = new LinkedHashMap()
    sarifData['schema'] = 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json'
    sarifData['version'] = "2.1.0"
    sarifData['runs'] = [
        [
            tool: [
                driver: [
                    name: "SonarQube",
                    version: "9.9.0"
                ]
            ],
            results: combinedResults
        ]
    ]
    return JsonOutput.toJson(sarifData)
}