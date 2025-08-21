import groovy.json.JsonOutput

// Map SonarQube hotspots to issues format for SARIF conversion
def mapHotspotsToIssues(hotspots) {
    return hotspots.collect { hotspot ->
        [
            rule: hotspot.ruleKey,
            message: hotspot.message,
            filePath: hotspot.component.split(":")[1],
            startLine: hotspot.textRange.startLine,
            endLine: hotspot.textRange.endLine,
            startColumn: hotspot.textRange.startOffset,
            endColumn: hotspot.textRange.endOffset
        ]
    }
}

// Map issues directly to SARIF results format
def mapIssuesToSarif(issues) {
    return issues.collect { issue ->
        [
            ruleId: issue.rule,
            message: issue.message,
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
                            endColumn: issue.endColumn
                        ]
                    ]
                ]
            ]
        ]
    }
}

// Convert issues to SARIF JSON
def convertIssuesToSarif(issues, sonarVersion = "9.9.0") {
    def sarifData = [
        version: "2.1.0",
        runs: [
            [
                tool: [
                    driver: [
                        name: "SonarQube",
                        version: sonarVersion
                    ]
                ],
                results: mapIssuesToSarif(issues)
            ]
        ]
    ]
    println JsonOutput.prettyPrint(JsonOutput.toJson(sarifData))
    return sarifData
}
