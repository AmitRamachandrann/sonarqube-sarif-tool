def convertSonarToSarif(sonarData) {
    def sarifData = [
        version: "2.1.0",
        runs: [
            [
                tool: [
                    driver: [
                        name: "SonarQube",
                        version: sonarData.version
                    ]
                ],
                results: []
            ]
        ]
    ]

    sonarData.issues.each { issue ->
        sarifData.runs[0].results << [
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

    return sarifData
}