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
            impacts: [ "severity" : hotspot.vulnerabilityProbability.toUpperCase() ]
        ]
    }
}


// Map issues directly to SARIF results format
def mapIssuesToSarif(issues) {
    // check the len of issues array before collecting
    def issuesArray = issues.issues
    if (!issuesArray || issuesArray.size() == 0) {
        return []
    }
    return issuesArray.collect { issue ->
        [
            ruleId: issue.rule,
            level : issue.impacts.severity,
            message:[
                text: issue.message
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
                            endColumn: issue.endColumn
                            // snippet: [
                            //     text: 
                            // ]
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
        '$schema': "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
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
    //println JsonOutput.prettyPrint(JsonOutput.toJson(sarifData));
    return sarifData
}

// use this function
// Combine both issues and hotspots into a single SARIF file
def getSarifOutput(issuesJson, hotspotsJson) {
    def jsonSlurper = new JsonSlurper()
    def issuesData = jsonSlurper.parseText(issuesJson)
    def hotspotsData = jsonSlurper.parseText(hotspotsJson)

    def issuesSarif = mapIssuesToSarif(issuesData)
    def hotspotsSarif = mapIssuesToSarif(mapHotspotsToIssues(hotspotsData))

    // Combine both lists
    def combinedResults = issuesSarif + hotspotsSarif

    def sarifData = [
        version: "2.1.0",
        runs: [
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
    ]
    return JsonOutput.toJson(sarifData)
}



// def jsonString = '''
// {
//   "paging": {
//     "pageIndex": 1,
//     "pageSize": 500,
//     "total": 3
//   },
//   "hotspots": [
//     {
//       "key": "c6070d77-1ccf-4872-a427-ed424c2128fe",
//       "component": "sarif_test_41:Dockerfile",
//       "project": "sarif_test_41",
//       "securityCategory": "auth",
//       "vulnerabilityProbability": "HIGH",
//       "status": "TO_REVIEW",
//       "line": 7,
//       "message": "Make sure that using ARG to handle a secret is safe here.",
//       "author": "aramachandran@cloudbees.com",
//       "creationDate": "2025-07-30T08:59:24+0000",
//       "updateDate": "2025-08-21T03:15:14+0000",
//       "textRange": {
//         "startLine": 7,
//         "endLine": 7,
//         "startOffset": 4,
//         "endOffset": 9
//       },
//       "flows": [],
//       "ruleKey": "docker:S6472",
//       "messageFormattings": []
//     },
//     {
//       "key": "744f9f06-a784-4dae-83d5-14088a9d1cb8",
//       "component": "sarif_test_41:main.go",
//       "project": "sarif_test_41",
//       "securityCategory": "auth",
//       "vulnerabilityProbability": "HIGH",
//       "status": "TO_REVIEW",
//       "line": 18,
//       "message": "\"password\" detected here, make sure this is not a hard-coded credential.",
//       "author": "aramachandran@cloudbees.com",
//       "creationDate": "2025-07-30T08:59:24+0000",
//       "updateDate": "2025-08-21T03:15:14+0000",
//       "textRange": {
//         "startLine": 18,
//         "endLine": 18,
//         "startOffset": 6,
//         "endOffset": 14
//       },
//       "flows": [],
//       "ruleKey": "go:S2068",
//       "messageFormattings": []
//     },
//     {
//       "key": "1eb58ac5-db37-462f-ab57-5a616ea9716a",
//       "component": "sarif_test_41:Dockerfile",
//       "project": "sarif_test_41",
//       "securityCategory": "permission",
//       "vulnerabilityProbability": "MEDIUM",
//       "status": "TO_REVIEW",
//       "line": 14,
//       "message": "Copying recursively might inadvertently add sensitive data to the container. Make sure it is safe here.",
//       "author": "aramachandran@cloudbees.com",
//       "creationDate": "2025-07-30T08:59:24+0000",
//       "updateDate": "2025-08-21T03:15:14+0000",
//       "textRange": {
//         "startLine": 14,
//         "endLine": 14,
//         "startOffset": 5,
//         "endOffset": 6
//       },
//       "flows": [],
//       "ruleKey": "docker:S6470",
//       "messageFormattings": []
//     }
//   ],
//   "components": [
//     {
//       "key": "sarif_test_41:main.go",
//       "qualifier": "FIL",
//       "name": "main.go",
//       "longName": "main.go",
//       "path": "main.go"
//     },
//     {
//       "key": "sarif_test_41",
//       "qualifier": "TRK",
//       "name": "sarif_test_41",
//       "longName": "sarif_test_41"
//     },
//     {
//       "key": "sarif_test_41:Dockerfile",
//       "qualifier": "FIL",
//       "name": "Dockerfile",
//       "longName": "Dockerfile",
//       "path": "Dockerfile"
//     }
//   ]
// }
// '''

// test data
// def hotspots = [
//     paging: [
//         pageIndex: 1,
//         pageSize: 500,
//         total: 3
//     ],
//     hotspots: [
//         [
//             key: 'c6070d77-1ccf-4872-a427-ed424c2128fe',
//             component: 'sarif_test_41:Dockerfile',
//             project: 'sarif_test_41',
//             securityCategory: 'auth',
//             vulnerabilityProbability: 'HIGH',
//             status: 'TO_REVIEW',
//             line: 7,
//             message: 'Make sure that using ARG to handle a secret is safe here.',
//             author: 'aramachandran@cloudbees.com',
//             creationDate: '2025-07-30T08:59:24+0000',
//             updateDate: '2025-08-21T03:15:14+0000',
//             textRange: [
//                 startLine: 7,
//                 endLine: 7,
//                 startOffset: 4,
//                 endOffset: 9
//             ],
//             flows: [],
//             ruleKey: 'docker:S6472',
//             messageFormattings: []
//         ],
//         [
//             key: '744f9f06-a784-4dae-83d5-14088a9d1cb8',
//             component: 'sarif_test_41:main.go',
//             project: 'sarif_test_41',
//             securityCategory: 'auth',
//             vulnerabilityProbability: 'HIGH',
//             status: 'TO_REVIEW',
//             line: 18,
//             message: '"password" detected here, make sure this is not a hard-coded credential.',
//             author: 'aramachandran@cloudbees.com',
//             creationDate: '2025-07-30T08:59:24+0000',
//             updateDate: '2025-08-21T03:15:14+0000',
//             textRange: [
//                 startLine: 18,
//                 endLine: 18,
//                 startOffset: 6,
//                 endOffset: 14
//             ],
//             flows: [],
//             ruleKey: 'go:S2068',
//             messageFormattings: []
//         ],
//         [
//             key: '1eb58ac5-db37-462f-ab57-5a616ea9716a',
//             component: 'sarif_test_41:Dockerfile',
//             project: 'sarif_test_41',
//             securityCategory: 'permission',
//             vulnerabilityProbability: 'MEDIUM',
//             status: 'TO_REVIEW',
//             line: 14,
//             message: 'Copying recursively might inadvertently add sensitive data to the container. Make sure it is safe here.',
//             author: 'aramachandran@cloudbees.com',
//             creationDate: '2025-07-30T08:59:24+0000',
//             updateDate: '2025-08-21T03:15:14+0000',
//             textRange: [
//                 startLine: 14,
//                 endLine: 14,
//                 startOffset: 5,
//                 endOffset: 6
//             ],
//             flows: [],
//             ruleKey: 'docker:S6470',
//             messageFormattings: []
//         ]
//     ],
//     components: [
//         [
//             key: 'sarif_test_41:main.go',
//             qualifier: 'FIL',
//             name: 'main.go',
//             longName: 'main.go',
//             path: 'main.go'
//         ],
//         [
//             key: 'sarif_test_41',
//             qualifier: 'TRK',
//             name: 'sarif_test_41',
//             longName: 'sarif_test_41'
//         ],
//         [
//             key: 'sarif_test_41:Dockerfile',
//             qualifier: 'FIL',
//             name: 'Dockerfile',
//             longName: 'Dockerfile',
//             path: 'Dockerfile'
//         ]
//     ]
// ]

// def escapeBackslashes(String input) {
//     return input.replaceAll('""', '"')
// }
// def processedJsonString = escapeBackslashes(jsonString)
// println(processedJsonString)
// println(jsonString)



