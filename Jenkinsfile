// =====================================================================
// DevSecOps Pipeline
// Source Scan -> Docker Build -> Image Scan -> DAST -> AWS ECR Push
//
// Security findings:
//   - Mark build UNSTABLE
//   - Display warnings in Jenkins console
//   - Continue remaining stages
//
// Infrastructure/build failures:
//   - Can still fail the pipeline
//
// Reports:
//   - Individual JSON / TXT / HTML reports
//   - Consolidated HTML Security Report
// =====================================================================


// =====================================================================
// NON-BLOCKING SECURITY SCAN FUNCTION
// =====================================================================

def runScan(String name, String cmd, String report) {

    int rc = sh(script: cmd, returnStatus: true)

    sh "ls -lh '${report}' || true"

    if (rc != 0) {

        unstable("${name} detected issues or encountered an error.")

        echo """
        =====================================================
        SECURITY WARNING: ${name}
        Exit Code : ${rc}
        Status    : ISSUES DETECTED / SCAN ERROR
        Action    : Continuing pipeline
        Report    : ${report}
        =====================================================
        """

    } else {

        echo """
        =====================================================
        ${name} PASSED
        Report: ${report}
        =====================================================
        """
    }
}


pipeline {

    agent none


    options {

        timestamps()

        timeout(time: 60, unit: 'MINUTES')

        disableConcurrentBuilds()

        buildDiscarder(logRotator(numToKeepStr: '20'))
    }


    stages {


        // =============================================================
        // STAGE 1: SOURCE CODE SECURITY
        // Agent: Node-1
        // =============================================================

        stage('Stage-1: Source Code Security') {

            agent { label 'Node-1' }


            stages {


                // -----------------------------------------------------
                // 1. SOURCE CODE CHECKOUT
                // -----------------------------------------------------

                stage('Pull Source Code') {

                    steps {

                        git branch: 'main',
                            url: 'https://github.com/ParikshitArer/DevSecOps-Project.git'

                        sh 'ls -al'

                        script {

                            env.GIT_SHORT = sh(
                                script: 'git rev-parse --short HEAD',
                                returnStdout: true
                            ).trim()
                        }

                        stash name: 'report-tool',
                              includes: 'generate_report.py',
                              allowEmpty: true
                    }
                }


                // -----------------------------------------------------
                // 2. GITLEAKS - SECRET SCANNING
                // -----------------------------------------------------

                stage('Gitleaks - Secret Scanning') {

                    steps {

                        script {

                            runScan(
                                'Gitleaks',
                                '''
                                if gitleaks git \
                                    --redact \
                                    --report-format json \
                                    --report-path gitleaks-report.json .
                                then
                                    rc=0
                                else
                                    rc=$?
                                fi

                                [ -f gitleaks-report.json ] || printf '[]\\n' > gitleaks-report.json

                                exit "$rc"
                                ''',
                                'gitleaks-report.json'
                            )
                        }
                    }
                }


                // -----------------------------------------------------
                // 3. PARALLEL SECURITY SCANS
                // -----------------------------------------------------

                stage('SAST, SCA and SBOM') {

                    failFast false

                    parallel {


                        // =============================================
                        // BANDIT - PYTHON SAST
                        // =============================================

                        stage('Bandit - Python SAST') {

                            steps {

                                script {

                                    runScan(
                                        'Bandit',
                                        '~/bandit-env/bin/bandit -r app/ -lll -f json -o bandit-report.json',
                                        'bandit-report.json'
                                    )
                                }
                            }
                        }


                        // =============================================
                        // SEMGREP - SAST
                        // =============================================

                        stage('Semgrep - SAST') {

                            steps {

                                script {

                                    runScan(
                                        'Semgrep',
                                        'semgrep scan --config auto --severity ERROR --error --json --output semgrep-report.json app/',
                                        'semgrep-report.json'
                                    )
                                }
                            }
                        }


                        // =============================================
                        // PIP-AUDIT - DEPENDENCY SCANNING
                        // =============================================

                        stage('pip-audit - Dependency Scanning') {

                            steps {

                                script {

                                    runScan(
                                        'pip-audit',
                                        '~/sca-env/bin/pip-audit -r requirements.txt --format json --progress-spinner off --output dependency-report.json',
                                        'dependency-report.json'
                                    )
                                }
                            }
                        }


                        // =============================================
                        // SYFT - SBOM GENERATION
                        // =============================================

                        stage('Syft - SBOM Generation') {

                            steps {

                                script {

                                    runScan(
                                        'Syft',
                                        'syft dir:. -o cyclonedx-json=sbom.json',
                                        'sbom.json'
                                    )
                                }
                            }
                        }
                    }
                }


                // -----------------------------------------------------
                // 4. STASH APPLICATION
                // -----------------------------------------------------

                stage('Stashing Application') {

                    steps {

                        stash name: 'application',

                              includes: '**/*',

                              excludes: '.git/**,gitleaks-report.json,bandit-report.json,semgrep-report.json,dependency-report.json,sbom.json'
                    }
                }
            }


            // ---------------------------------------------------------
            // STAGE 1 POST ACTIONS
            // ---------------------------------------------------------

            post {

                always {

                    stash name: 'reports-source',

                          includes: 'gitleaks-report.json,bandit-report.json,semgrep-report.json,dependency-report.json,sbom.json',

                          allowEmpty: true
                }
            }
        }



        // =============================================================
        // STAGE 2: DOCKER BUILD AND IMAGE SECURITY
        // Agent: built-in
        // =============================================================

        stage('Stage-2: Docker Build and Image Security') {

            agent { label 'built-in' }


            stages {


                // -----------------------------------------------------
                // RECEIVE SOURCE CODE
                // -----------------------------------------------------

                stage('Receive Source Code') {

                    steps {

                        deleteDir()

                        unstash 'application'

                        sh 'ls -al'
                    }
                }


                // -----------------------------------------------------
                // BUILD DOCKER IMAGE
                // -----------------------------------------------------

                stage('Build Docker Image') {

                    steps {

                        sh 'docker build -t devsecops-demo-api:${BUILD_NUMBER} .'
                    }
                }


                // -----------------------------------------------------
                // TRIVY CONTAINER IMAGE SCANNING
                // -----------------------------------------------------

                stage('Trivy - Container Image Scanning') {

                    steps {

                        script {

                            // Generate complete JSON report.

                            runScan(
                                'Trivy JSON Scan',
                                'trivy image --format json --output trivy-report.json devsecops-demo-api:${BUILD_NUMBER}',
                                'trivy-report.json'
                            )


                            // HIGH and CRITICAL vulnerability check.
                            // Unfixed vulnerabilities are excluded.

                            runScan(
                                'Trivy Security Scan',
                                'trivy image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 --format table --output trivy-report.txt devsecops-demo-api:${BUILD_NUMBER}',
                                'trivy-report.txt'
                            )
                        }
                    }
                }
            }


            // ---------------------------------------------------------
            // STAGE 2 POST ACTIONS
            // ---------------------------------------------------------

            post {

                always {

                    stash name: 'reports-image',

                          includes: 'trivy-report.json,trivy-report.txt',

                          allowEmpty: true
                }
            }
        }



        // =============================================================
        // STAGE 3: OWASP ZAP DAST
        // Agent: built-in
        // =============================================================

        stage('Stage-3: OWASP ZAP DAST Scan') {

            agent { label 'built-in' }


            stages {


                // -----------------------------------------------------
                // START APPLICATION
                // -----------------------------------------------------

                stage('Start Application') {

                    steps {

                        sh '''
                            set -e

                            docker rm -f devsecops-app-${BUILD_NUMBER} || true

                            docker run -d \
                                --name devsecops-app-${BUILD_NUMBER} \
                                -p 127.0.0.1:5000:5000 \
                                devsecops-demo-api:${BUILD_NUMBER}


                            echo "Waiting for application to become ready..."


                            for i in $(seq 1 15); do

                                if curl -fsS http://127.0.0.1:5000/ > /dev/null; then

                                    echo "Application is ready."

                                    exit 0
                                fi

                                echo "Waiting for application... attempt $i"

                                sleep 2
                            done


                            echo "Application failed to start."

                            docker logs devsecops-app-${BUILD_NUMBER} || true

                            exit 1
                        '''
                    }
                }


                // -----------------------------------------------------
                // OWASP ZAP SECURITY SCAN
                // -----------------------------------------------------

                stage('OWASP ZAP Security Scan') {

                    steps {

                        script {

                            runScan(
                                'OWASP ZAP',
                                '''
                                /snap/bin/zaproxy \
                                    -cmd \
                                    -port 8090 \
                                    -quickurl http://127.0.0.1:5000 \
                                    -quickout "$WORKSPACE/zap-report.html"
                                ''',
                                'zap-report.html'
                            )
                        }
                    }
                }
            }


            // ---------------------------------------------------------
            // STAGE 3 POST ACTIONS
            // ---------------------------------------------------------

            post {

                always {

                    sh 'docker rm -f devsecops-app-${BUILD_NUMBER} || true'

                    stash name: 'reports-zap',

                          includes: 'zap-report.html,zap-report.json',

                          allowEmpty: true
                }
            }
        }



        // =============================================================
        // STAGE 4: AWS ECR IMAGE PUSH
        // Agent: built-in
        //
        // Security findings do not block this stage.
        // Infrastructure and AWS errors can still fail it.
        // =============================================================

        stage('Stage-4: AWS ECR Image Push') {

            agent { label 'built-in' }


            steps {

                withCredentials([

                    usernamePassword(

                        credentialsId: 'aws-ecr-credentials',

                        usernameVariable: 'AWS_ACCESS_KEY_ID',

                        passwordVariable: 'AWS_SECRET_ACCESS_KEY'
                    )
                ]) {

                    sh '''

                        set -e

                        set +x

                        export AWS_DEFAULT_REGION=ap-south-1


                        # Check AWS CLI availability

                        if command -v aws >/dev/null 2>&1; then

                            AWS_CLI="$(command -v aws)"

                        elif [ -x /usr/local/bin/aws ]; then

                            AWS_CLI="/usr/local/bin/aws"

                        else

                            echo "ERROR: AWS CLI is not installed on this Jenkins node."

                            exit 1
                        fi


                        echo "AWS CLI found: $AWS_CLI"


                        # Get AWS account ID

                        ACCOUNT_ID=$("$AWS_CLI" sts get-caller-identity \
                            --query Account \
                            --output text)


                        ECR_REGISTRY="${ACCOUNT_ID}.dkr.ecr.${AWS_DEFAULT_REGION}.amazonaws.com"

                        ECR_IMAGE="${ECR_REGISTRY}/devsecops_repo:${BUILD_NUMBER}"


                        # Authenticate with AWS ECR

                        echo "Logging in to AWS ECR..."


                        "$AWS_CLI" ecr get-login-password \
                            --region "$AWS_DEFAULT_REGION" | \
                            docker login \
                                --username AWS \
                                --password-stdin "$ECR_REGISTRY"


                        # Tag Docker image

                        echo "Tagging Docker image..."


                        docker tag \
                            devsecops-demo-api:${BUILD_NUMBER} \
                            "$ECR_IMAGE"


                        # Push image to ECR

                        echo "Pushing Docker image to AWS ECR..."


                        docker push "$ECR_IMAGE"


                        echo "Successfully pushed image:"
                        echo "$ECR_IMAGE"

                    '''
                }
            }
        }
    }



    // =============================================================
    // GLOBAL POST: SECURITY REPORT GENERATION
    // Runs after every build, including unstable and failed builds.
    // =============================================================

    post {

        always {

            node('built-in') {

                deleteDir()


                script {

                    // -------------------------------------------------
                    // RETRIEVE AVAILABLE REPORTS
                    // -------------------------------------------------

                    ['report-tool', 'reports-source', 'reports-image', 'reports-zap'].each { name ->

                        try {

                            unstash name

                        } catch (err) {

                            echo "No '${name}' data available."
                        }
                    }


                    // -------------------------------------------------
                    // GENERATE CONSOLIDATED SECURITY REPORT
                    // -------------------------------------------------

                    if (fileExists('generate_report.py')) {

                        int reportRc = sh(

                            script: """
                                python3 generate_report.py \
                                    --out security-report.html \
                                    --build '${env.BUILD_NUMBER}' \
                                    --commit '${env.GIT_SHORT ?: 'unknown'}'
                            """,

                            returnStatus: true
                        )


                        if (reportRc != 0) {

                            unstable('Security report generator returned a non-zero exit code.')

                            echo "WARNING: Report generator returned exit code ${reportRc}."
                        }


                        // -------------------------------------------------
                        // PUBLISH HTML REPORT
                        // -------------------------------------------------

                        try {

                            publishHTML(target: [

                                reportDir: '.',

                                reportFiles: 'security-report.html,zap-report.html',

                                reportName: 'Security Report',

                                keepAll: true,

                                alwaysLinkToLastBuild: true,

                                allowMissing: true
                            ])

                        } catch (Throwable t) {

                            echo 'HTML Publisher unavailable. Download security-report.html from build artifacts.'
                        }

                    } else {

                        echo 'generate_report.py not found. Skipping dashboard.'
                    }
                }


                // -----------------------------------------------------
                // ARCHIVE REPORTS
                // -----------------------------------------------------

                archiveArtifacts(

                    artifacts: '*.json,*.txt,*.html',

                    allowEmptyArchive: true
                )
            }


            echo 'DevSecOps pipeline execution completed.'
        }
    }
}