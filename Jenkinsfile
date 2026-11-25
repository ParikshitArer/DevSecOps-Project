// =====================================================================
// DevSecOps pipeline: scan -> build -> image scan -> DAST -> ECR push
// plus one readable HTML "Security Report" for every build.
//
// Repo root must contain: Jenkinsfile, generate_report.py, Dockerfile,
//                         app/, requirements.txt
// Jenkins needs: HTML Publisher plugin; python3 on the built-in node.
// =====================================================================

// Runs a command, then fails the stage if it returned non-zero.
// Reports are JSON for the dashboard, so they are not printed to the console.
def runScan(String name, String cmd, String report) {
    int rc = sh(script: cmd, returnStatus: true)
    sh "ls -l ${report} || true"
    if (rc != 0) {
        error "${name} FAILED (exit code ${rc}). Open the Security Report for details."
    }
    echo "${name} PASSED."
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
        // STAGE 1: SOURCE CODE SECURITY (Node-1)
        // =============================================================
        stage('Stage-1: Source Code Security') {
            agent { label 'Node-1' }

            stages {

                stage('Pull Source Code') {
                    steps {
                        git branch: 'main',
                            url: 'https://github.com/ParikshitArer/DevSecOps-Project.git'
                        sh 'ls -al'
                        script {
                            env.GIT_SHORT = sh(script: 'git rev-parse --short HEAD', returnStdout: true).trim()
                        }
                        // The report generator is needed later on another node
                        stash name: 'report-tool', includes: 'generate_report.py', allowEmpty: true
                    }
                }

                stage('Gitleaks - Secret Scanning') {
                    steps {
                        script {
                            // Some Gitleaks versions write no file when nothing is found,
                            // so create an empty report to show the scan ran and was clean.
                           runScan('Gitleaks', '''
    if gitleaks git --redact --report-format json --report-path gitleaks-report.json .; then
        rc=0
    else
        rc=$?
    fi

    [ -f gitleaks-report.json ] || echo '[]' > gitleaks-report.json
    exit $rc
''', 'gitleaks-report.json')
                        }
                    }
                }

                // Independent checks run in parallel so every report is produced
                stage('SAST, SCA and SBOM') {
                    failFast false
                    parallel {

                        stage('Bandit - Python SAST') {
                            steps {
                                script {
                                    runScan('Bandit',
                                            '~/bandit-env/bin/bandit -r app/ -lll -f json -o bandit-report.json',
                                            'bandit-report.json')
                                }
                            }
                        }

                        stage('Semgrep - SAST') {
                            steps {
                                script {
                                    // --error is required, otherwise Semgrep exits 0 even with findings
                                    runScan('Semgrep',
                                            'semgrep scan --config auto --severity ERROR --error --json --output semgrep-report.json app/',
                                            'semgrep-report.json')
                                }
                            }
                        }

                        stage('pip-audit - Dependency Scanning') {
                            steps {
                                script {
                                    runScan('pip-audit',
                                            '~/sca-env/bin/pip-audit -r requirements.txt --format json --progress-spinner off --output dependency-report.json',
                                            'dependency-report.json')
                                }
                            }
                        }

                        stage('Syft - SBOM Generation') {
                            steps {
                                sh 'syft dir:. -o cyclonedx-json=sbom.json'
                            }
                        }
                    }
                }

                stage('Stashing Application') {
                    steps {
                        stash name: 'application',
                              includes: '**/*',
                              excludes: '.git/**,gitleaks-report.json,bandit-report.json,semgrep-report.json,dependency-report.json,sbom.json'
                    }
                }
            }

            post {
                always {
                    // Runs even when a scan failed, so the dashboard always gets data
                    stash name: 'reports-source',
                          includes: 'gitleaks-report.json,bandit-report.json,semgrep-report.json,dependency-report.json,sbom.json',
                          allowEmpty: true
                }
            }
        }

        // =============================================================
        // STAGE 2: DOCKER BUILD AND IMAGE SCANNING (built-in node)
        // =============================================================
        stage('Stage-2: Docker Build and Image Security') {
            agent { label 'built-in' }

            stages {

                stage('Receive Source Code') {
                    steps {
                        deleteDir()
                        unstash 'application'
                        sh 'ls -al'
                    }
                }

                stage('Build Docker Image') {
                    steps {
                        sh 'docker build -t devsecops-demo-api:${BUILD_NUMBER} .'
                    }
                }

                stage('Trivy - Container Image Scanning') {
                    steps {
                        script {
                            // 1) full JSON report for the dashboard (never fails the build)
                            sh 'trivy image --format json --output trivy-report.json devsecops-demo-api:${BUILD_NUMBER}'
                            // 2) the gate: only fixable HIGH/CRITICAL issues block the build
                            runScan('Trivy',
                                    'trivy image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 --format table --output trivy-report.txt devsecops-demo-api:${BUILD_NUMBER}',
                                    'trivy-report.txt')
                        }
                    }
                }
            }

            post {
                always {
                    stash name: 'reports-image', includes: 'trivy-report.json,trivy-report.txt', allowEmpty: true
                }
            }
        }

        // =============================================================
        // STAGE 3: OWASP ZAP DAST SCAN (built-in node)
        // =============================================================
        stage('Stage-3: OWASP ZAP DAST Scan') {
            agent { label 'built-in' }

            stages {

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

                stage('OWASP ZAP Security Scan') {
                    steps {
                        // HTML report. If your ZAP version supports a .json extension
                        // for -quickout, switch to zap-report.json so the dashboard
                        // counts ZAP findings too.
                        sh '''
                            set -e
                            /snap/bin/zaproxy \
                                -cmd \
                                -port 8090 \
                                -quickurl http://127.0.0.1:5000 \
                                -quickout "$WORKSPACE/zap-report.html"
                        '''
                    }
                }
            }

            post {
                always {
                    sh 'docker rm -f devsecops-app-${BUILD_NUMBER} || true'
                    stash name: 'reports-zap', includes: 'zap-report.html,zap-report.json', allowEmpty: true
                }
            }
        }

        // =============================================================
        // STAGE 4: AWS ECR IMAGE PUSH (only reached if every scan passed)
        // =============================================================
        stage('Stage-4: AWS ECR Image Push') {
            agent { label 'built-in' }

            steps {
                // Better long term: attach an IAM role to this machine and delete these keys.
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

                        # Look up the account ID at runtime instead of hardcoding it
                        ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
                        ECR_REGISTRY="${ACCOUNT_ID}.dkr.ecr.${AWS_DEFAULT_REGION}.amazonaws.com"
                        ECR_IMAGE="${ECR_REGISTRY}/devsecops_repo:${BUILD_NUMBER}"

                        echo "Logging in to AWS ECR..."
                        aws ecr get-login-password --region "$AWS_DEFAULT_REGION" | \
                            docker login --username AWS --password-stdin "$ECR_REGISTRY"

                        echo "Tagging and pushing image..."
                        docker tag devsecops-demo-api:${BUILD_NUMBER} "$ECR_IMAGE"
                        docker push "$ECR_IMAGE"

                        echo "Pushed image: devsecops_repo:${BUILD_NUMBER}"
                    '''
                }
            }
        }
    }

    // =================================================================
    // GLOBAL POST: build and publish the Security Report
    // Runs after every build, including failed ones.
    // =================================================================
    post {
        always {
            node('built-in') {
                deleteDir()
                script {
                    ['report-tool', 'reports-source', 'reports-image', 'reports-zap'].each { name ->
                        try {
                            unstash name
                        } catch (err) {
                            echo "No '${name}' data (that stage did not run)."
                        }
                    }

                    if (fileExists('generate_report.py')) {
                        sh "python3 generate_report.py --out security-report.html --build '${env.BUILD_NUMBER}' --commit '${env.GIT_SHORT ?: 'unknown'}'"

                        archiveArtifacts artifacts: '*.json,*.txt,*.html', allowEmptyArchive: true

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
                            echo 'HTML Publisher is not available. Download security-report.html from the build artifacts.'
                        }
                    } else {
                        echo 'generate_report.py not found, skipping dashboard.'
                    }
                }

                archiveArtifacts artifacts: '*.json,*.txt,*.html', allowEmptyArchive: true
            }
            echo 'DevSecOps pipeline execution completed.'
        }
    }
}
