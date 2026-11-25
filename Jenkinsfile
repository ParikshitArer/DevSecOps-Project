
// =====================================================================
// DevSecOps pipeline:
// Source Scan -> Docker Build -> Image Scan -> DAST -> ECR Push
//
// Security findings mark the build UNSTABLE instead of FAILED.
// Infrastructure and essential build failures can still stop the pipeline.
// =====================================================================


// ---------------------------------------------------------------------
// NON-BLOCKING SECURITY SCAN FUNCTION
// ---------------------------------------------------------------------

def runScan(String name, String cmd, String report) {

    int rc = sh(script: cmd, returnStatus: true)

    sh "ls -l ${report} || true"

    if (rc != 0) {

        unstable("${name} detected issues or encountered an error.")

        echo """
        =====================================================
        WARNING: ${name}
        Exit Code: ${rc}
        Status: Issues detected / scan error
        Pipeline: Continuing
        Report: ${report}
        =====================================================
        """

    } else {

        echo "${name} PASSED."
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
        // =============================================================

        stage('Stage-1: Source Code Security') {

            agent { label 'Node-1' }


            stages {


                // -----------------------------------------------------
                // SOURCE CODE CHECKOUT
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
                // GITLEAKS
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

                                [ -f gitleaks-report.json ] || echo '[]' > gitleaks-report.json

                                exit $rc
                                ''',
                                'gitleaks-report.json'
                            )
                        }
                    }
                }


                // -----------------------------------------------------
                // PARALLEL SECURITY SCANS
                // -----------------------------------------------------

                stage('SAST, SCA and SBOM') {

                    failFast false

                    parallel {


                        // BANDIT

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


                        // SEMGREP

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


                        // PIP AUDIT

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


                        // SYFT

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
                // STASH APPLICATION
                // -----------------------------------------------------

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

                    stash name: 'reports-source',

                          includes: 'gitleaks-report.json,bandit-report.json,semgrep-report.json,dependency-report.json,sbom.json',

                          allowEmpty: true
                }
            }
        }



        // =============================================================
        // STAGE 2: DOCKER BUILD AND IMAGE SECURITY
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


                // -----------------------------------------------------
                // DOCKER BUILD
                // -----------------------------------------------------

                stage('Build Docker Image') {

                    steps {

                        sh 'docker build -t devsecops-demo-api:${BUILD_NUMBER} .'
                    }
                }


                // -----------------------------------------------------
                // TRIVY
                // -----------------------------------------------------

                stage('Trivy - Container Image Scanning') {

                    steps {

                        script {

                            // Full JSON report

                            runScan(
                                'Trivy JSON Scan',
                                'trivy image --format json --output trivy-report.json devsecops-demo-api:${BUILD_NUMBER}',
                                'trivy-report.json'
                            )


                            // HIGH and CRITICAL vulnerability check

                            runScan(
                                'Trivy Security Gate',
                                'trivy image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 --format table --output trivy-report.txt devsecops-demo-api:${BUILD_NUMBER}',
                                'trivy-report.txt'
                            )
                        }
                    }
                }
            }


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

                            echo "Waiting for application..."

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
                // ZAP SCAN
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

                        ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

                        ECR_REGISTRY="${ACCOUNT_ID}.dkr.ecr.${AWS_DEFAULT_REGION}.amazonaws.com"

                        ECR_IMAGE="${ECR_REGISTRY}/devsecops_repo:${BUILD_NUMBER}"


                        echo "Logging in to AWS ECR..."

                        aws ecr get-login-password --region "$AWS_DEFAULT_REGION" | \
                            docker login --username AWS --password-stdin "$ECR_REGISTRY"


                        echo "Tagging Docker image..."

                        docker tag devsecops-demo-api:${BUILD_NUMBER} "$ECR_IMAGE"


                        echo "Pushing image to ECR..."

                        docker push "$ECR_IMAGE"


                        echo "Successfully pushed image: $ECR_IMAGE"
                    '''
                }
            }
        }
    }



    // =============================================================
    // GLOBAL POST: SECURITY REPORT GENERATION
    // =============================================================

    post {

        always {

            node('built-in') {
