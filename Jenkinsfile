```groovy
// =====================================================================
// SecureNotes DevSecOps Pipeline
//
// Source Scan -> Docker Build -> Image Scan -> DAST
// -> ECR Push -> EC2 Deployment
//
// Authentication:
//   Jenkins EC2 IAM Role: Jenkins-main-ec2
//   Application EC2 IAM Role: ec2-ecr-roles
//
// Security findings:
//   Mark build UNSTABLE and continue.
//
// Infrastructure/build failures:
//   Can fail the pipeline.
//
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


    // =============================================================
    // PIPELINE ENVIRONMENT
    // =============================================================

    environment {

        AWS_DEFAULT_REGION = 'ap-south-1'

        DEPLOY_INSTANCE_ID = 'i-03470ba1c47c894b5'

        ECR_REPOSITORY = 'devsecops_repo'
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

                                [ -f gitleaks-report.json ] || printf '[]\\n' > gitleaks-report.json

                                exit "$rc"
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


                        // PIP-AUDIT

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


            // ---------------------------------------------------------
            // SOURCE REPORTS
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


                stage('Receive Source Code') {

                    steps {

                        deleteDir()

                        unstash 'application'

                        sh 'ls -al'
                    }
                }


                // DOCKER BUILD

                stage('Build Docker Image') {

                    steps {

                        sh 'docker build -t devsecops-demo-api:${BUILD_NUMBER} .'
                    }
                }


                // TRIVY SCAN

                stage('Trivy - Container Image Scanning') {

                    steps {

                        script {

                            runScan(
                                'Trivy JSON Scan',
                                'trivy image --format json --output trivy-report.json devsecops-demo-api:${BUILD_NUMBER}',
                                'trivy-report.json'
                            )


                            runScan(
                                'Trivy Security Scan',
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
        // Agent: built-in
        // =============================================================

        stage('Stage-3: OWASP ZAP DAST Scan') {

            agent { label 'built-in' }


            stages {


                // START APPLICATION

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

                                sleep 2

                            done


                            echo "Application failed to start."

                            docker logs devsecops-app-${BUILD_NUMBER} || true

                            exit 1
                        '''
                    }
                }


                // ZAP SCAN

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
        // STAGE 4: PUSH IMAGE TO AWS ECR
        //
        // Authentication: Jenkins EC2 IAM role
        // No static AWS credentials required.
        // =============================================================

        stage('Stage-4: AWS ECR Image Push') {

            agent { label 'built-in' }


            steps {

                sh '''

                    set -e

                    set +x

                    export AWS_DEFAULT_REGION=ap-south-1


                    echo "Checking Jenkins EC2 IAM identity..."

                    aws sts get-caller-identity


                    # Get AWS account ID

                    ACCOUNT_ID=$(aws sts get-caller-identity \
                        --query Account \
                        --output text)


                    ECR_REGISTRY="${ACCOUNT_ID}.dkr.ecr.${AWS_DEFAULT_REGION}.amazonaws.com"

                    ECR_IMAGE="${ECR_REGISTRY}/${ECR_REPOSITORY}:${BUILD_NUMBER}"


                    # Authenticate with ECR using Jenkins EC2 role

                    echo "Logging in to AWS ECR..."

                    aws ecr get-login-password \
                        --region "$AWS_DEFAULT_REGION" | \
                        docker login \
                            --username AWS \
                            --password-stdin "$ECR_REGISTRY"


                    # Tag image

                    echo "Tagging image..."

                    docker tag \
                        devsecops-demo-api:${BUILD_NUMBER} \
                        "$ECR_IMAGE"


                    # Push image

                    echo "Pushing image to ECR..."

                    docker push "$ECR_IMAGE"


                    echo "Successfully pushed image:"

                    echo "$ECR_IMAGE"
                '''
            }
        }



        // =============================================================
        // STAGE 5: DEPLOY APPLICATION TO APPLICATION EC2
        //
        // Jenkins -> AWS SSM -> Application EC2
        //
        // Application EC2 uses its own IAM role to pull from ECR.
        // =============================================================

        stage('Stage-5: Deploy to Application EC2') {

            agent { label 'built-in' }


            steps {

                script {


                    // -------------------------------------------------
                    // GET AWS ACCOUNT ID AND IMAGE URI
                    // -------------------------------------------------

                    def accountId = sh(

                        script: 'aws sts get-caller-identity --query Account --output text',

                        returnStdout: true
                    ).trim()


                    def registry = "${accountId}.dkr.ecr.${env.AWS_DEFAULT_REGION}.amazonaws.com"

                    def imageUri = "${registry}/${env.ECR_REPOSITORY}:${env.BUILD_NUMBER}"


                    // -------------------------------------------------
                    // CREATE REMOTE DEPLOYMENT SCRIPT
                    // -------------------------------------------------

                    def deployScript = '''#!/bin/bash

set -eu

AWS_REGION="ap-south-1"

ECR_REGISTRY="__ECR_REGISTRY__"

IMAGE_URI="__IMAGE_URI__"

CONTAINER_NAME="securenotes-api"

ENV_FILE="/etc/securenotes/securenotes.env"

DATA_DIR="/opt/securenotes/data"


echo "Checking Docker and AWS CLI..."

command -v docker

command -v aws


# Verify environment configuration

if [ ! -s "$ENV_FILE" ]; then

    echo "ERROR: Application environment file is missing."

    exit 1

fi


# Prepare persistent application storage

install -d -o 10001 -g 10001 -m 0750 "$DATA_DIR"


# Authenticate to ECR using the application EC2 IAM role

echo "Authenticating with ECR..."

ECR_PASSWORD=$(aws ecr get-login-password --region "$AWS_REGION")

printf '%s' "$ECR_PASSWORD" | docker login \
    --username AWS \
    --password-stdin "$ECR_REGISTRY"

unset ECR_PASSWORD


# Pull the exact image produced by this Jenkins build

echo "Pulling image: $IMAGE_URI"

docker pull "$IMAGE_URI"


# Stop previous application container

echo "Removing previous container..."

docker rm -f "$CONTAINER_NAME" || true


# Start new application container

echo "Starting SecureNotes API..."

docker run -d \
    --name "$CONTAINER_NAME" \
    --restart unless-stopped \
    -p 80:5000 \
    --env-file "$ENV_FILE" \
    --mount type=bind,source="$DATA_DIR",target=/srv/data \
    --log-opt max-size=10m \
    --log-opt max-file=3 \
    "$IMAGE_URI"


# Wait for Docker health check

echo "Waiting for application health check..."

for i in $(seq 1 60); do

    STATUS=$(docker inspect \
        --format '{{.State.Health.Status}}' \
        "$CONTAINER_NAME" 2>/dev/null || true)

    if [ "$STATUS" = "healthy" ]; then

        echo "SecureNotes API is healthy."

        exit 0

    fi

    if [ "$STATUS" = "unhealthy" ]; then

        echo "Application health check failed."

        docker logs "$CONTAINER_NAME" || true

        exit 1

    fi

    echo "Waiting for application... attempt $i"

    sleep 5

done


echo "Application health check timed out."

docker logs "$CONTAINER_NAME" || true

exit 1
'''


                    // Substitute the exact image details.

                    deployScript = deployScript
                        .replace('__ECR_REGISTRY__', registry)
                        .replace('__IMAGE_URI__', imageUri)


                    // -------------------------------------------------
                    // CREATE SSM PARAMETERS JSON
                    // -------------------------------------------------

                    writeFile(

                        file: 'ssm-parameters.json',

                        text: groovy.json.JsonOutput.toJson([
                            commands: [deployScript]
                        ])
                    )
                }


                // -----------------------------------------------------
                // SEND DEPLOYMENT COMMAND TO APPLICATION EC2
                // -----------------------------------------------------

                sh '''

                    set -e

                    set +x

                    export AWS_DEFAULT_REGION=ap-south-1


                    echo "Checking Jenkins IAM role..."

                    aws sts get-caller-identity


                    echo "Sending deployment command to application EC2..."


                    COMMAND_ID=$(aws ssm send-command \
                        --region "$AWS_DEFAULT_REGION" \
                        --instance-ids "$DEPLOY_INSTANCE_ID" \
                        --document-name "AWS-RunShellScript" \
                        --comment "Deploy SecureNotes build ${BUILD_NUMBER}" \
                        --timeout-seconds 900 \
                        --parameters file://ssm-parameters.json \
                        --query "Command.CommandId" \
                        --output text)


                    echo "SSM Command ID: $COMMAND_ID"


                    echo "Waiting for deployment..."


                    for i in $(seq 1 120); do

                        STATUS=$(aws ssm get-command-invocation \
                            --region "$AWS_DEFAULT_REGION" \
                            --command-id "$COMMAND_ID" \
                            --instance-id "$DEPLOY_INSTANCE_ID" \
                            --query Status \
                            --output text 2>/dev/null || true)


                        case "$STATUS" in


                            Success)

                                echo "Deployment completed successfully."

                                aws ssm get-command-invocation \
                                    --region "$AWS_DEFAULT_REGION" \
                                    --command-id "$COMMAND_ID" \
                                    --instance-id "$DEPLOY_INSTANCE_ID" \
                                    --query StandardOutputContent \
                                    --output text

                                exit 0

                                ;;


                            Failed|TimedOut|Cancelled|DeliveryTimedOut|ExecutionTimedOut|Undeliverable|Terminated)

                                echo "Deployment failed: $STATUS"

                                aws ssm get-command-invocation \
                                    --region "$AWS_DEFAULT_REGION" \
                                    --command-id "$COMMAND_ID" \
                                    --instance-id "$DEPLOY_INSTANCE_ID" \
                                    --query StandardErrorContent \
                                    --output text || true

                                exit 1

                                ;;

                        esac


                        sleep 5

                    done


                    echo "Deployment timed out."

                    exit 1
                '''


                sh 'rm -f ssm-parameters.json'
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
                    // RETRIEVE REPORTS
                    // -------------------------------------------------

                    ['report-tool', 'reports-source', 'reports-image', 'reports-zap'].each { name ->

                        try {

                            unstash name

                        } catch (err) {

                            echo "No '${name}' data available."
                        }
                    }


                    // -------------------------------------------------
                    // GENERATE HTML SECURITY REPORT
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
                // ARCHIVE SCAN REPORTS
                // -----------------------------------------------------

                archiveArtifacts(

                    artifacts: '*.json,*.txt,*.html',

                    allowEmptyArchive: true
                )
            }


            echo 'SecureNotes DevSecOps pipeline execution completed.'
        }
    }
}
```