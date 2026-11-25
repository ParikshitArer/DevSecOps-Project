
// =====================================================================
// SecureNotes DevSecOps Pipeline
//
// GitHub -> Source Scanning -> Docker Build -> Trivy
// -> OWASP ZAP -> ECR Push -> EC2 Deployment
//
// Authentication:
//   Jenkins ECR credentials: aws-ecr-credentials
//   Jenkins EC2 IAM role: Jenkins-main-ec2
//   Application EC2: i-03470ba1c47c894b5
//
// ECR authentication:
//   Jenkins generates temporary ECR token.
//   Token is stored temporarily in SSM Parameter Store SecureString.
//   Application EC2 retrieves token through SSM.
//
// Security findings:
//   Mark build UNSTABLE and continue.
//
// Infrastructure/build failures:
//   Can fail the pipeline.
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


    // =================================================================
    // PIPELINE OPTIONS
    // =================================================================

    options {

        timestamps()

        timeout(time: 60, unit: 'MINUTES')

        disableConcurrentBuilds()

        buildDiscarder(logRotator(numToKeepStr: '20'))

        skipDefaultCheckout(true)
    }


    // =================================================================
    // GLOBAL ENVIRONMENT
    // =================================================================

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

                        deleteDir()

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


                // RECEIVE APPLICATION

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


                // TRIVY

                stage('Trivy - Container Image Scanning') {

                    steps {

                        script {

                            // Full JSON report.

                            runScan(
                                'Trivy JSON Scan',
                                'trivy image --format json --output trivy-report.json devsecops-demo-api:${BUILD_NUMBER}',
                                'trivy-report.json'
                            )


                            // HIGH and CRITICAL vulnerabilities.

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

                                echo "Waiting for application... attempt $i"

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
        // STAGE 4: AWS ECR IMAGE PUSH
        //
        // Uses Jenkins credential: aws-ecr-credentials
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


                        echo "Authenticating with configured Jenkins AWS credentials..."


                        ACCOUNT_ID=$(aws sts get-caller-identity \
                            --query Account \
                            --output text)


                        ECR_REGISTRY="${ACCOUNT_ID}.dkr.ecr.${AWS_DEFAULT_REGION}.amazonaws.com"

                        ECR_IMAGE="${ECR_REGISTRY}/${ECR_REPOSITORY}:${BUILD_NUMBER}"


                        echo "ECR registry: $ECR_REGISTRY"


                        # Authenticate with ECR

                        aws ecr get-login-password \
                            --region "$AWS_DEFAULT_REGION" | \
                            docker login \
                                --username AWS \
                                --password-stdin "$ECR_REGISTRY"


                        # Tag image

                        echo "Tagging Docker image..."

                        docker tag \
                            devsecops-demo-api:${BUILD_NUMBER} \
                            "$ECR_IMAGE"


                        # Push image

                        echo "Pushing Docker image to ECR..."

                        docker push "$ECR_IMAGE"


                        echo "Successfully pushed image:"

                        echo "$ECR_IMAGE"
                    '''
                }
            }
        }



        // =============================================================
        // STAGE 5: DEPLOY APPLICATION TO APPLICATION EC2
        //
        // Jenkins Credentials:
        //   Generate temporary ECR authorization token.
        //
        // Jenkins EC2 IAM Role:
        //   Store temporary token and execute SSM commands.
        //
        // Application EC2 SSM Role:
        //   Retrieve temporary token from Parameter Store.
        // =============================================================

        stage('Stage-5: Deploy to Application EC2') {

            agent { label 'built-in' }


            steps {

                withCredentials([

                    usernamePassword(

                        credentialsId: 'aws-ecr-credentials',

                        usernameVariable: 'AWS_ACCESS_KEY_ID',

                        passwordVariable: 'AWS_SECRET_ACCESS_KEY'
                    )
                ]) {


                    script {


                        // -------------------------------------------------
                        // IMAGE DETAILS
                        // -------------------------------------------------

                        def accountId = sh(

                            script: 'aws sts get-caller-identity --query Account --output text',

                            returnStdout: true
                        ).trim()


                        def registry = "${accountId}.dkr.ecr.${env.AWS_DEFAULT_REGION}.amazonaws.com"

                        def imageUri = "${registry}/${env.ECR_REPOSITORY}:${env.BUILD_NUMBER}"

                        def parameterName = "/securenotes/deploy/ecr-password/build-${env.BUILD_NUMBER}"


                        // -------------------------------------------------
                        // REMOTE APPLICATION DEPLOYMENT SCRIPT
                        //
                        // IMPORTANT:
                        // This script does NOT call ecr get-login-password.
                        // It retrieves the token generated by Jenkins.
                        // -------------------------------------------------

                        def deployScript = '''#!/bin/bash

set -euo pipefail

AWS_REGION="ap-south-1"

ECR_REGISTRY="__ECR_REGISTRY__"

IMAGE_URI="__IMAGE_URI__"

PARAMETER_NAME="__PARAMETER_NAME__"

CONTAINER_NAME="securenotes-api"

ENV_FILE="/etc/securenotes/securenotes.env"

DATA_DIR="/opt/securenotes/data"


echo "Checking deployment requirements..."

command -v docker

command -v aws


# Check application environment file

if [ ! -s "$ENV_FILE" ]; then

    echo "ERROR: Application environment file is missing."

    exit 1

fi


# Prepare persistent application storage

echo "Preparing application storage..."

install -d -o 10001 -g 10001 -m 0750 "$DATA_DIR"


# Retrieve temporary ECR token from Parameter Store

echo "Retrieving temporary ECR authentication token..."

ECR_PASSWORD=$(aws ssm get-parameter \
    --name "$PARAMETER_NAME" \
    --with-decryption \
    --query 'Parameter.Value' \
    --output text \
    --region "$AWS_REGION")


if [ -z "$ECR_PASSWORD" ]; then

    echo "ERROR: Unable to retrieve ECR authentication token."

    exit 1

fi


# Authenticate Docker using Jenkins-generated token

echo "Logging in to ECR..."

printf '%s' "$ECR_PASSWORD" | docker login \
    --username AWS \
    --password-stdin "$ECR_REGISTRY"


unset ECR_PASSWORD


# Pull image from ECR

echo "Pulling image: $IMAGE_URI"

docker pull "$IMAGE_URI"


# Remove stored Docker registry credentials

docker logout "$ECR_REGISTRY" >/dev/null 2>&1 || true


# Remove previous application container

echo "Removing previous application container..."

docker rm -f "$CONTAINER_NAME" || true


# Start the new container

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


                        // Substitute image and parameter details.

                        deployScript = deployScript

                            .replace('__ECR_REGISTRY__', registry)

                            .replace('__IMAGE_URI__', imageUri)

                            .replace('__PARAMETER_NAME__', parameterName)


                        // Create SSM parameters JSON.

                        writeFile(

                            file: 'ssm-parameters.json',

                            text: groovy.json.JsonOutput.toJson([

                                commands: [deployScript]

                            ])
                        )
                    }



                    // =================================================
                    // GENERATE TOKEN, STORE SECURELY AND DEPLOY
                    // =================================================

                    sh '''

                        set -e

                        set +x

                        export AWS_DEFAULT_REGION=ap-south-1


                        # Unique parameter for this Jenkins build.

                        PARAMETER_NAME="/securenotes/deploy/ecr-password/build-${BUILD_NUMBER}"


                        # Temporary protected file.

                        umask 077

                        PARAMETER_FILE=$(mktemp)


                        # Cleanup runs whether deployment succeeds or fails.

                        cleanup() {

                            unset ECR_PASSWORD

                            aws ssm delete-parameter \
                                --name "$PARAMETER_NAME" \
                                --region "$AWS_DEFAULT_REGION" \
                                >/dev/null 2>&1 || true

                            rm -f "$PARAMETER_FILE"

                            rm -f ssm-parameters.json
                        }

                        trap cleanup EXIT


                        # -------------------------------------------------
                        # 1. GENERATE ECR TOKEN USING JENKINS CREDENTIALS
                        # -------------------------------------------------

                        echo "Generating temporary ECR authentication token..."


                        ECR_PASSWORD=$(aws ecr get-login-password \
                            --region "$AWS_DEFAULT_REGION")


                        if [ -z "$ECR_PASSWORD" ]; then

                            echo "ERROR: Could not generate ECR token."

                            exit 1

                        fi


                        # -------------------------------------------------
                        # 2. SWITCH TO JENKINS EC2 IAM ROLE
                        # -------------------------------------------------

                        # Remove Jenkins static credentials from this shell.
                        # Subsequent SSM API calls use Jenkins EC2 IAM role.

                        unset AWS_ACCESS_KEY_ID

                        unset AWS_SECRET_ACCESS_KEY

                        unset AWS_SESSION_TOKEN

                        unset AWS_SECURITY_TOKEN


                        echo "Checking Jenkins EC2 IAM role..."

                        aws sts get-caller-identity


                        # -------------------------------------------------
                        # 3. CREATE SECURE PARAMETER PAYLOAD
                        # -------------------------------------------------

                        export ECR_PASSWORD

                        export PARAMETER_NAME

                        export PARAMETER_FILE


                        python3 - <<'PY'
import json
import os

payload = {
    "Name": os.environ["PARAMETER_NAME"],
    "Type": "SecureString",
    "Value": os.environ["ECR_PASSWORD"],
    "Overwrite": True
}

with open(os.environ["PARAMETER_FILE"], "w") as output:
    json.dump(payload, output)
PY


                        chmod 600 "$PARAMETER_FILE"


                        # -------------------------------------------------
                        # 4. STORE TOKEN IN PARAMETER STORE
                        # -------------------------------------------------

                        echo "Storing encrypted ECR token in Parameter Store..."


                        aws ssm put-parameter \
                            --cli-input-json "file://${PARAMETER_FILE}" \
                            --region "$AWS_DEFAULT_REGION" \
                            >/dev/null


                        unset ECR_PASSWORD

                        rm -f "$PARAMETER_FILE"


                        echo "Temporary token stored successfully."


                        # -------------------------------------------------
                        # 5. SEND DEPLOYMENT COMMAND TO APPLICATION EC2
                        # -------------------------------------------------

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


                        # -------------------------------------------------
                        # 6. WAIT FOR DEPLOYMENT
                        # -------------------------------------------------

                        echo "Waiting for application deployment..."


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


                                    echo "Remote error output:"

                                    aws ssm get-command-invocation \
                                        --region "$AWS_DEFAULT_REGION" \
                                        --command-id "$COMMAND_ID" \
                                        --instance-id "$DEPLOY_INSTANCE_ID" \
                                        --query StandardErrorContent \
                                        --output text || true


                                    echo "Remote command output:"

                                    aws ssm get-command-invocation \
                                        --region "$AWS_DEFAULT_REGION" \
                                        --command-id "$COMMAND_ID" \
                                        --instance-id "$DEPLOY_INSTANCE_ID" \
                                        --query StandardOutputContent \
                                        --output text || true


                                    exit 1

                                    ;;

                            esac


                            sleep 5

                        done


                        echo "Deployment timed out."

                        exit 1
                    '''
                }
            }
        }
    }



    // =============================================================
    // GLOBAL POST: SECURITY REPORT GENERATION
    // Runs after every build, including UNSTABLE and FAILED builds.
    // =============================================================

    post {

        always {

            node('built-in') {

                deleteDir()


                script {


                    // -------------------------------------------------
                    // RETRIEVE ALL AVAILABLE REPORTS
                    // -------------------------------------------------

                    [
                        'report-tool',
                        'reports-source',
                        'reports-image',
                        'reports-zap'
                    ].each { name ->

                        try {

                            unstash name

                        } catch (err) {

                            echo "No '${name}' data available."
                        }
                    }


                    // -------------------------------------------------
                    // GENERATE CONSOLIDATED HTML REPORT
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

                            echo 'HTML Publisher unavailable. Download reports from build artifacts.'
                        }

                    } else {

                        echo 'generate_report.py not found. Skipping dashboard.'
                    }
                }


                // -----------------------------------------------------
                // ARCHIVE ALL REPORTS
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
