// =====================================================================
// SecureNotes DevSecOps Pipeline
// GitHub -> Source Scans -> Docker Build -> Trivy -> OWASP ZAP
// -> ECR Push -> SSM Deployment to Application EC2
//
// AWS authentication uses the Jenkins credential aws-ecr-credentials.
// No ECR token is stored in SSM Parameter Store.
// =====================================================================

// Security findings mark the build UNSTABLE and allow later stages to run.
def runScan(String name, String cmd, String report) {
    int rc = sh(script: cmd, returnStatus: true)
    sh "ls -lh '${report}' || true"

    if (rc != 0) {
        unstable("${name} detected issues or encountered an error.")
        echo "${name}: exit code ${rc}. Continuing pipeline. Report: ${report}"
    } else {
        echo "${name} PASSED. Report: ${report}"
    }
}

pipeline {
    agent none

    options {
        timestamps()
        timeout(time: 60, unit: 'MINUTES')
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '20'))
        skipDefaultCheckout(true)
    }

    environment {
        AWS_DEFAULT_REGION = 'ap-south-1'
        DEPLOY_INSTANCE_ID = 'i-03470ba1c47c894b5'
        ECR_REPOSITORY = 'devsecops_repo'
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

                stage('Gitleaks - Secret Scanning') {
                    steps {
                        script {
                            runScan(
                                'Gitleaks',
                                '''
                                if gitleaks git \
                                    --redact \
                                    --report-format json \
                                    --report-path gitleaks-report.json .; then
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

                stage('SAST, SCA and SBOM') {
                    failFast false
                    parallel {
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
        // STAGE 2: DOCKER BUILD AND IMAGE SECURITY (built-in)
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
        // STAGE 3: OWASP ZAP DAST (built-in)
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
                        set -euo pipefail
                        set +x
                        export AWS_DEFAULT_REGION=ap-south-1

                        echo "Authenticating with the AWS credentials stored in Jenkins..."
                        ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
                        ECR_REGISTRY="${ACCOUNT_ID}.dkr.ecr.${AWS_DEFAULT_REGION}.amazonaws.com"
                        ECR_IMAGE="${ECR_REGISTRY}/${ECR_REPOSITORY}:${BUILD_NUMBER}"

                        aws ecr get-login-password --region "$AWS_DEFAULT_REGION" | \
                            docker login --username AWS --password-stdin "$ECR_REGISTRY"

                        echo "Tagging image..."
                        docker tag "devsecops-demo-api:${BUILD_NUMBER}" "$ECR_IMAGE"

                        echo "Pushing image to ECR..."
                        docker push "$ECR_IMAGE"

                        echo "Image pushed: $ECR_IMAGE"
                    '''
                }
            }
        }

        // =============================================================
        // STAGE 5: DEPLOY TO APPLICATION EC2 THROUGH SSM
        //
        // Jenkins credential aws-ecr-credentials is used to:
        //   1. Generate an ECR authorization token.
        //   2. Call SSM SendCommand and poll the deployment result.
        //
        // No Parameter Store operation is used in this stage.
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
                    sh label: 'Deploy application through SSM', script: '''#!/usr/bin/env bash
set -Eeuo pipefail
set +x
umask 077

export AWS_DEFAULT_REGION="ap-south-1"
export DEPLOY_INSTANCE_ID="i-03470ba1c47c894b5"
export ECR_REPOSITORY="devsecops_repo"

# Confirm which IAM identity is being used without printing credentials.
aws sts get-caller-identity

ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
export ECR_REGISTRY="${ACCOUNT_ID}.dkr.ecr.${AWS_DEFAULT_REGION}.amazonaws.com"
export IMAGE_URI="${ECR_REGISTRY}/${ECR_REPOSITORY}:${BUILD_NUMBER}"

# Generate a short-lived ECR password. Do not echo or trace this value.
ECR_PASSWORD="$(aws ecr get-login-password --region "$AWS_DEFAULT_REGION")"
if [[ -z "$ECR_PASSWORD" ]]; then
    echo "ERROR: Could not generate an ECR authentication token."
    exit 1
fi

# Encode in the shell, avoiding the Groovy method rejected by Jenkins Script Security.
export ECR_PASSWORD_B64="$(printf '%s' "$ECR_PASSWORD" | base64 | tr -d '\n')"
unset ECR_PASSWORD

# Python safely JSON-encodes the SSM request, including the multiline script.
python3 - <<'PYTHON'
import json
import os
from pathlib import Path

registry = os.environ["ECR_REGISTRY"]
image_uri = os.environ["IMAGE_URI"]
token_b64 = os.environ["ECR_PASSWORD_B64"]
instance_id = os.environ["DEPLOY_INSTANCE_ID"]
build_number = os.environ["BUILD_NUMBER"]

remote_script = r"""#!/usr/bin/env bash
set -Eeuo pipefail

ECR_REGISTRY="__ECR_REGISTRY__"
IMAGE_URI="__IMAGE_URI__"
ECR_PASSWORD_B64="__ECR_PASSWORD_B64__"
CONTAINER_NAME="securenotes-api"
ENV_FILE="/etc/securenotes/securenotes.env"
DATA_DIR="/opt/securenotes/data"

echo "Checking deployment requirements..."
command -v docker

if [ ! -s "$ENV_FILE" ]; then
    echo "ERROR: Application environment file is missing: $ENV_FILE"
    exit 1
fi

echo "Preparing persistent application storage..."
install -d -o 10001 -g 10001 -m 0750 "$DATA_DIR"

echo "Authenticating Docker with ECR..."
printf '%s' "$ECR_PASSWORD_B64" | base64 --decode | docker login \\
    --username AWS \\
    --password-stdin "$ECR_REGISTRY"
unset ECR_PASSWORD_B64

echo "Pulling image: $IMAGE_URI"
docker pull "$IMAGE_URI"
docker logout "$ECR_REGISTRY" >/dev/null 2>&1 || true

echo "Replacing application container..."
docker rm -f "$CONTAINER_NAME" || true

echo "Starting SecureNotes API..."
docker run -d \\
    --name "$CONTAINER_NAME" \\
    --restart unless-stopped \\
    -p 80:5000 \\
    --env-file "$ENV_FILE" \\
    --mount type=bind,source="$DATA_DIR",target=/srv/data \\
    --log-opt max-size=10m \\
    --log-opt max-file=3 \\
    "$IMAGE_URI"

echo "Waiting for Docker health check..."
for i in $(seq 1 60); do
    STATUS=$(docker inspect --format '{{.State.Health.Status}}' "$CONTAINER_NAME" 2>/dev/null || true)

    if [ "$STATUS" = "healthy" ]; then
        echo "SecureNotes API is healthy."
        exit 0
    fi

    if [ "$STATUS" = "unhealthy" ]; then
        echo "Application health check failed."
        docker logs "$CONTAINER_NAME" || true
        exit 1
    fi

    echo "Waiting for application health... attempt $i"
    sleep 5
done

echo "Application health check timed out."
docker logs "$CONTAINER_NAME" || true
exit 1
"""

remote_script = (remote_script
    .replace("__ECR_REGISTRY__", registry)
    .replace("__IMAGE_URI__", image_uri)
    .replace("__ECR_PASSWORD_B64__", token_b64))

request = {
    "DocumentName": "AWS-RunShellScript",
    "InstanceIds": [instance_id],
    "Comment": f"Deploy SecureNotes build {build_number}",
    "TimeoutSeconds": 900,
    "Parameters": {"commands": [remote_script]},
}

path = Path("ssm-deployment-request.json")
path.write_text(json.dumps(request), encoding="utf-8")
path.chmod(0o600)
PYTHON

# The request contains the temporary ECR token. Delete it on every exit path.
trap 'rm -f ssm-deployment-request.json; unset ECR_PASSWORD_B64 || true' EXIT

if [[ ! -s ssm-deployment-request.json ]]; then
    echo "ERROR: Failed to create the SSM deployment request."
    exit 1
fi

unset ECR_PASSWORD_B64

echo "Sending deployment command to application EC2..."
COMMAND_ID="$(aws ssm send-command \\
    --region "$AWS_DEFAULT_REGION" \\
    --cli-input-json file://ssm-deployment-request.json \\
    --query 'Command.CommandId' \\
    --output text)"

echo "SSM Command ID: $COMMAND_ID"
echo "Waiting for application deployment..."

for i in $(seq 1 180); do
    STATUS="$(aws ssm get-command-invocation \\
        --region "$AWS_DEFAULT_REGION" \\
        --command-id "$COMMAND_ID" \\
        --instance-id "$DEPLOY_INSTANCE_ID" \\
        --query Status \\
        --output text 2>/dev/null || true)"

    case "$STATUS" in
        Success)
            echo "Deployment completed successfully."
            aws ssm get-command-invocation \\
                --region "$AWS_DEFAULT_REGION" \\
                --command-id "$COMMAND_ID" \\
                --instance-id "$DEPLOY_INSTANCE_ID" \\
                --query StandardOutputContent \\
                --output text
            exit 0
            ;;
        Failed|TimedOut|Cancelled|DeliveryTimedOut|ExecutionTimedOut|Undeliverable|Terminated)
            echo "Deployment failed: $STATUS"
            echo "Remote error output:"
            aws ssm get-command-invocation \\
                --region "$AWS_DEFAULT_REGION" \\
                --command-id "$COMMAND_ID" \\
                --instance-id "$DEPLOY_INSTANCE_ID" \\
                --query StandardErrorContent \\
                --output text || true
            echo "Remote command output:"
            aws ssm get-command-invocation \\
                --region "$AWS_DEFAULT_REGION" \\
                --command-id "$COMMAND_ID" \\
                --instance-id "$DEPLOY_INSTANCE_ID" \\
                --query StandardOutputContent \\
                --output text || true
            exit 1
            ;;
    esac

    sleep 5
done

echo "Deployment timed out while waiting for SSM."
exit 1
'''
                }
            }
        }

    }

    // =============================================================
    // GLOBAL POST: CONSOLIDATED SECURITY REPORTS
    // =============================================================
    post {
        always {
            node('built-in') {
                deleteDir()

                script {
                    ['report-tool', 'reports-source', 'reports-image', 'reports-zap'].each { name ->
                        try {
                            unstash name
                        } catch (err) {
                            echo "No '${name}' data available."
                        }
                    }

                    if (fileExists('generate_report.py')) {
                        int reportRc = sh(
                            script: """
                                python3 generate_report.py \\
                                    --out security-report.html \\
                                    --build '${env.BUILD_NUMBER}' \\
                                    --commit '${env.GIT_SHORT ?: 'unknown'}'
                            """,
                            returnStatus: true
                        )

                        if (reportRc != 0) {
                            unstable('Security report generator returned a non-zero exit code.')
                            echo "Report generator exit code: ${reportRc}"
                        }

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
                            echo 'HTML Publisher unavailable. Reports will be available as build artifacts.'
                        }
                    } else {
                        echo 'generate_report.py not found. Skipping consolidated dashboard.'
                    }
                }

                archiveArtifacts(
                    artifacts: '*.json,*.txt,*.html',
                    allowEmptyArchive: true
                )
            }

            echo 'SecureNotes DevSecOps pipeline execution completed.'
        }
    }
}