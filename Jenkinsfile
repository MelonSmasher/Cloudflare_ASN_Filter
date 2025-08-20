pipeline {
  agent { label 'docker' }
  environment {
    PYTHONUNBUFFERED = '1'
    // Shared config for scripts (can be overridden per-job)
    ASN_CSV = 'asn.csv'
    RULE_TEMPLATE = 'rule-template.wf'
    RULES_DIR = 'rules'
    MAX_RULE_CHARS = '4096'
    DRY_RUN = 'false'
  }
  options {
    timestamps()
    preserveStashes(buildCount: 5)
  }
  stages {
    stage('Checkout') {
      steps {
        checkout scm
      }
    }

    stage('Prepare CSV') {
      agent {
        docker {
          image 'python:3.11-alpine'
          reuseNode true
        }
      }
      steps {
        sh label: 'Copy example CSV to working CSV', script: '''
          set -eu
          cp -f asn_db.csv asn.csv
          cp -f rule-template.example.wf rule-template.wf
        '''
        stash name: 'inputs', includes: 'rule-template.wf, asn.csv'
      }
    }

    stage('Validate CSV') {
      agent {
        docker {
          image 'python:3.11-alpine'
          reuseNode true
        }
      }
      steps {
        unstash 'inputs'
        sh 'python3 scripts/validate_asn_csv.py'
      }
    }

    stage('Generate Rules') {
      agent {
        docker {
          image 'python:3.11-alpine'
          reuseNode true
        }
      }
      steps {
        unstash 'inputs'
        sh 'python3 scripts/generate_rules.py'
        stash name: 'rules', includes: 'rules/**'
      }
    }

    stage('Preflight Env') {
      agent {
        docker {
          image 'python:3.11-alpine'
          reuseNode true
        }
      }
      steps {
        withCredentials([string(credentialsId: params.CLOUDFLARE_API_TOKEN, variable: 'CLOUDFLARE_API_TOKEN')]) {
          sh label: 'Ensure required Cloudflare env vars are present', script: '''
            set -eu
            # Use :+x to avoid printing actual values in Jenkins shell trace
            [ -n "${CLOUDFLARE_API_TOKEN:+x}" ] || { echo "CLOUDFLARE_API_TOKEN not set" >&2; exit 1; }
            [ -n "${CLOUDFLARE_ZONE_ID:+x}" ] || { echo "CLOUDFLARE_ZONE_ID not set" >&2; exit 1; }
          '''
        }
      }
    }

    stage('Sync to Cloudflare') {
      agent {
        docker {
          image 'python:3.11-alpine'
          reuseNode true
        }
      }
      steps {
        unstash 'rules'
        withCredentials([string(credentialsId: params.CLOUDFLARE_API_TOKEN, variable: 'CLOUDFLARE_API_TOKEN')]) {
          sh 'python3 scripts/sync_rules.py'
        }
      }
    }
  }
  post {
    always {
      archiveArtifacts artifacts: 'rules/*.wf', onlyIfSuccessful: false, allowEmptyArchive: true
    }
  }
}
