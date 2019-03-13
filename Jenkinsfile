pipeline {
  agent { label 'docker' }
  parameters {
    string(name: 'mvn_env_opts', defaultValue: '-Xms64m -Xmx256m', description: 'Maven environment options')
    string(name: 'mvn_build_opts', defaultValue: '-Dfrontend-build -Ddocker-build', description: 'Maven build options')
    string(name: 'mvn_goals', defaultValue: 'clean verify', description: 'Maven build goals')
  }
  environment { 
    MAVEN_OPTS = "${params.mvn_env_opts}"
  }
  stages {
    stage('Build webapp') {
      steps {
        sh "./mvnw ${params.mvn_build_opts} ${params.mvn_goals} -DskipTests"
      }
    }
    stage('Run tests') {
      steps {
        sh "./mvnw ${params.mvn_build_opts} test"
      }
      post {
        always {
          junit 'target/surefire-reports/**/*.xml'
        }
      }
    }
    stage('Build image') {
      steps {
        sh "./mvnw ${params.mvn_build_opts} dockerfile:build"
      }
    }
    stage('Push image') {
      steps {
        sh "./mvnw ${params.mvn_build_opts} dockerfile:push"
      }
    }
  }
  post {
    always {
      archiveArtifacts 'target/*.war'
    }
  }
}