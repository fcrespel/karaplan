#!/bin/sh

# Set variables
PROJECT_ID=$(curl -s "http://metadata.google.internal/computeMetadata/v1/project/project-id" -H "Metadata-Flavor: Google")
BUCKET_NAME="$PROJECT_ID"
SECRET_PREFIX="karaplan"

# Install Ops Agent
curl -sSf https://dl.google.com/cloudagents/add-google-cloud-ops-agent-repo.sh | bash -s -- --also-install

# Install Tomcat
apt-get update
apt-get install -y openjdk-17-jre-headless tomcat10
systemctl stop tomcat10
rm -Rf /var/lib/tomcat10/webapps/ROOT

# Download app
gsutil cp gs://$BUCKET_NAME/karaplan/karaplan.war /var/lib/tomcat10/webapps/ROOT.war

# Configure app
mkdir -p /var/lib/tomcat10/bin
cat - > /var/lib/tomcat10/bin/setenv.sh <<'EOF'
export SPRING_PROFILES_ACTIVE="gcp"
export SECRET_PREFIX="${SECRET_PREFIX}"
EOF

# Start Tomcat
systemctl restart tomcat10
