#!/bin/sh

# Set variables
PROJECT_ID=$(curl -s "http://metadata.google.internal/computeMetadata/v1/project/project-id" -H "Metadata-Flavor: Google")
BUCKET_NAME=$PROJECT_ID

# Install Tomcat
apt-get update
apt-get install -y tomcat8
systemctl stop tomcat8
rm -Rf /var/lib/tomcat8/webapps/ROOT

# Download app
gsutil cp gs://$BUCKET_NAME/karaplan/karaplan-1.0.0-SNAPSHOT.war /var/lib/tomcat8/webapps/ROOT.war

# Configure app
mkdir -p /var/lib/tomcat8/bin
cat - > /var/lib/tomcat8/bin/setenv.sh <<EOF
export SPRING_DATASOURCE_USERNAME="karaplan"
export SPRING_DATASOURCE_PASSWORD="toComplete"
export SPRING_DATASOURCE_URL="jdbc:mysql://toComplete/karaplan?useSSL=false"
export SPRING_JPA_DATABASEPLATFORM="org.hibernate.dialect.MySQL5InnoDBDialect"
export SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GOOGLE_CLIENTID="toComplete"
export SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GOOGLE_CLIENTSECRET="toComplete"
export SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_FACEBOOK_CLIENTID="toComplete"
export SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_FACEBOOK_CLIENTSECRET="toComplete"
export SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GITHUB_CLIENTID="toComplete"
export SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GITHUB_CLIENTSECRET="toComplete"
EOF

# Start Tomcat
systemctl restart tomcat8
