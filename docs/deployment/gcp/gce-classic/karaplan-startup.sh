#!/bin/sh

# Set variables
PROJECT_ID=$(curl -s "http://metadata.google.internal/computeMetadata/v1/project/project-id" -H "Metadata-Flavor: Google")
BUCKET_NAME=$PROJECT_ID

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
export SPRING_PROFILES_ACTIVE='gcp'
export SPRING_DATASOURCE_USERNAME='${db_username}'
export SPRING_DATASOURCE_PASSWORD='${db_password}'
export SPRING_DATASOURCE_URL='jdbc:mysql:///${db_name}?useSSL=false&socketFactory=com.google.cloud.sql.mysql.SocketFactory&cloudSqlInstance=${db_instance}'
export SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GOOGLE_CLIENTID='${google_oauth_clientid}'
export SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GOOGLE_CLIENTSECRET='${google_oauth_clientsecret}'
export SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_FACEBOOK_CLIENTID='${facebook_oauth_clientid}'
export SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_FACEBOOK_CLIENTSECRET='${facebook_oauth_clientsecret}'
export SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GITHUB_CLIENTID='${github_oauth_clientid}'
export SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GITHUB_CLIENTSECRET='${github_oauth_clientsecret}'
EOF

# Start Tomcat
systemctl restart tomcat10
