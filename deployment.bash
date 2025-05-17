# Create service user
sudo useradd -r -s /bin/false pulseup

# Create directory and copy files
sudo mkdir -p /opt/pulseup-agent
sudo cp dist/pulseup-agent /opt/pulseup-agent/
sudo cp .env /opt/pulseup-agent/

# Set permissions
sudo chown -R pulseup:pulseup /opt/pulseup-agent
sudo chmod 750 /opt/pulseup-agent
sudo chmod 640 /opt/pulseup-agent/.env

# Install service
sudo cp pulseup-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable pulseup-agent
sudo systemctl start pulseup-agent