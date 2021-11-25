#!/usr/bin/env bash
mkdir -p /home/ubuntu/install


echo "
{
    \"DaemonAuthenticationType\":     \"password\",
    \"DaemonAuthenticationPassword\": \"Password1#\",
    \"TlsBootstrapType\":             \"server-path\",
    \"TlsBootstrapHostname\":         \"${hostname}\",
    \"TlsBootstrapCert\":             \"/home/ubuntu/install/server.crt\",
    \"TlsBootstrapKey\":              \"/home/ubuntu/install/server.key\",
    \"BypassPreflightChecks\":        true,
    \"ImportSettingsFrom\":           \"/home/ubuntu/install/settings.json\",
    \"LicenseFileLocation\":          \"/home/ubuntu/install/license.rli\"
}" > /home/ubuntu/install/replicated.conf
echo "${cert_pem}" > /home/ubuntu/install/server.crt
echo "${key_pem}" > /home/ubuntu/install/server.key
IPADDR=$(hostname -I | awk '{print $1}')
echo "#!/usr/bin/env bash
chmod 600 /home/ubuntu/install/server.key
cd /home/ubuntu/install
aws s3 cp s3://aakulov-aws6-tfe . --recursive
curl -# -o /home/ubuntu/install/install.sh https://install.terraform.io/ptfe/stable
chmod +x install.sh
sudo rm -rf /usr/share/keyrings/docker-archive-keyring.gpg
cp /home/ubuntu/install/replicated.conf /etc/replicated.conf
cp /home/ubuntu/install/replicated.conf /root/replicated.conf
chown -R ubuntu: /home/ubuntu/install
yes | sudo /usr/bin/bash /home/ubuntu/install/install.sh no-proxy private-address=$IPADDR public-address=$IPADDR
exit 0
" > /home/ubuntu/install/install_tfe.sh

chmod +x /home/ubuntu/install/install_tfe.sh

sh /home/ubuntu/install/install_tfe.sh &> /home/ubuntu/install/install_tfe.log
