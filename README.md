# vault2go
makes the vault mystery universe simple

JBoss / EAP offers with vault.sh a script for encoding cleartext passwords in standalone.xml.
RedHat describes the process to get an encrypted password with keytool and vault.sh.

vault2go.sh automates the described process and generates a standalone.xml with encryped passwords.

Usage: 

vault2go.sh <JBOSS_HOME> <ALIAS> <PASSWORD>

vault2go.sh <JBOSS_HOME> <ALIAS> <PASSWORD> other-file-than-standalone.xml

Output:

3 files will be generated in $JBOSS_HOME/standalone/configuration:

- VAULT.dat
- VAULT.keystore
- VAULT.standalone.xml or VAULT.other-file.xml

All you have to do: 

- check encryption:    diff VAULT.standalone.xml standalone.xml
- activate encryption: cp VAULT.standalone.xml standalone.xml 
- restart JBOSS

To check encryped password:  vault2go.sh <JBOSS_HOME> <ALIAS> 
