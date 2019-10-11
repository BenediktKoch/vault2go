#!/bin/bash
# @author:  benedikt.koch@mt-ag.com
# @created: 2019-09-25
# @desc:    replace password in standalone.xml with JBoss vault.sh 
# @param:   <JBOSS-HOMEDIR> <alias> <password-to-replace>
# -----------------------------------------------------------

# --- handle output for script logging
#
do_log()
{

    me=`hostname`
    if [ "$OUTFILE" != "" ]
    then
        echo "`date '+%Y-%m-%d %H:%M:%S'` $me :$@ " | tee -a $OUTFILE
    else
        echo "`date '+%Y-%m-%d %H:%M:%S'` $me :$@ "
    fi
}

# -----------------------------------------------------------
# show error message and usage
usage()
{
	do_log ""
	do_log "$1"
	do_log ""
	do_log "usage: `basename $0` <JBOSS-HOME> <alias-for-password> <password-to-hide> [ jboss-config.xml ]"
	do_log ""
	exit 1
}

# -----------------------------------------------------------
#
create_keystore()
{
	if [ -f $KEYSTORE ]
        then
		# do_log "WARN: $KEYSTORE already exists"
                return 0
        fi

	$KEYTOOL -genseckey -alias vault -storetype jceks -keyalg AES -keysize 128 -storepass vault22 -keypass vault22 -validity 7300 -keystore $KEYSTORE >/dev/null 2>&1
	rc=$?
	
	if [ $rc != 0 ]
	then
		do_log "FATAL: `basename $KEYTOOL` returns $rc"
		exit 1
	fi

	return 0
}

# -----------------------------------------------------------
#
create_vault()
{
	# check if pw entry already exists
	#
	$VAULT $COPTS > /dev/null 2>&1
	retcode=$?
	
	if [ $retcode == 0 ]
	then
		# pw already exists so delete entry
		#
		$VAULT $DOPTS > /dev/null 2>&1
		retcode=$?

    		if [ $retcode != 0 ]
    		then
			do_log "FATAL: delete existing pw with vault.sh returns $retcode"
			exit 1 
		fi	
	fi
	
	# create pw entry
	#
	$VAULT $SOPTS > /dev/null 2>&1
	retcode=$?

	if [ $retcode != 0 ]
    	then
		do_log "FATAL: insert pw with vault.sh returns $retcode"
		exit 1
	fi

	return 0
}

create_config()
{
	# copy standalone.xml to standalone.vault
	#
	if [ ! -f $JBOSS_NEWCONFIG ]
	then 
		cp $JBOSS_CONFIG $JBOSS_NEWCONFIG
		retcode=$?
		if [ $retcode -ne 0 ]
		then
        		do_log "FATAL: copy $JBOSS_CONFIG to $JBOSS_NEWCONFIG returns $retcode"
        		exit 1
		fi
	fi

	# replace cleartext pw in standalone.vault
	#
	pw_exist=`grep -c "<password>$PASSWORD</password>" $JBOSS_NEWCONFIG`
	if [ $pw_exist -gt 0 ]
	then
		sed -bi 's/<password>'$PASSWORD'<\/password>/<password>${'$ENCPW'}<\/password>/g' $JBOSS_NEWCONFIG
	else
		# perhaps already crypted?
		pw_crypted=`grep -c "$ENCPW" $JBOSS_NEWCONFIG`
		if [ $pw_crypted -eq 0 ]
		then
			do_log "WARN: no <password>$PASSWORD</password> in $JBOSS_NEWCONFIG"
		fi
	fi

	# insert vault options into standalone.vault
	#
	vault_exist=`grep -c "<vault>" $JBOSS_NEWCONFIG`
	if [ $vault_exist -eq 0 ]
	then
		cat << EOF > $TMPFILE
	<vault>
	  <vault-option name="KEYSTORE_URL" value="$KEYSTORE"/>
	  <vault-option name="KEYSTORE_PASSWORD" value="MASK-5dOaAVafCSd"/>
	  <vault-option name="KEYSTORE_ALIAS" value="Vault"/>
	  <vault-option name="SALT" value="1234abcd"/>
	  <vault-option name="ITERATION_COUNT" value="120"/>
	  <vault-option name="ENC_FILE_DIR" value="$VDIR/"/>
	</vault>
EOF
		sed -bi '/<\/extensions>/ r '$TMPFILE'' $JBOSS_NEWCONFIG
	fi
	
	return 0
}

# -----------------------------------------------------------
# generate java stuff
#
java_stuff()
{
        pushd /tmp >/dev/null 2>&1

        cat << EOF > getVault.java

import java.util.HashMap;
import java.util.Map;

import org.jboss.security.vault.SecurityVault;
import org.jboss.security.vault.SecurityVaultException;
import org.jboss.security.vault.SecurityVaultFactory;
import org.jboss.security.vault.SecurityVaultUtil;
import org.picketbox.plugins.vault.PicketBoxSecurityVault;

public class getVault
{
        public static void main(final String[] args) throws SecurityVaultException
        {
                final SecurityVault vault = SecurityVaultFactory.get();

                if (!vault.isInitialized())
                {
                        final Map<String, Object> optionsInitVault = new HashMap<String, Object>();
                        optionsInitVault.put(PicketBoxSecurityVault.KEYSTORE_URL, "${KEYSTORE_URL}");
                        optionsInitVault.put(PicketBoxSecurityVault.KEYSTORE_PASSWORD, "${KEYSTORE_PASSWORD}");
                        optionsInitVault.put(PicketBoxSecurityVault.KEYSTORE_ALIAS, "${KEYSTORE_ALIAS}");
                        optionsInitVault.put(PicketBoxSecurityVault.KEYSTORE_TYPE, "${KEYSTORE_TYPE}");
                        optionsInitVault.put(PicketBoxSecurityVault.SALT, "${SALT}");
                        optionsInitVault.put(PicketBoxSecurityVault.ITERATION_COUNT, "${ITERATION_COUNT}");
                        optionsInitVault.put(PicketBoxSecurityVault.ENC_FILE_DIR, "${ENC_FILE_DIR}");
                        vault.init(optionsInitVault);
                }

                final String pw = "${ENCPW}";

                if (!SecurityVaultUtil.isVaultFormat(pw))
                {
                        System.out.println("FATAL: " + pw + " is no vault format");
                }
                else
                {
                        System.out.println(SecurityVaultUtil.getValueAsString(pw));
                }
        }
}

EOF

        # compile and call
        #
        $JAVAC getVault.java
        RES=`$JAVA getVault 2>/dev/null`

        do_log ""
        do_log "ENCRYPTION is $ENCPW"
        if [ "$RES"x == "x" ]
        then
                RES="no match!!"
        fi
        do_log "DECRYPTION is $RES"
        do_log ""

        # cleanup
        #
        rm getVault.java getVault.cl*
        popd >/dev/null 2>&1

        return 0
}

# #####################################################################################
# MAIN
#

# -----------------------------------------------------------
# check params
#
if [ $# -lt 2 ]
then
	usage "missing params"
fi

# ----------------------------------------------------
# define some VARS
# 
JBOSS_HOME=$1
ALIAS=$2

PASSWORD=""
if [ $# -gt 2 ]
then
	PASSWORD=$3
fi

JBCFG=standalone.xml
if [ $# -eq 4 ]
then
	JBCFG=`basename $4`		
fi

ENCPW="VAULT::vb::$ALIAS::1"
VDIR=$JBOSS_HOME/standalone/configuration
JBOSS_CONFIG=$JBOSS_HOME/standalone/configuration/$JBCFG
JBOSS_NEWCONFIG=$JBOSS_HOME/standalone/configuration/VAULT.`basename $JBOSS_CONFIG`
TMPFILE=/tmp/vault.tmp
VAULT=$JBOSS_HOME/bin/vault.sh
JBOSS_MODULES=$JBOSS_HOME/modules/system/layers/base/org
KEYSTORE=$VDIR/VAULT.keystore
KEYSTORE_URL=$KEYSTORE
KEYSTORE_PASSWORD="MASK-5dOaAVafCSd"
KEYSTORE_ALIAS="VAULT"
KEYSTORE_TYPE="jceks"
SALT="1234abcd"
ITERATION_COUNT="120"
ENC_FILE_DIR="$JBOSS_HOME/standalone/configuration/"


# common vault opts for set check delete
COMOPTS="--keystore $KEYSTORE --keystore-password vault22 --alias Vault --vault-block vb --attribute $ALIAS --enc-dir $VDIR/ --iteration $ITERATION_COUNT --salt $SALT"
SOPTS="$COMOPTS --sec-attr $PASSWORD"
COPTS="$COMOPTS --check-sec-attr"
DOPTS="$COMOPTS --remove-sec-attr"

# java stuff 
#

JARPICKETBOX=`ls $JBOSS_MODULES/picketbox/main/picketbox-?.?.?.*-redhat-1.jar`
JARLOGGING=`ls $JBOSS_MODULES/jboss/logging/main/jboss-logging-?.?.?.*-redhat-?.jar`
export CLASSPATH=.:$JARPICKETBOX:$JARLOGGING

# check dirs
#
for dir in $JBOSS_HOME $VDIR $JBOSS_MODULES
do
	if [ ! -d $dir ]
	then
		do_log "FATAL: $dir not found error" 
		exit 1
	fi
done

# check files
#
for file in $JBOSS_CONFIG $VAULT $JARPICKETBOX $JARLOGGING
do
        if [ ! -f $file ]
        then
                do_log "FATAL: $file not found error"
                exit 1
        fi
done

# check procs
#
for proc in java javac keytool
do
	if [ ! `command -v $proc` ]
	then
		do_log "FATAL: $proc not found error. Add JAVA_HOME/bin to PATH..."
		exit 1
	fi
done
KEYTOOL=`which keytool`
JAVA=`which java`
JAVAC=`which javac`

# ----------------------------------------------------
# run encryption 
#
if [ $# -gt 2 ]
then 
	create_keystore
	create_vault
	create_config

	do_log ""
	do_log "DECRYPTION is $PASSWORD"
	do_log "ENCRYPTION is $ENCPW"
	do_log ""
else
	java_stuff	
fi
