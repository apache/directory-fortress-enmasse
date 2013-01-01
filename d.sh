#!/bin/sh
export JAVA_HOME=/opt/jdk1.7.0_10
export ANT_HOME=./apache-ant
export M2_HOME=/usr/share/maven2
mvn deploy -DperformRelease=true -Dgpg.passphrase=$1
