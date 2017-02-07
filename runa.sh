#-----------------------------------------------------------------
# *.java --> *.dex
#-----------------------------------------------------------------
#reset JAVA_HOME
source ~/.bashrc_eclipse
cd src/main/android/dex
javac -source 1.6 -target 1.6 -d . ../../dfirewall.java
dx --dex --output=dfirewall.dex dfirewall/dfirewall.class
rm -r dfirewall

#-----------------------------------------------------------------
# *.dex --> *.apk
#-----------------------------------------------------------------
cd ..
apktool b dex

#-----------------------------------------------------------------
# *.dex signature
#-----------------------------------------------------------------
#keytool -genkey -v -keystore sig/kt1 -alias ktas1 -keyalg RSA -keysize 2048 -validity 365
