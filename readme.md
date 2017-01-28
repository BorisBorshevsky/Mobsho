# Mobsho HW

### key generation commands
```bash
mkdir A
mkdir B
cd A
keytool -genkeypair -alias keyA -keystore storeA.jks -dname "CN=CRYPTO" -storepass passwordA -keypass passwordA -keyalg RSA
keytool -certreq -keystore storeA.jks -storepass passwordA -alias keyA -file certA.csr
keytool -gencert -keystore storeA.jks -storepass passwordA -alias keyA -infile certA.csr -outfile certA.cer
mv certA.cer ../B
cd ../B
keytool -genkeypair -alias keyB -keystore storeB.jks -dname "CN=CRYPTO" -storepass passwordB -keypass passwordB -keyalg RSA
keytool -certreq -keystore storeB.jks -storepass passwordB -alias keyB -file certB.csr
keytool -gencert -keystore storeB.jks -storepass passwordB -alias keyB -infile certB.csr -outfile certB.cer
mv certB.cer ../A
keytool -importcert -keystore storeB.jks -storepass passwordB -file certA.cer -alias keyA 
cd ../A
keytool -importcert -keystore storeA.jks -storepass passwordA -file certB.cer -alias keyB

```

## build command
`mvn install`

## encrypt command
`java -jar target/crypto-1.0-SNAPSHOT.jar encrypt data.txt encrypedData.txt A/storeA.jks keyA passwordA keyB`

## decrypt commnad
`java -jar target/crypto-1.0-SNAPSHOT.jar decrypt encrypedData.txt decryptedData.txt B/storeB.jks keyB passwordB keyA
`