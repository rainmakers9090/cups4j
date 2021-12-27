package org.cups4j;

public class CupsSSL
{
    private String keyStorePath = "";

    private  String keyStorePass = "";

    private String keyPass = "";

    private int sslPort = 0;

    public CupsSSL(String keyStorePath, String keyStorePass , String keyPass , int sslPort) {
        super();
        this.keyStorePath = keyStorePath;
        this.keyStorePass = keyStorePass;
        this.keyPass = keyPass;
        this.sslPort = sslPort;
    }

    public String getKeyStorePath() {
        return keyStorePath;
    }

    public String getKeyStorePass() {
        return keyStorePass;
    }

    public String getKeyPass() {
        return keyPass;
    }

    public int getSslPort() {
        return sslPort;
    }

}
