package cn.hx.openssl.android;

public class AESUtil {

    static {
        try {
            System.loadLibrary("openssl-android");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * AES加密字节数组(CBC_128)
     *
     * @param contentArray 待加密码数据
     * @param key          加密密钥
     * @param iv           偏移向量
     * @return 加密后数据
     * @throws Exception 异常
     */
    public static native byte[] encrypt_AES_CBC_128(byte[] contentArray, byte[] key, byte[] iv) throws Exception;

    /**
     * AES解密字节数组(CBC_128)
     *
     * @param encryptedArray 待加解码数据
     * @param key            解密密钥
     * @param iv             偏移向量
     * @return 解密后数据
     * @throws Exception 异常
     */
    public static native byte[] decrypt_AES_CBC_128(byte[] encryptedArray, byte[] key, byte[] iv) throws Exception;

}
