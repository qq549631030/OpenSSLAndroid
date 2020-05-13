//
// Created by huangx on 2020/5/12.
//

#include <jni.h>
#include <string>
#include <iostream>
#include <openssl/ossl_typ.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

extern "C"
JNIEXPORT jbyteArray

JNICALL
Java_cn_hx_openssl_android_AESUtil_encrypt_1AES_1CBC_1128(JNIEnv *env, jclass thiz,
                                                          jbyteArray content_array, jbyteArray key,
                                                          jbyteArray iv) {
    jbyte *cContent = env->GetByteArrayElements(content_array, NULL);
    jbyte *cKey = env->GetByteArrayElements(key, NULL);
    jbyte *cIv = env->GetByteArrayElements(iv, NULL);

    size_t src_Len = static_cast<size_t>(env->GetArrayLength(content_array));
    int outlen = 0, cipherText_len = 0;
    unsigned char *out = (unsigned char *) malloc((src_Len / 16 + 1) * 16);
    //清空内存空间
    memset(out, 0, (src_Len / 16 + 1) * 16);

    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);

    EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, (const unsigned char *) cKey,
                       (const unsigned char *) cIv);
    EVP_EncryptUpdate(&ctx, out, &outlen, (const unsigned char *) cContent,
                      src_Len);
    cipherText_len = outlen;

    EVP_EncryptFinal_ex(&ctx, out + outlen, &outlen);
    cipherText_len += outlen;

    EVP_CIPHER_CTX_cleanup(&ctx);
    env->ReleaseByteArrayElements(content_array, cContent, 0);
    env->ReleaseByteArrayElements(key, cKey, 0);
    env->ReleaseByteArrayElements(iv, cIv, 0);

    jbyteArray cipher = env->NewByteArray(cipherText_len);
    env->SetByteArrayRegion(cipher, 0, cipherText_len, (jbyte *) out);
    free(out);
    return cipher;
}

extern "C"
JNIEXPORT jbyteArray

JNICALL
Java_cn_hx_openssl_android_AESUtil_decrypt_1AES_1CBC_1128(JNIEnv *env, jclass thiz,
                                                          jbyteArray encrypted_array,
                                                          jbyteArray key,
                                                          jbyteArray iv) {
    jbyte *cContent = env->GetByteArrayElements(encrypted_array, NULL);
    jbyte *cKey = env->GetByteArrayElements(key, NULL);
    jbyte *cIv = env->GetByteArrayElements(iv, NULL);

    size_t src_Len = static_cast<size_t>(env->GetArrayLength(encrypted_array));
    int outlen = 0, plaintext_len = 0;

    unsigned char *out = (unsigned char *) malloc(src_Len);
    memset(out, 0, src_Len);

    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    EVP_DecryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, (const unsigned char *) cKey,
                       (const unsigned char *) cIv);
    EVP_DecryptUpdate(&ctx, out, &outlen, (const unsigned char *) cContent, src_Len);
    plaintext_len = outlen;

    EVP_DecryptFinal_ex(&ctx, out + outlen, &outlen);
    plaintext_len += outlen;

    EVP_CIPHER_CTX_cleanup(&ctx);
    env->ReleaseByteArrayElements(encrypted_array, cContent, 0);
    env->ReleaseByteArrayElements(key, cKey, 0);
    env->ReleaseByteArrayElements(iv, cIv, 0);

    jbyteArray cipher = env->NewByteArray(plaintext_len);
    env->SetByteArrayRegion(cipher, 0, plaintext_len, (jbyte *) out);
    free(out);
    return cipher;
}


