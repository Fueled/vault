package com.fueled.vault

import android.annotation.TargetApi
import android.content.Context
import android.os.Build
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyGenParameterSpec
import android.util.Log
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.math.BigInteger
import java.security.*
import java.security.KeyStore.getDefaultType
import java.security.KeyStore.getInstance
import java.security.cert.CertificateException
import java.security.spec.AlgorithmParameterSpec
import java.util.*
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.security.auth.x500.X500Principal

/**
 * API to create, save and get keys
 */
class Vault : ErrorHandler {

    val VERSION = Build.VERSION.SDK_INT

    private var keystoreName = DEFAULT_KEYSTORE_NAME
    private var keystorePassword = DEFAULT_KEYSTORE_PASSWORD
    private val keystoreFile: File

    private val context: Context

    /**
     * Creates a store with default name and password. Name is "keystore" and password is application id

     * @param context used to get local files dir of application
     */
    constructor(context: Context) {
        this.context = context
        keystoreFile = File(this.context.filesDir, keystoreName)
    }

    /**
     * Creates a store with provided name and password.

     * @param context used to get local files dir of application
     */
    constructor(context: Context, name: String, password: CharArray) {
        this.context = context
        keystoreName = name
        keystorePassword = password
        keystoreFile = File(this.context.filesDir, keystoreName)
    }

    /**
     * Create and saves RSA 1024 Private key with given alias and password. Use generateAsymmetricKey(@NonNull
     * KeyProperties keyProps) to customize key properties
     *
     *
     * Saves key to KeyStore. Uses keystore with default type located in application cache on device if API < 18.
     * Uses AndroidKeyStore if API is >= 18.

     * @return KeyPair or null if any error occurs
     */
    fun generateAsymmetricKey(alias: String, password: CharArray): KeyPair? {
        val start = Calendar.getInstance()
        val end = Calendar.getInstance()
        end.add(Calendar.YEAR, 20)

        val keyProps = KeyProperties.Builder()
                .setAlias(alias)
                .setPassword(password)
                .setKeySize(1024)
                .setKeyType(Options.ALGORITHM_RSA)
                .setSerialNumber(BigInteger.ONE)
                .setSubject(X500Principal("CN=$alias CA Certificate"))
                .setStartDate(start.time)
                .setEndDate(end.time)
                .setBlockModes(Options.BLOCK_MODE_ECB)
                .setEncryptionPaddings(Options.PADDING_PKCS_1)
                .setSignatureAlgorithm(Options.ALGORITHM_SHA256_WITH_RSA_ENCRYPTION)
                .build()

        return generateAsymmetricKey(keyProps)
    }

    /**
     * Create and saves Private key specified in KeyProperties with self signed x509 Certificate.
     *
     *
     * Saves key to KeyStore. Uses keystore with default type located in application cache on device if API < 18.
     * Uses AndroidKeyStore if API is >= 18.

     * @return KeyPair or null if any error occurs
     */
    fun generateAsymmetricKey(keyProps: KeyProperties): KeyPair? {
        val result: KeyPair?
        if (lowerThenMarshmallow()) {
            result = generateAndroidJellyAsymmetricKey(keyProps)
        } else {
            result = generateAndroidMAsymmetricKey(keyProps)
        }
        return result
    }

    /**
     * Create and saves 256 AES SecretKey key using provided alias and password.
     *
     *
     * Saves key to KeyStore. Uses keystore with default type located in application cache on device if API < 23.
     * Uses AndroidKeyStore if API is >= 23.

     * @return KeyPair or null if any error occurs
     */
    fun generateSymmetricKey(alias: String, password: CharArray): SecretKey? {
        val keyProps = KeyProperties.Builder()
                .setAlias(alias)
                .setPassword(password)
                .setKeySize(256)
                .setKeyType(Options.ALGORITHM_AES)
                .setBlockModes(Options.BLOCK_MODE_CBC)
                .setEncryptionPaddings(Options.PADDING_PKCS_7)
                .build()
        return generateSymmetricKey(keyProps)
    }

    /**
     * Create and saves SecretKey key specified in KeyProperties.
     *
     *
     * Saves key to KeyStore. Uses keystore with default type located in application cache on device if API < 23.
     * Uses AndroidKeyStore if API is >= 23.

     * @return KeyPair or null if any error occurs
     */
    fun generateSymmetricKey(keyProps: KeyProperties): SecretKey? {
        val result: SecretKey?
        if (lowerThenMarshmallow()) {
            result = generateDefaultSymmetricKey(keyProps)
        } else {
            result = generateAndroidSymmetricKey(keyProps)
        }
        return result
    }

    /**
     * @return KeyPair or null if any error occurs
     */
    fun getAsymmetricKey(alias: String): KeyPair {
        return getAsymmetricKeyFromAndroidKeyStore(alias)
    }

    /**
     * @return SecretKey or null if any error occurs
     */
    fun getSymmetricKey(alias: String, password: CharArray): SecretKey {
        var result: SecretKey? = null
        if (lowerThenMarshmallow()) {
            result = getSymmetricKeyFromDefaultKeyStore(alias, password)
        } else {
            result = getSymmetricKeyFromAndroidtKeyStore(alias)
        }
        return result
    }

    /**
     * @return true if key with given alias is in keystore
     */
    fun hasKey(alias: String): Boolean {
        var result = false
        try {
            var keyStore: KeyStore
            if (lowerThenMarshmallow()) {
                keyStore = createAndroidKeystore()
                result = isKeyEntry(alias, keyStore)
                if (!result) {
                    // SecretKey's are stored in default keystore up to 23 API
                    keyStore = createDefaultKeyStore()
                    result = isKeyEntry(alias, keyStore)
                }
            } else {
                keyStore = createAndroidKeystore()
                result = isKeyEntry(alias, keyStore)
            }

        } catch (e: KeyStoreException) {
            onException(e)
        } catch (e: CertificateException) {
            onException(e)
        } catch (e: IOException) {
            onException(e)
        } catch (e: NoSuchAlgorithmException) {
            onException(e)
        }

        return result
    }

    /**
     * Deletes key with given alias
     */
    fun deleteKey(alias: String) {
        try {
            var keyStore: KeyStore
            if (lowerThenMarshmallow()) {
                keyStore = createAndroidKeystore()
                if (isKeyEntry(alias, keyStore)) {
                    deleteEntryFromAndroidKeystore(alias, keyStore)
                } else {
                    keyStore = createDefaultKeyStore()
                    if (isKeyEntry(alias, keyStore)) {
                        deleteEntryFromDefaultKeystore(alias, keyStore)
                    }
                }
            } else {
                keyStore = createAndroidKeystore()
                deleteEntryFromAndroidKeystore(alias, keyStore)
            }
        } catch (e: KeyStoreException) {
            onException(e)
        } catch (e: CertificateException) {
            onException(e)
        } catch (e: IOException) {
            onException(e)
        } catch (e: NoSuchAlgorithmException) {
            onException(e)
        }

    }

    @Throws(KeyStoreException::class)
    private fun isKeyEntry(alias: String, keyStore: KeyStore?): Boolean {
        return keyStore != null && keyStore.isKeyEntry(alias)
    }

    @Throws(KeyStoreException::class, IOException::class, CertificateException::class, NoSuchAlgorithmException::class)
    private fun deleteEntryFromDefaultKeystore(alias: String, keyStore: KeyStore?) {
        if (keyStore != null) {
            keyStore.deleteEntry(alias)
            keyStore.store(FileOutputStream(keystoreFile), keystorePassword)
        }
    }

    @Throws(KeyStoreException::class)
    private fun deleteEntryFromAndroidKeystore(alias: String, keyStore: KeyStore?) {
        keyStore?.deleteEntry(alias)
    }

    @TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
    private fun generateAndroidJellyAsymmetricKey(keyProps: KeyProperties): KeyPair? {
        try {
            val keySpec = keyPropsToKeyPairGeneratorSpec(keyProps)
            return generateAndroidAsymmetricKey(keyProps, keySpec)
        } catch (e: NoSuchAlgorithmException) {
            onException(e)
        } catch (e: NoSuchProviderException) {
            onException(e)
        } catch (e: InvalidAlgorithmParameterException) {
            onException(e)
        }

        return null
    }

    @TargetApi(Build.VERSION_CODES.M)
    private fun generateAndroidMAsymmetricKey(keyProps: KeyProperties): KeyPair? {
        try {
            val keySpec = keyPropsToKeyGenParameterASpec(keyProps)
            return generateAndroidAsymmetricKey(keyProps, keySpec)
        } catch (e: NoSuchAlgorithmException) {
            onException(e)
        } catch (e: NoSuchProviderException) {
            onException(e)
        } catch (e: InvalidAlgorithmParameterException) {
            onException(e)
        }

        return null
    }

    @Throws(NoSuchProviderException::class, NoSuchAlgorithmException::class, InvalidAlgorithmParameterException::class)
    private fun generateAndroidAsymmetricKey(keyProps: KeyProperties, keySpec: AlgorithmParameterSpec): KeyPair {
        val generator = KeyPairGenerator.getInstance(keyProps.keyType, PROVIDER_ANDROID_KEY_STORE)
        generator.initialize(keySpec)
        return generator.generateKeyPair()
    }

    @Throws(NoSuchAlgorithmException::class)
    private fun createAsymmetricKey(keyProps: KeyProperties): KeyPair {
        val generator = KeyPairGenerator.getInstance(keyProps.keyType)
        generator.initialize(keyProps.keySize)
        return generator.generateKeyPair()
    }

    private fun generateDefaultSymmetricKey(keyProps: KeyProperties): SecretKey? {
        try {
            val key = createSymmetricKey(keyProps)
            val keyEntry = KeyStore.SecretKeyEntry(key)
            val keyStore = createDefaultKeyStore()

            keyStore.setEntry(keyProps.alias, keyEntry, KeyStore.PasswordProtection(keyProps.password))
            keyStore.store(FileOutputStream(keystoreFile), keystorePassword)
            return key
        } catch (e: NoSuchAlgorithmException) {
            onException(e)
        } catch (e: CertificateException) {
            onException(e)
        } catch (e: KeyStoreException) {
            onException(e)
        } catch (e: IOException) {
            onException(e)
        }

        return null
    }

    @TargetApi(Build.VERSION_CODES.M)
    private fun generateAndroidSymmetricKey(keyProps: KeyProperties): SecretKey? {
        try {
            val provider = PROVIDER_ANDROID_KEY_STORE
            val keyGenerator = KeyGenerator.getInstance(keyProps.keyType, provider)
            val keySpec = keyPropsToKeyGenParameterSSpec(keyProps)
            keyGenerator.init(keySpec)
            return keyGenerator.generateKey()
        } catch (e: NoSuchAlgorithmException) {
            onException(e)
        } catch (e: NoSuchProviderException) {
            onException(e)
        } catch (e: InvalidAlgorithmParameterException) {
            onException(e)
        }

        return null
    }

    @TargetApi(Build.VERSION_CODES.KITKAT)
    @Throws(NoSuchAlgorithmException::class)
    private fun keyPropsToKeyPairGeneratorSpec(keyProps: KeyProperties): KeyPairGeneratorSpec {
        val builder = KeyPairGeneratorSpec.Builder(context)
                .setAlias(keyProps.alias)
                .setSerialNumber(keyProps.serialNumber)
                .setSubject(keyProps.subject)
                .setStartDate(keyProps.startDate)
                .setEndDate(keyProps.endDate)

        if (biggerThenJellyBean()) {
            builder.setKeySize(keyProps.keySize)
        }

        return builder.build()
    }

    @TargetApi(Build.VERSION_CODES.M)
    @Throws(NoSuchAlgorithmException::class)
    private fun keyPropsToKeyGenParameterASpec(keyProps: KeyProperties): KeyGenParameterSpec {
        val purposes = android.security.keystore.KeyProperties.PURPOSE_ENCRYPT or android.security.keystore.KeyProperties.PURPOSE_DECRYPT
        return KeyGenParameterSpec.Builder(keyProps.alias, purposes)
                .setKeySize(keyProps.keySize)
                .setCertificateSerialNumber(keyProps.serialNumber)
                .setCertificateSubject(keyProps.subject)
                .setCertificateNotBefore(keyProps.startDate)
                .setCertificateNotAfter(keyProps.endDate)
                .setBlockModes(keyProps.blockModes)
                .setEncryptionPaddings(keyProps.encryptionPadding)
                .build()
    }

    @TargetApi(Build.VERSION_CODES.M)
    @Throws(NoSuchAlgorithmException::class)
    private fun keyPropsToKeyGenParameterSSpec(keyProps: KeyProperties): KeyGenParameterSpec {
        val purposes = android.security.keystore.KeyProperties.PURPOSE_ENCRYPT or android.security.keystore.KeyProperties.PURPOSE_DECRYPT
        return KeyGenParameterSpec.Builder(keyProps.alias, purposes)
                .setKeySize(keyProps.keySize)
                .setBlockModes(keyProps.blockModes)
                .setEncryptionPaddings(keyProps.encryptionPadding)
                .build()
    }

    @Throws(NoSuchAlgorithmException::class)
    private fun createSymmetricKey(keyProps: KeyProperties): SecretKey {
        val keyGenerator = KeyGenerator.getInstance(keyProps.keyType)
        keyGenerator.init(keyProps.keySize)
        val key = keyGenerator.generateKey()
        return key
    }

    private fun getAsymmetricKeyFromAndroidKeyStore(alias: String): KeyPair {
        var result: KeyPair? = null
        try {
            val keyStore = createAndroidKeystore()
            val privateKey = keyStore.getKey(alias, null) as PrivateKey
            val publicKey = keyStore.getCertificate(alias).publicKey
            result = KeyPair(publicKey, privateKey)
        } catch (e: KeyStoreException) {
            onException(e)
        } catch (e: CertificateException) {
            onException(e)
        } catch (e: IOException) {
            onException(e)
        } catch (e: NoSuchAlgorithmException) {
            onException(e)
        } catch (e: UnrecoverableEntryException) {
            onException(e)
        }

        return result as KeyPair
    }

    private fun getSymmetricKeyFromDefaultKeyStore(alias: String, password: CharArray): SecretKey {
        var result: SecretKey? = null
        try {
            val keyStore = createDefaultKeyStore()
            result = keyStore.getKey(alias, password) as SecretKey
        } catch (e: KeyStoreException) {
            onException(e)
        } catch (e: CertificateException) {
            onException(e)
        } catch (e: IOException) {
            onException(e)
        } catch (e: NoSuchAlgorithmException) {
            onException(e)
        } catch (e: UnrecoverableEntryException) {
            onException(e)
        }

        return result as SecretKey
    }

    private fun getSymmetricKeyFromAndroidtKeyStore(alias: String): SecretKey {
        var result: SecretKey? = null
        try {
            val keyStore = createAndroidKeystore()
            result = keyStore.getKey(alias, null) as SecretKey
        } catch (e: KeyStoreException) {
            onException(e)
        } catch (e: CertificateException) {
            onException(e)
        } catch (e: IOException) {
            onException(e)
        } catch (e: NoSuchAlgorithmException) {
            onException(e)
        } catch (e: UnrecoverableEntryException) {
            onException(e)
        }

        return result as SecretKey
    }

    /**
     * Cache for default keystore
     */
    private var mDefaultKeyStore: KeyStore? = null

    @Throws(KeyStoreException::class, CertificateException::class, NoSuchAlgorithmException::class, IOException::class)
    private fun createDefaultKeyStore(): KeyStore {
        if (mDefaultKeyStore == null) {
            val defaultType = getDefaultType()
            mDefaultKeyStore = getInstance(defaultType)
            if (!keystoreFile.exists()) {
                mDefaultKeyStore!!.load(null)
            } else {
                mDefaultKeyStore!!.load(FileInputStream(keystoreFile), keystorePassword)
            }
        }
        return mDefaultKeyStore as KeyStore
    }

    /**
     * Cache for android keystore
     */
    private var mAndroidKeyStore: KeyStore? = null

    @Throws(KeyStoreException::class, CertificateException::class, NoSuchAlgorithmException::class, IOException::class)
    private fun createAndroidKeystore(): KeyStore {
        if (mAndroidKeyStore == null) {
            mAndroidKeyStore = KeyStore.getInstance(PROVIDER_ANDROID_KEY_STORE)
        }
        mAndroidKeyStore!!.load(null)
        return mAndroidKeyStore as KeyStore
    }

    companion object {

        private val PROVIDER_ANDROID_KEY_STORE = "AndroidKeyStore"
        private val DEFAULT_KEYSTORE_NAME = "keystore"
        private val DEFAULT_KEYSTORE_PASSWORD = BuildConfig.APPLICATION_ID.toCharArray()
    }

    /**
     * @return true it current api version is lower then 23
     */
    fun lowerThenMarshmallow(): Boolean {
        return VERSION < Build.VERSION_CODES.M
    }

    /**
     * @return true it current api version is bigger then 18
     */
    fun biggerThenJellyBean(): Boolean {
        return VERSION > Build.VERSION_CODES.JELLY_BEAN_MR2
    }

}

open class ErrorHandler {
    private var errorListener: ErrorListener? = null

    /**
     * Use this method to handle errors that may occur while working with this class. Error log with short information
     * about exception will be printed to log cat even if there is no [ErrorListener] specified.

     * @param errorListener will be triggered if any error occurs.
     */
    fun setErrorListener(errorListener: ErrorListener) {
        this.errorListener = errorListener
    }

    /**
     * Prints exception in logs and triggers listener if it is not null
     */
    protected fun onException(e: Exception) {
        if (BuildConfig.DEBUG) {
            Log.e("Vault", Log.getStackTraceString(e))
        } else {
            Log.e("Vault", e.toString())
        }
        if (errorListener != null) {
            errorListener!!.onError(e)
        }
    }
}


interface ErrorListener {
    fun onError(e: Exception)
}

