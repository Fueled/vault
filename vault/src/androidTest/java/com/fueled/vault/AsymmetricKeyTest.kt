package com.fueled.vault

import android.os.Build
import android.support.test.runner.AndroidJUnit4

import org.hamcrest.Matchers
import org.junit.Test
import org.junit.runner.RunWith

import java.math.BigInteger
import java.security.KeyPair
import java.util.Calendar

import javax.security.auth.x500.X500Principal

import org.hamcrest.CoreMatchers.instanceOf
import org.hamcrest.CoreMatchers.`is`
import org.hamcrest.CoreMatchers.notNullValue
import org.hamcrest.CoreMatchers.nullValue
import org.hamcrest.core.IsNot.not
import org.junit.Assert.assertThat

@RunWith(AndroidJUnit4::class)
class AsymmetricKeyTest : BaseContextTest(), BaseKeyTest {

    @Test
    override fun shouldBeAbleToGenerateDefaultKeyIsNotNull() {
        val vault = Vault(context, BaseKeyTest.STORE_NAME, BaseKeyTest.STORE_PASSWORD)
        val keyPair = vault.generateAsymmetricKey(BaseKeyTest.KEY_ALIAS_ASYMMETRIC, BaseKeyTest.KEY_PASSWORD)
        assertThat<KeyPair>(keyPair, `is`(notNullValue()))
        vault.deleteKey(BaseKeyTest.KEY_ALIAS_ASYMMETRIC)
    }

    @Test
    override fun shouldBeAbleToGenerateKeyIsNotNull() {
        val vault = Vault(context, BaseKeyTest.STORE_NAME, BaseKeyTest.STORE_PASSWORD)

        val start = Calendar.getInstance()
        val end = Calendar.getInstance()
        end.add(Calendar.YEAR, 1)

        val keyPair = vault.generateAsymmetricKey(KeyProperties.Builder()
                .setAlias(BaseKeyTest.KEY_ALIAS_ASYMMETRIC)
                .setPassword(BaseKeyTest.KEY_PASSWORD)
                .setKeySize(BaseKeyTest.KEY_SIZE)
                .setKeyType("RSA")
                .setSerialNumber(BigInteger.ONE)
                .setSubject(X500Principal("CN=" + BaseKeyTest.KEY_ALIAS_ASYMMETRIC + " CA Certificate"))
                .setStartDate(start.time)
                .setEndDate(start.time)
                .setBlockModes("ECB")
                .setEncryptionPaddings("PKCS1Padding")
                .setSignatureAlgorithm("SHA256WithRSAEncryption")
                .build())

        assertThat<KeyPair>(keyPair, `is`(notNullValue()))
        vault.deleteKey(BaseKeyTest.KEY_ALIAS_ASYMMETRIC)
    }

    @Test
    override fun shouldBeAbleToGenerateKeyHasWrongType() {
        val vault = Vault(context, BaseKeyTest.STORE_NAME, BaseKeyTest.STORE_PASSWORD)

        val start = Calendar.getInstance()
        val end = Calendar.getInstance()
        end.add(Calendar.YEAR, 1)

        val keyPair = vault.generateAsymmetricKey(KeyProperties.Builder()
                .setAlias(BaseKeyTest.KEY_ALIAS_ASYMMETRIC)
                .setPassword(BaseKeyTest.KEY_PASSWORD)
                .setKeySize(BaseKeyTest.KEY_SIZE)
                .setKeyType("no-such-key-type")
                .setSerialNumber(BigInteger.ONE)
                .setSubject(X500Principal("CN=" + BaseKeyTest.KEY_ALIAS_ASYMMETRIC + " CA Certificate"))
                .setStartDate(start.time)
                .setEndDate(start.time)
                .setBlockModes("ECB")
                .setEncryptionPaddings("PKCS1Padding")
                .setSignatureAlgorithm("SHA256WithRSAEncryption")
                .build())

        assertThat<KeyPair>(keyPair, `is`(nullValue()))
    }

    @Test
    override fun shouldBeAbleToGenerateKeyHasNoBlockModes() {
        val vault = Vault(context, BaseKeyTest.STORE_NAME, BaseKeyTest.STORE_PASSWORD)

        val start = Calendar.getInstance()
        val end = Calendar.getInstance()
        end.add(Calendar.YEAR, 1)

        val keyPair = vault.generateAsymmetricKey(KeyProperties.Builder()
                .setAlias(BaseKeyTest.KEY_ALIAS_ASYMMETRIC)
                .setPassword(BaseKeyTest.KEY_PASSWORD)
                .setKeySize(BaseKeyTest.KEY_SIZE)
                .setKeyType("RSA")
                .setSerialNumber(BigInteger.ONE)
                .setSubject(X500Principal("CN=" + BaseKeyTest.KEY_ALIAS_ASYMMETRIC + " CA Certificate"))
                .setStartDate(start.time)
                .setEndDate(start.time)
                .setBlockModes("no-such-block-modes")
                .setEncryptionPaddings("PKCS1Padding")
                .setSignatureAlgorithm("SHA256WithRSAEncryption")
                .build())

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            assertThat<KeyPair>(keyPair, `is`(notNullValue()))
            vault.deleteKey(BaseKeyTest.KEY_ALIAS_ASYMMETRIC)
        } else {
            assertThat<KeyPair>(keyPair, `is`(nullValue()))
        }
    }

    @Test
    override fun shouldBeAbleToGenerateKeyHasNoEncryptionPaddings() {
        val vault = Vault(context, BaseKeyTest.STORE_NAME, BaseKeyTest.STORE_PASSWORD)

        val start = Calendar.getInstance()
        val end = Calendar.getInstance()
        end.add(Calendar.YEAR, 1)

        val keyPair = vault.generateAsymmetricKey(KeyProperties.Builder()
                .setAlias(BaseKeyTest.KEY_ALIAS_ASYMMETRIC)
                .setPassword(BaseKeyTest.KEY_PASSWORD)
                .setKeySize(BaseKeyTest.KEY_SIZE)
                .setKeyType("RSA")
                .setSerialNumber(BigInteger.ONE)
                .setSubject(X500Principal("CN=" + BaseKeyTest.KEY_ALIAS_ASYMMETRIC + " CA Certificate"))
                .setStartDate(start.time)
                .setEndDate(start.time)
                .setBlockModes("ECB")
                .setEncryptionPaddings("no-such-encryption-paddings")
                .setSignatureAlgorithm("SHA256WithRSAEncryption")
                .build())

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            assertThat<KeyPair>(keyPair, `is`(notNullValue()))
            vault.deleteKey(BaseKeyTest.KEY_ALIAS_ASYMMETRIC)
        } else {
            assertThat<KeyPair>(keyPair, `is`(nullValue()))
        }
    }

    @Test
    override fun shouldBeAbleToGetKeyIsNotNull() {
        var vault = Vault(context, BaseKeyTest.STORE_NAME, BaseKeyTest.STORE_PASSWORD)
        vault.generateAsymmetricKey(BaseKeyTest.KEY_ALIAS_ASYMMETRIC, BaseKeyTest.KEY_PASSWORD)
        var keyPair = vault.getAsymmetricKey(BaseKeyTest.KEY_ALIAS_ASYMMETRIC)
        assertThat(keyPair, `is`(notNullValue()))

        vault = Vault(context, BaseKeyTest.STORE_NAME, BaseKeyTest.STORE_PASSWORD)
        keyPair = vault.getAsymmetricKey(BaseKeyTest.KEY_ALIAS_ASYMMETRIC)
        assertThat(keyPair, `is`(notNullValue()))

        vault.deleteKey(BaseKeyTest.KEY_ALIAS_ASYMMETRIC)
    }

    @Test
    override fun shouldBeAbleToCheckHasKeyIsTrue() {
        val vault = Vault(context, BaseKeyTest.STORE_NAME, BaseKeyTest.STORE_PASSWORD)
        vault.generateAsymmetricKey(BaseKeyTest.KEY_ALIAS_ASYMMETRIC, BaseKeyTest.KEY_PASSWORD)
        assertThat(vault.hasKey(BaseKeyTest.KEY_ALIAS_ASYMMETRIC), `is`(true))
        vault.deleteKey(BaseKeyTest.KEY_ALIAS_ASYMMETRIC)
    }

    @Test
    override fun shouldBeAbleToCheckHasKeyIsFalse() {
        val vault = Vault(context, BaseKeyTest.STORE_NAME, BaseKeyTest.STORE_PASSWORD)
        assertThat(vault.hasKey(BaseKeyTest.KEY_ALIAS_ASYMMETRIC), `is`(false))
    }

    @Test
    override fun shouldBeAbleToDeleteKey() {
        var vault = Vault(context, BaseKeyTest.STORE_NAME, BaseKeyTest.STORE_PASSWORD)
        vault.generateAsymmetricKey(BaseKeyTest.KEY_ALIAS_ASYMMETRIC, BaseKeyTest.KEY_PASSWORD)
        vault.deleteKey(BaseKeyTest.KEY_ALIAS_ASYMMETRIC)
        assertThat(vault.hasKey(BaseKeyTest.KEY_ALIAS_ASYMMETRIC), `is`(false))

        // make sure that new instance of vault also doesn't contains the key
        vault = Vault(context, BaseKeyTest.STORE_NAME, BaseKeyTest.STORE_PASSWORD)
        assertThat(vault.hasKey(BaseKeyTest.KEY_ALIAS_ASYMMETRIC), `is`(false))
    }

    @Test
    override fun shouldBeAbleToEncryptSmallData() {
        val vault = Vault(context, BaseKeyTest.STORE_NAME, BaseKeyTest.STORE_PASSWORD)
        val keyPair = vault.generateAsymmetricKey(BaseKeyTest.KEY_ALIAS_ASYMMETRIC, BaseKeyTest.KEY_PASSWORD)
        val crypto = Crypto(Options.TRANSFORMATION_ASYMMETRIC)
        val encrypt = crypto.encrypt(BaseKeyTest.SMALL_DATA, keyPair!!)
        val decrypt = crypto.decrypt(encrypt!!, keyPair)
        assertThat(BaseKeyTest.SMALL_DATA, `is`<String>(decrypt))
        vault.deleteKey(BaseKeyTest.KEY_ALIAS_ASYMMETRIC)
    }

    @Test
    override fun shouldBeAbleToEncryptLargeData() {
        val vault = Vault(context, BaseKeyTest.STORE_NAME, BaseKeyTest.STORE_PASSWORD)
        val keyPair = vault.generateAsymmetricKey(BaseKeyTest.KEY_ALIAS_ASYMMETRIC, BaseKeyTest.KEY_PASSWORD)
        val crypto = Crypto(Options.TRANSFORMATION_ASYMMETRIC, Options.ENCRYPTION_BLOCK_SIZE, Options.DECRYPTION_BLOCK_SIZE)
        val encrypt = crypto.encrypt(BaseKeyTest.LARGE_DATA, keyPair!!)
        val decrypt = crypto.decrypt(encrypt!!, keyPair)
        assertThat(BaseKeyTest.LARGE_DATA, `is`<String>(decrypt))
        vault.deleteKey(BaseKeyTest.KEY_ALIAS_ASYMMETRIC)
    }

    @Test
    fun encryptLargeDataWith512KeySizeIsValid() {
        encryptLargeDataIsValid(512)
    }

    @Test
    fun encryptLargeDataWith1024KeySizeIsValid() {
        encryptLargeDataIsValid(1024)
    }

    @Test
    fun encryptLargeDataWith2048KeySizeIsValid() {
        encryptLargeDataIsValid(2048)
    }

    @Test
    fun encryptLargeDataWith3072KeySizeIsValid() {
        encryptLargeDataIsValid(3072)
    }

    @Test
    fun encryptLargeDataWith4096KeySizeIsValid() {
        encryptLargeDataIsValid(4096)
    }

    @Test
    override fun shouldBeAbleToCheckInValidEncryptData() {
        // different keys encryption
        val vault = Vault(context, BaseKeyTest.STORE_NAME, BaseKeyTest.STORE_PASSWORD)
        var keyPair = vault.generateAsymmetricKey(BaseKeyTest.KEY_ALIAS_ASYMMETRIC, BaseKeyTest.KEY_PASSWORD)
        val keyPair2 = vault.generateAsymmetricKey("key-pair-2", BaseKeyTest.KEY_PASSWORD)
        var crypto = Crypto(Options.TRANSFORMATION_SYMMETRIC)
        var encrypt = crypto.encrypt(BaseKeyTest.SMALL_DATA, keyPair!!)
        var decrypt = crypto.decrypt(encrypt!!, keyPair2!!)
        assertThat(BaseKeyTest.SMALL_DATA, `is`(not<String>(decrypt)))
        vault.deleteKey(BaseKeyTest.KEY_ALIAS_ASYMMETRIC)
        vault.deleteKey("key-pair-2")

        // wrong block props for large data

        try {
            keyPair = vault.generateAsymmetricKey(BaseKeyTest.KEY_ALIAS_ASYMMETRIC, BaseKeyTest.KEY_PASSWORD)
            crypto = Crypto(Options.TRANSFORMATION_ASYMMETRIC)
            encrypt = crypto.encrypt(BaseKeyTest.LARGE_DATA, keyPair!!)
            decrypt = crypto.decrypt(encrypt!!, keyPair)
        } catch (e: Exception) {
            assertThat(Build.VERSION.SDK_INT, `is`(Matchers.lessThan(Build.VERSION_CODES.JELLY_BEAN_MR2)))
            assertThat(e, `is`(instanceOf<Any>(ArrayIndexOutOfBoundsException::class.java)))
        }

        assertThat(BaseKeyTest.LARGE_DATA, `is`(not<String>(decrypt)))
        vault.deleteKey(BaseKeyTest.KEY_ALIAS_ASYMMETRIC)
    }

    private fun encryptLargeDataIsValid(keySize: Int) {
        val vault = Vault(context, BaseKeyTest.STORE_NAME, BaseKeyTest.STORE_PASSWORD)

        val start = Calendar.getInstance()
        val end = Calendar.getInstance()
        end.add(Calendar.YEAR, 1)

        val keyProps = KeyProperties.Builder()
                .setAlias(BaseKeyTest.KEY_ALIAS_ASYMMETRIC)
                .setPassword(BaseKeyTest.KEY_PASSWORD)
                .setKeySize(keySize)
                .setKeyType("RSA")
                .setSerialNumber(BigInteger.ONE)
                .setSubject(X500Principal("CN=" + BaseKeyTest.KEY_ALIAS_ASYMMETRIC + " CA Certificate"))
                .setStartDate(start.time)
                .setEndDate(start.time)
                .setBlockModes("ECB")
                .setEncryptionPaddings("PKCS1Padding")
                .setSignatureAlgorithm("SHA256WithRSAEncryption")
                .build()

        val keyPair = vault.generateAsymmetricKey(keyProps)

        val encryptionBlock: Int
        val decryptionBlock: Int

        if (Build.VERSION.SDK_INT == Build.VERSION_CODES.JELLY_BEAN_MR2) {
            encryptionBlock = Options.RSA_ECB_PKCS1PADDING_ENCRYPTION_BLOCK_SIZE_FOR_JELLY_BEAN
            decryptionBlock = Options.RSA_ECB_PKCS1PADDING_DECRYPTION_BLOCK_SIZE_FOR_JELLY_BEAN
        } else {
            encryptionBlock = keySize / 8 - 11
            decryptionBlock = keySize / 8
        }

        val crypto = Crypto(Options.TRANSFORMATION_ASYMMETRIC, encryptionBlock, decryptionBlock)
        val encrypt = crypto.encrypt(BaseKeyTest.LARGE_DATA, keyPair!!)
        val decrypt = crypto.decrypt(encrypt!!, keyPair)

        assertThat(BaseKeyTest.LARGE_DATA, `is`<String>(decrypt))
        vault.deleteKey(BaseKeyTest.KEY_ALIAS_ASYMMETRIC)
    }
}
