package com.fueled.vault

import android.security.KeyPairGeneratorSpec
import android.util.Base64

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.Key
import java.security.KeyPair
import java.security.NoSuchAlgorithmException

import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.CipherOutputStream
import javax.crypto.IllegalBlockSizeException
import javax.crypto.NoSuchPaddingException
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

/**
 * API to encrypt/decrypt data
 */
class Crypto : ErrorHandler {
    private var transformation: String? = null
    private var encryptionBlockSize: Int = 0
    private var decryptionBlockSize: Int = 0

    /**
     * Initializes Crypto to encrypt/decrypt data with given transformation.

     * @param transformation is used to encrypt/decrypt data. See [Cipher] for more info.
     */
    constructor(transformation: String) {
        this.transformation = transformation
    }

    /**
     * Initializes Crypto to encrypt/decrypt data using buffer with provided lengths. This might be useful if you
     * want to encrypt/decrypt big amount of data using Block Based Algorithms (such as RSA). By default they can
     * proceed only one block of data, not bigger then a size of a key that was used for encryption/decryption.

     * @param transformation is used to encrypt/decrypt data. See [Cipher] for more info.
     *
     *
     * *
     * @param encryptionBlockSize block size for keys used with this Crypto for encryption. Depends on API level.
     * * For example: 1024 size RSA/ECB/PKCS1Padding key will equal to (keySize / 8) - 11 == (1024 / 8) - 11 == 117
     * * but for API 18 it is equal to 245 as there is no possibility to specify key size in [ ] and 2048 key size is always used there. Use [Options.ENCRYPTION_BLOCK_SIZE] in
     * * pair with key created by [Vault.generateSymmetricKey]
     *
     *
     * *
     * @param decryptionBlockSize block size for keys used with this Crypto for decryption. Depend on API level. For
     * * example: 1024 size RSA/ECB/PKCS1Padding key will equal to (keySize / 8) == (1024 / 8) == 128 but on API 18 it
     * * is equal to 256 as there is no possibility to specify key size in [KeyPairGeneratorSpec] and 2048 key
     * * size is always used there. Use [Options.DECRYPTION_BLOCK_SIZE] in pair with key created by [ ][Vault.generateSymmetricKey]
     */
    constructor(transformation: String, encryptionBlockSize: Int, decryptionBlockSize: Int) {
        this.transformation = transformation
        this.encryptionBlockSize = encryptionBlockSize
        this.decryptionBlockSize = decryptionBlockSize
    }

    /**
     * The same as encrypt(data, key.getPublic(), false);

     * @return encrypted data in Base64 String or null if any error occur. Doesn't use Initialisation Vectors
     */
    fun encrypt(data: String, key: KeyPair): String? {
        return encrypt(data, key.public, false)
    }

    /**
     * The same as encrypt(data, key, true)

     * @return encrypted data in Base64 String or null if any error occur. Does use Initialisation Vectors
     */
    fun encrypt(data: String, key: SecretKey): String? {
        return encrypt(data, key, true)
    }

    /**
     * @param useInitialisationVectors specifies when ever IvParameterSpec should be used in encryption
     * *
     * *
     * @return encrypted data in Base64 String or null if any error occur. if useInitialisationVectors is true, data
     * * also contains iv key inside. In this case data will be returned in this format <iv key>]<encrypted data>
    </encrypted></iv> */
    fun encrypt(data: String, key: Key, useInitialisationVectors: Boolean): String? {
        var result = ""
        try {
            val cipher = Cipher.getInstance(if (transformation == null) key.algorithm else transformation)
            cipher.init(Cipher.ENCRYPT_MODE, key)

            if (useInitialisationVectors) {
                val iv = cipher.iv
                val ivString = Base64.encodeToString(iv, Base64.DEFAULT)
                result = ivString + IV_SEPARATOR
            }

            val plainData = data.toByteArray(charset(UTF_8))
            val decodedData: ByteArray
            if (encryptionBlockSize == 0 && decryptionBlockSize == 0) {
                decodedData = decode(cipher, plainData)
            } else {
                decodedData = decodeWithBuffer(cipher, plainData, encryptionBlockSize)
            }

            val encodedString = Base64.encodeToString(decodedData, Base64.DEFAULT)
            result += encodedString
        } catch (e: NoSuchAlgorithmException) {
            onException(e)
        } catch (e: NoSuchPaddingException) {
            onException(e)
        } catch (e: InvalidKeyException) {
            onException(e)
        } catch (e: BadPaddingException) {
            onException(e)
        } catch (e: IllegalBlockSizeException) {
            onException(e)
        } catch (e: IOException) {
            onException(e)
        }

        return result
    }

    /**
     * The same as decrypt(data, key.getPrivate(), false)

     * @param data Base64 encrypted data. Doesn't use Initialisation Vectors
     * *
     * *
     * @return decrypted data or null if any error occur
     */
    fun decrypt(data: String, key: KeyPair): String? {
        return decrypt(data, key.private, false)
    }


    /**
     * The same as decrypt(data, key, true)

     * @param data Base64 encrypted data with iv key. Does use Initialisation Vectors
     * *
     * *
     * @return decrypted data or null if any error occur
     */
    fun decrypt(data: String, key: SecretKey): String? {
        return decrypt(data, key, true)
    }


    /**
     * @param data Base64 encrypted data. If useInitialisationVectors is enabled, data should contain iv key inside.
     * * In this case data should be in this format <iv key>]<encrypted data>
     * *
     * @param useInitialisationVectors specifies when ever IvParameterSpec should be used in encryption
     * *
     * *
     * @return decrypted data or null if any error occur
    </encrypted></iv> */
    fun decrypt(data: String, key: Key, useInitialisationVectors: Boolean): String? {
        var result: String? = null
        try {
            val transformation = if (this.transformation == null) key.algorithm else this.transformation
            val cipher = Cipher.getInstance(transformation)

            val encodedString: String

            if (useInitialisationVectors) {
                val split = data.split(IV_SEPARATOR.toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
                val ivString = split[0]
                encodedString = split[1]
                val ivSpec = IvParameterSpec(Base64.decode(ivString, Base64.DEFAULT))
                cipher.init(Cipher.DECRYPT_MODE, key, ivSpec)
            } else {
                encodedString = data
                cipher.init(Cipher.DECRYPT_MODE, key)
            }

            val decodedData: ByteArray
            val encryptedData = Base64.decode(encodedString, Base64.DEFAULT)
            if (encryptionBlockSize == 0 && decryptionBlockSize == 0) {
                decodedData = decode(cipher, encryptedData)
            } else {
                decodedData = decodeWithBuffer(cipher, encryptedData, decryptionBlockSize)
            }
            result = String(decodedData)
        } catch (e: NoSuchAlgorithmException) {
            onException(e)
        } catch (e: NoSuchPaddingException) {
            onException(e)
        } catch (e: InvalidKeyException) {
            onException(e)
        } catch (e: BadPaddingException) {
            onException(e)
        } catch (e: IllegalBlockSizeException) {
            onException(e)
        } catch (e: IOException) {
            onException(e)
        } catch (e: InvalidAlgorithmParameterException) {
            onException(e)
        }

        return result
    }

    @Throws(IOException::class, IllegalBlockSizeException::class, BadPaddingException::class)
    private fun decode(cipher: Cipher, plainData: ByteArray): ByteArray {
        val baos = ByteArrayOutputStream()
        val cipherOutputStream = CipherOutputStream(baos, cipher)
        cipherOutputStream.write(plainData)
        cipherOutputStream.close()
        return baos.toByteArray()
    }

    @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
    private fun decodeWithBuffer(cipher: Cipher, plainData: ByteArray, bufferLength: Int): ByteArray {
        // string initialize 2 buffers.
        // scrambled will hold intermediate results
        var scrambled: ByteArray

        // toReturn will hold the total result
        var toReturn = ByteArray(0)

        // holds the bytes that have to be modified in one step
        var buffer = ByteArray(if (plainData.size > bufferLength) bufferLength else plainData.size)

        for (i in plainData.indices) {
            if (i > 0 && i % bufferLength == 0) {
                //execute the operation
                scrambled = cipher.doFinal(buffer)
                // add the result to our total result.
                toReturn = append(toReturn, scrambled)
                // here we calculate the bufferLength of the next buffer required
                var newLength = bufferLength

                // if newLength would be longer than remaining bytes in the bytes array we shorten it.
                if (i + bufferLength > plainData.size) {
                    newLength = plainData.size - i
                }
                // clean the buffer array
                buffer = ByteArray(newLength)
            }
            // copy byte into our buffer.
            buffer[i % bufferLength] = plainData[i]
        }

        // this step is needed if we had a trailing buffer. should only happen when encrypting.
        // example: we encrypt 110 bytes. 100 bytes per run means we "forgot" the last 10 bytes. they are in the buffer array
        scrambled = cipher.doFinal(buffer)

        // final step before we can return the modified data.
        toReturn = append(toReturn, scrambled)
        return toReturn
    }

    private fun append(prefix: ByteArray, suffix: ByteArray): ByteArray {
        val toReturn = ByteArray(prefix.size + suffix.size)
        for (i in prefix.indices) {
            toReturn[i] = prefix[i]
        }
        for (i in suffix.indices) {
            toReturn[i + prefix.size] = suffix[i]
        }
        return toReturn
    }

    companion object {

        private val UTF_8 = "UTF-8"
        private val IV_SEPARATOR = "]"
    }
}
