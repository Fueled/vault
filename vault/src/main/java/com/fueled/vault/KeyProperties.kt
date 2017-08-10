package com.fueled.vault

import android.security.KeyPairGeneratorSpec

import java.math.BigInteger
import java.util.Date

import javax.security.auth.x500.X500Principal

class KeyProperties {
    lateinit var alias: String
    lateinit var password: CharArray
    lateinit var keyType: String
    var keySize: Int = 0

    lateinit var blockModes: String
    lateinit var encryptionPadding: String

    lateinit var signatureAlgorithm: String
    lateinit var serialNumber: BigInteger
    lateinit var subject: X500Principal
    lateinit var startDate: Date
    lateinit var endDate: Date

    class Builder {
        private val props = KeyProperties()

        /**
         * Required for Symmetric and Asymmetric key
         */
        fun setAlias(alias: String): Builder {
            props.alias = alias
            return this
        }

        /**
         * Required for Symmetric and Asymmetric key
         */
        fun setKeyType(keyType: String): Builder {
            props.keyType = keyType
            return this
        }

        /**
         * Required for Symmetric using API < 23 and Asymmetric key using API < 18.

         * @param password used for additional key secure in Default KeyStore.
         */
        fun setPassword(password: CharArray): Builder {
            props.password = password
            return this
        }

        /**
         * Required for Symmetric using API < 23 and Asymmetric key using API < 18. Is ignored in 18 API for Asymmetric
         * keys as there is no possibility to specify it for [KeyPairGeneratorSpec]
         */
        fun setKeySize(keySize: Int): Builder {
            props.keySize = keySize
            return this
        }

        /**
         * Required for Asymmetric key.
         */
        fun setSerialNumber(serialNumber: BigInteger): Builder {
            props.serialNumber = serialNumber
            return this
        }

        /**
         * Required for Asymmetric key.
         *
         *
         * Example: final X500Principal subject = new X500Principal("CN=" + alias + " CA Certificate");
         */
        fun setSubject(subject: X500Principal): Builder {
            props.subject = subject
            return this
        }

        /**
         * Required for Asymmetric key.
         */
        fun setStartDate(startDate: Date): Builder {
            props.startDate = startDate
            return this
        }

        /**
         * Required for Asymmetric key.
         */
        fun setEndDate(endDate: Date): Builder {
            props.endDate = endDate
            return this
        }

        /**
         * Required for Symmetric and Asymmetric keys using API >= 23.
         */
        fun setBlockModes(blockModes: String): Builder {
            props.blockModes = blockModes
            return this
        }

        /**
         * Required for Symmetric and Asymmetric keys using API >= 23.
         */
        fun setEncryptionPaddings(encryptionPaddings: String): Builder {
            props.encryptionPadding = encryptionPaddings
            return this
        }

        /**
         * Required for Asymmetric key using API < 18.
         */
        fun setSignatureAlgorithm(signatureAlgorithm: String): Builder {
            props.signatureAlgorithm = signatureAlgorithm
            return this
        }

        fun build(): KeyProperties {
            return props
        }
    }
}
