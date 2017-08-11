package com.fueled.vault

internal interface BaseKeyTest {

    fun shouldBeAbleToGenerateDefaultKeyIsNotNull()
    fun shouldBeAbleToGenerateKeyIsNotNull()
    fun shouldBeAbleToGenerateKeyHasWrongType()
    fun shouldBeAbleToGenerateKeyHasNoBlockModes()
    fun shouldBeAbleToGenerateKeyHasNoEncryptionPaddings()
    fun shouldBeAbleToGetKeyIsNotNull()
    fun shouldBeAbleToCheckHasKeyIsTrue()
    fun shouldBeAbleToCheckHasKeyIsFalse()
    fun shouldBeAbleToDeleteKey()
    fun shouldBeAbleToEncryptSmallData()
    fun shouldBeAbleToEncryptLargeData()
    fun shouldBeAbleToCheckInValidEncryptData()

    companion object {

        val STORE_NAME = "security-store"
        val STORE_PASSWORD = "password".toCharArray()

        val KEY_ALIAS_ASYMMETRIC = "asymmetric"
        val KEY_ALIAS_SYMMETRIC = "symmetric"
        val KEY_PASSWORD = "password".toCharArray()
        val KEY_SIZE = 1024

        val SMALL_DATA = "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
        val LARGE_DATA = "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo".repeat(110)
    }
}
