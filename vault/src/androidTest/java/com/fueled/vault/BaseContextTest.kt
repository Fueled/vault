package com.fueled.vault

import android.content.Context
import android.support.test.InstrumentationRegistry

import org.junit.Before

open class BaseContextTest {

    protected lateinit var context: Context

    @Before
    fun setup() {
        context = InstrumentationRegistry.getTargetContext()
    }

}
