package com.aegis.security.core.network

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import kotlinx.serialization.json.Json
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import java.io.IOException
import java.util.concurrent.TimeUnit
import javax.inject.Singleton

/** Recusa qualquer requisição que não seja HTTPS, inclusive após redirecionamentos. */
internal class HttpsOnlyInterceptor : Interceptor {
    override fun intercept(chain: Interceptor.Chain): okhttp3.Response {
        val request = chain.request()
        if (!request.url.isHttps) throw IOException("Conexões sem HTTPS são bloqueadas")
        return chain.proceed(request)
    }
}

@Module
@InstallIn(SingletonComponent::class)
object NetworkModule {
    @Provides
    @Singleton
    fun providesJson(): Json = Json {
        ignoreUnknownKeys = true
        explicitNulls = false
    }

    @Provides
    @Singleton
    fun providesOkHttpClient(): OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .writeTimeout(30, TimeUnit.SECONDS)
        .callTimeout(0, TimeUnit.SECONDS)
        // Retentativas são controladas pelo repositório, respeitando os limites da conta.
        .retryOnConnectionFailure(false)
        .followSslRedirects(false)
        .addNetworkInterceptor(HttpsOnlyInterceptor())
        .build()
}

@Module
@InstallIn(SingletonComponent::class)
abstract class BackendApiModule {
    @Binds
    abstract fun bindsBackendApi(client: AegisBackendClient): BackendApi
}
