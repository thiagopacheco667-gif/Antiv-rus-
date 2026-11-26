package com.aegis.security.core.security.di

import com.aegis.security.domain.analysis.AnalysisEngine
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import dagger.multibindings.Multibinds

/**
 * Ponto de registro dos mecanismos de análise.
 *
 * Declara o conjunto (que pode estar vazio) de [AnalysisEngine]. Cada mecanismo real,
 * a partir da Etapa 2, contribui com:
 *
 * ```
 * @Binds @IntoSet abstract fun bindsSha256Engine(impl: Sha256Engine): AnalysisEngine
 * ```
 *
 * Nesta etapa nenhum mecanismo está implementado, portanto o conjunto é vazio e a interface
 * informa ao usuário que a análise ainda não está disponível.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class AnalysisEnginesModule {
    @Multibinds
    abstract fun analysisEngines(): Set<AnalysisEngine>
}
