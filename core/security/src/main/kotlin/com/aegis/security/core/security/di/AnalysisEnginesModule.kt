package com.aegis.security.core.security.di

import com.aegis.security.core.security.apk.AndroidApkManifestReader
import com.aegis.security.core.security.apk.ApkEngine
import com.aegis.security.core.security.apk.ApkManifestReader
import com.aegis.security.core.security.apk.ApkPartExtractor
import com.aegis.security.core.security.dex.DexEngine
import com.aegis.security.core.security.elf.ElfEngine
import com.aegis.security.core.security.identify.DefaultFormatIdentifier
import com.aegis.security.core.security.pdf.PdfEngine
import com.aegis.security.core.security.pe.PeEngine
import com.aegis.security.core.security.rules.ApkRules
import com.aegis.security.core.security.rules.ArchiveRules
import com.aegis.security.core.security.rules.BinaryRules
import com.aegis.security.core.security.rules.DefaultRuleEngine
import com.aegis.security.core.security.rules.DocumentRules
import com.aegis.security.core.security.rules.GeneralRules
import com.aegis.security.core.security.rules.RuleSet
import com.aegis.security.core.security.signature.EicarEngine
import com.aegis.security.core.security.zip.ZipEngine
import com.aegis.security.domain.analysis.AnalysisEngine
import com.aegis.security.domain.analysis.ExecutablePartExtractor
import com.aegis.security.domain.analysis.FormatIdentifier
import com.aegis.security.domain.analysis.PatternScanner
import com.aegis.security.domain.analysis.RuleEngine
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import dagger.multibindings.IntoSet
import dagger.multibindings.Multibinds
import javax.inject.Singleton

/**
 * Registro de mecanismos e regras. Para adicionar um mecanismo, implemente [AnalysisEngine]
 * e acrescente um `@Binds @IntoSet` aqui — nada mais no app precisa mudar.
 */
@Module
@InstallIn(SingletonComponent::class)
internal abstract class AnalysisEnginesModule {
    @Multibinds
    abstract fun analysisEngines(): Set<AnalysisEngine>

    /** Vazio enquanto nenhum mecanismo YARA real estiver integrado e testado. */
    @Multibinds
    abstract fun patternScanners(): Set<PatternScanner>

    @Binds @IntoSet abstract fun bindsZipEngine(engine: ZipEngine): AnalysisEngine
    @Binds @IntoSet abstract fun bindsApkEngine(engine: ApkEngine): AnalysisEngine
    @Binds @IntoSet abstract fun bindsDexEngine(engine: DexEngine): AnalysisEngine
    @Binds @IntoSet abstract fun bindsPeEngine(engine: PeEngine): AnalysisEngine
    @Binds @IntoSet abstract fun bindsElfEngine(engine: ElfEngine): AnalysisEngine
    @Binds @IntoSet abstract fun bindsPdfEngine(engine: PdfEngine): AnalysisEngine
    @Binds @IntoSet abstract fun bindsEicarEngine(engine: EicarEngine): AnalysisEngine

    @Binds @IntoSet abstract fun bindsGeneralRules(rules: GeneralRules): RuleSet
    @Binds @IntoSet abstract fun bindsArchiveRules(rules: ArchiveRules): RuleSet
    @Binds @IntoSet abstract fun bindsApkRules(rules: ApkRules): RuleSet
    @Binds @IntoSet abstract fun bindsBinaryRules(rules: BinaryRules): RuleSet
    @Binds @IntoSet abstract fun bindsDocumentRules(rules: DocumentRules): RuleSet

    @Binds @Singleton abstract fun bindsRuleEngine(engine: DefaultRuleEngine): RuleEngine
    @Binds abstract fun bindsFormatIdentifier(identifier: DefaultFormatIdentifier): FormatIdentifier
    @Binds abstract fun bindsApkManifestReader(reader: AndroidApkManifestReader): ApkManifestReader
    @Binds abstract fun bindsPartExtractor(extractor: ApkPartExtractor): ExecutablePartExtractor
}
