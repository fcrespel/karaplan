package me.crespel.karaplan;

import static com.tngtech.archunit.base.DescribedPredicate.alwaysTrue;
import static com.tngtech.archunit.core.domain.JavaClass.Predicates.resideInAPackage;
import static com.tngtech.archunit.library.Architectures.layeredArchitecture;
import static com.tngtech.archunit.library.dependencies.SlicesRuleDefinition.slices;

import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

@AnalyzeClasses(packages = ArchitectureTest.ROOT, importOptions = ImportOption.DoNotIncludeTests.class)
public class ArchitectureTest {

	public static final String ROOT = "me.crespel.karaplan";

	@ArchTest
	static final ArchRule layersShouldBeRespected = layeredArchitecture()
		.consideringOnlyDependenciesInLayers()
		.layer("Domain").definedBy(ROOT + ".domain..")
		.layer("Model").definedBy(ROOT + ".model..")
		.layer("Repository").definedBy(ROOT + ".repository..")
		.layer("Service").definedBy(ROOT + ".service..")
		.layer("Web").definedBy(ROOT + ".web..")
		.whereLayer("Web").mayNotBeAccessedByAnyLayer()
		.whereLayer("Service").mayOnlyBeAccessedByLayers("Web")
		.whereLayer("Repository").mayOnlyBeAccessedByLayers("Service")
		.whereLayer("Domain").mayOnlyBeAccessedByLayers("Web", "Service", "Repository")
		.whereLayer("Model").mayOnlyBeAccessedByLayers("Web", "Service");

	@ArchTest
	static final ArchRule noPackageCycles = slices()
		.matching(ROOT + ".(*)..").should().beFreeOfCycles()
		.ignoreDependency(resideInAPackage(ROOT + ".config.."), alwaysTrue())
		.as("Application packages must be free of dependency cycles");

}
