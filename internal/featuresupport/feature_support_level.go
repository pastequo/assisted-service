package featuresupport

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/go-openapi/swag"
	"github.com/hashicorp/go-version"
	"github.com/openshift/assisted-service/internal/common"
	"github.com/openshift/assisted-service/models"
	"github.com/thoas/go-funk"
)

var featuresList = map[models.FeatureSupportLevelID]SupportLevelFeature{
	// Generic features
	models.FeatureSupportLevelIDSNO:                       (&SnoFeature{}).New(),
	models.FeatureSupportLevelIDTNA:                       (&TnaFeature{}).New(),
	models.FeatureSupportLevelIDCUSTOMMANIFEST:            (&CustomManifestFeature{}).New(),
	models.FeatureSupportLevelIDSINGLENODEEXPANSION:       (&SingleNodeExpansionFeature{}).New(),
	models.FeatureSupportLevelIDMINIMALISO:                (&MinimalIso{}).New(),
	models.FeatureSupportLevelIDFULLISO:                   (&FullIso{}).New(),
	models.FeatureSupportLevelIDSKIPMCOREBOOT:             &skipMcoReboot{},
	models.FeatureSupportLevelIDNONSTANDARDHACONTROLPLANE: (&NonStandardHAControlPlane{}).New(),

	// Network features
	models.FeatureSupportLevelIDVIPAUTOALLOC:              (&VipAutoAllocFeature{}).New(),
	models.FeatureSupportLevelIDCLUSTERMANAGEDNETWORKING:  (&ClusterManagedNetworkingFeature{}).New(),
	models.FeatureSupportLevelIDUSERMANAGEDNETWORKING:     (&UserManagedNetworkingFeature{}).New(),
	models.FeatureSupportLevelIDDUALSTACKVIPS:             (&DualStackVipsFeature{}).New(),
	models.FeatureSupportLevelIDDUALSTACK:                 (&DualStackFeature{}).New(),
	models.FeatureSupportLevelIDPLATFORMMANAGEDNETWORKING: (&PlatformManagedNetworkingFeature{}).New(),
	models.FeatureSupportLevelIDSDNNETWORKTYPE:            (&SDNNetworkTypeFeature{}).New(),
	models.FeatureSupportLevelIDOVNNETWORKTYPE:            (&OVNNetworkTypeFeature{}).New(),
	models.FeatureSupportLevelIDUSERMANAGEDLOADBALANCER:   (&UserManagedLoadBalancerFeature{}).New(),

	// Olm Operators features
	models.FeatureSupportLevelIDLVM:                    (&LvmFeature{}).New(),
	models.FeatureSupportLevelIDCNV:                    (&CnvFeature{}).New(),
	models.FeatureSupportLevelIDLSO:                    (&LsoFeature{}).New(),
	models.FeatureSupportLevelIDMCE:                    (&MceFeature{}).New(),
	models.FeatureSupportLevelIDODF:                    (&OdfFeature{}).New(),
	models.FeatureSupportLevelIDMTV:                    (&MtvFeature{}).New(),
	models.FeatureSupportLevelIDOSC:                    (&OscFeature{}).New(),
	models.FeatureSupportLevelIDNODEFEATUREDISCOVERY:   (&NodeFeatureDiscoveryFeature{}).New(),
	models.FeatureSupportLevelIDNVIDIAGPU:              (&NvidiaGPUFeature{}).New(),
	models.FeatureSupportLevelIDPIPELINES:              (&PipelinesFeature{}).New(),
	models.FeatureSupportLevelIDSERVICEMESH:            (&ServiceMeshFeature{}).New(),
	models.FeatureSupportLevelIDSERVERLESS:             (&ServerLessFeature{}).New(),
	models.FeatureSupportLevelIDOPENSHIFTAI:            (&OpenShiftAIFeature{}).New(),
	models.FeatureSupportLevelIDAUTHORINO:              (&AuthorinoFeature{}).New(),
	models.FeatureSupportLevelIDNMSTATE:                (&NmstateFeature{}).New(),
	models.FeatureSupportLevelIDAMDGPU:                 (&AMDGPUFeature{}).New(),
	models.FeatureSupportLevelIDKMM:                    (&KMMFeature{}).New(),
	models.FeatureSupportLevelIDNODEHEALTHCHECK:        (&NodeHealthcheckFeature{}).New(),
	models.FeatureSupportLevelIDSELFNODEREMEDIATION:    (&SelfNodeRemediationFeature{}).New(),
	models.FeatureSupportLevelIDFENCEAGENTSREMEDIATION: (&FenceAgentsRemediationFeature{}).New(),
	models.FeatureSupportLevelIDNODEMAINTENANCE:        (&NodeMaintenanceFeature{}).New(),
	models.FeatureSupportLevelIDKUBEDESCHEDULER:        (&KubeDeschedulerFeature{}).New(),

	// Platform features
	models.FeatureSupportLevelIDNUTANIXINTEGRATION:  (&NutanixIntegrationFeature{}).New(),
	models.FeatureSupportLevelIDVSPHEREINTEGRATION:  (&VsphereIntegrationFeature{}).New(),
	models.FeatureSupportLevelIDEXTERNALPLATFORMOCI: (&OciIntegrationFeature{}).New(),
	models.FeatureSupportLevelIDBAREMETALPLATFORM:   (&BaremetalPlatformFeature{}).New(),
	models.FeatureSupportLevelIDNONEPLATFORM:        (&NonePlatformFeature{}).New(),
	models.FeatureSupportLevelIDEXTERNALPLATFORM:    (&ExternalPlatformFeature{}).New(),
}

func GetFeatureByID(featureID models.FeatureSupportLevelID) SupportLevelFeature {
	return featuresList[featureID]
}

func getFeatureSupportList(features map[models.FeatureSupportLevelID]SupportLevelFeature, filters SupportLevelFilters) models.SupportLevels {
	featureSupportList := models.SupportLevels{}

	for _, feature := range features {
		featureID := feature.getId()

		if !isFeatureCompatibleWithArchitecture(feature, filters.OpenshiftVersion, swag.StringValue(filters.CPUArchitecture)) {
			featureSupportList[string(featureID)] = models.SupportLevelUnavailable
		} else {
			featureSupportList[string(featureID)] = feature.getSupportLevel(filters)
		}
	}
	return featureSupportList
}

// removeEmptySupportLevel remove features with an empty support level value
// Currently in case of filtering features by <platform> we cannot return all other platforms in that list.
func removeEmptySupportLevel(supportLevels models.SupportLevels) {
	var featuresToRemove []string

	for featureId, supportLevel := range supportLevels {
		if string(supportLevel) == "" {
			featuresToRemove = append(featuresToRemove, featureId)
		}
	}

	for _, featureId := range featuresToRemove {
		delete(supportLevels, featureId)
	}
}

// GetFeatureSupportList Get features support level list, cpuArchitecture is optional and the default value is x86
func GetFeatureSupportList(openshiftVersion string, cpuArchitecture *string, platformType *models.PlatformType, externalPlatformName *string) models.SupportLevels {
	filters := SupportLevelFilters{
		OpenshiftVersion:     openshiftVersion,
		CPUArchitecture:      cpuArchitecture,
		PlatformType:         platformType,
		ExternalPlatformName: externalPlatformName,
	}

	if cpuArchitecture == nil {
		filters.CPUArchitecture = swag.String(common.DefaultCPUArchitecture)
	}
	featuresSupportList := overrideInvalidRequest(featuresList, *filters.CPUArchitecture, openshiftVersion)
	if featuresSupportList == nil {
		featuresSupportList = getFeatureSupportList(featuresList, filters)
	}

	// remove features that collide with the given filters
	removeEmptySupportLevel(featuresSupportList)

	return featuresSupportList
}

func sliceIntersect[T comparable](a, b []T) []T {
	ret := funk.Join(a, b, funk.InnerJoin)

	return ret.([]T)
}

func computeSupportLevelFilters(openshiftVersion string, cpuArchitecture string, featureIDs []models.FeatureSupportLevelID) (SupportLevelFilters, error) {
	ret := SupportLevelFilters{
		OpenshiftVersion: openshiftVersion,
		CPUArchitecture:  swag.String(cpuArchitecture),
	}

	// Set platform
	platforms := sliceIntersect(featureIDs, []models.FeatureSupportLevelID{
		models.FeatureSupportLevelIDBAREMETALPLATFORM,
		models.FeatureSupportLevelIDNONEPLATFORM,
		models.FeatureSupportLevelIDNUTANIXINTEGRATION,
		models.FeatureSupportLevelIDVSPHEREINTEGRATION,
		models.FeatureSupportLevelIDEXTERNALPLATFORM,
	})

	if len(platforms) != 1 {
		return ret, fmt.Errorf("platform feature must be set exactly once, here: %s", platforms)
	}

	var platform models.PlatformType

	switch platforms[0] {
	case models.FeatureSupportLevelIDBAREMETALPLATFORM:
		platform = models.PlatformTypeBaremetal
	case models.FeatureSupportLevelIDNONEPLATFORM:
		platform = models.PlatformTypeNone
	case models.FeatureSupportLevelIDNUTANIXINTEGRATION:
		platform = models.PlatformTypeNutanix
	case models.FeatureSupportLevelIDVSPHEREINTEGRATION:
		platform = models.PlatformTypeVsphere
	case models.FeatureSupportLevelIDEXTERNALPLATFORM:
		platform = models.PlatformTypeExternal
	}

	ret.PlatformType = &platform

	// Set external platform name
	externalPlatformNames := sliceIntersect(featureIDs, []models.FeatureSupportLevelID{
		models.FeatureSupportLevelIDEXTERNALPLATFORMOCI,
	})

	if len(externalPlatformNames) > 1 {
		return ret, fmt.Errorf("external platform name feature cannot be set multiple time, here: %s", externalPlatformNames)
	}

	if len(externalPlatformNames) == 1 {
		var externalPlatformName string

		switch externalPlatformNames[0] {
		case models.FeatureSupportLevelIDEXTERNALPLATFORMOCI:
			externalPlatformName = "oci"
		}

		ret.ExternalPlatformName = &externalPlatformName
	}

	return ret, nil
}

func GetFeatureSupports(ctx context.Context, openshiftVersion string, cpuArchitecture string, requireFeatureIDs []models.FeatureSupportLevelID) (models.FeatureSupports, error) {
	// First check all params are known
	_, err := version.NewVersion(openshiftVersion)
	if err != nil {
		return nil, fmt.Errorf("invalid openshift version: %w", err)
	}

	cpuArchitectureFeatureID, ok := cpuArchitectureFeatureIdMap[cpuArchitecture]
	if !ok {
		return nil, fmt.Errorf("unknown cpu architecture: %s", cpuArchitecture)
	}

	for _, featureID := range requireFeatureIDs {
		if _, ok := featuresList[models.FeatureSupportLevelID(featureID)]; !ok {
			return nil, fmt.Errorf("unknown feature id: %s", featureID)
		}
	}

	// A platform feature must be set
	filter, err := computeSupportLevelFilters(openshiftVersion, cpuArchitecture, requireFeatureIDs)
	if err != nil {
		return nil, err
	}

	// Then validate provided features are compatible with each other
	if _, ok := cpuFeaturesList[cpuArchitectureFeatureID]; !ok {
		// This should never happen
		return nil, fmt.Errorf("internal error about CPU Architecture Feature: %s", cpuArchitectureFeatureID)
	}

	if !isArchitectureSupported(cpuArchitectureFeatureID, openshiftVersion) {
		return nil, fmt.Errorf("cannot use %s architecture because it's not compatible on version %s of OpenShift", cpuArchitecture, openshiftVersion)
	}

	var featureCompatibilityError error
	for _, featureID := range requireFeatureIDs {
		feature := featuresList[models.FeatureSupportLevelID(featureID)]

		if !isFeatureCompatibleWithArchitecture(feature, openshiftVersion, cpuArchitecture) {
			featureCompatibilityError = errors.Join(
				featureCompatibilityError,
				fmt.Errorf("cannot use %s because it's not compatible with the %s architecture on version %s of OpenShift", featureID, cpuArchitecture, openshiftVersion),
			)

			continue
		}

		incompatibleFeatures := sliceIntersect(feature.getIncompatibleFeatures(openshiftVersion), requireFeatureIDs)
		if len(incompatibleFeatures) > 0 {
			featureCompatibilityError = errors.Join(
				featureCompatibilityError,
				fmt.Errorf("cannot use %s because it's not compatible with %s", featureID, incompatibleFeatures),
			)

			continue
		}
	}

	if featureCompatibilityError != nil {
		return nil, featureCompatibilityError
	}

	// Finally generate result
	ret := make(models.FeatureSupports, 0)
	for featureID, feature := range featuresList {
		id := featureID
		supportLevel := feature.getSupportLevel(filter)

		if supportLevel == "" {
			continue
		}

		feat := models.FeatureSupport{
			FeatureSupportLevelID: &id,
			Name:                  swag.String(feature.GetName()),
			SupportLevel:          &supportLevel,
		}

		isFeatureCompatibleWithArchitecture := isFeatureCompatibleWithArchitecture(feature, openshiftVersion, cpuArchitecture)
		if !isFeatureCompatibleWithArchitecture {
			feat.Reason = &models.FeatureSupportReason{
				InvalidCPUArchitecture: true,
			}
		}

		incompatibleFeatureIDs := sliceIntersect(feature.getIncompatibleFeatures(openshiftVersion), requireFeatureIDs)
		if len(incompatibleFeatureIDs) > 0 {
			if feat.Reason == nil {
				feat.Reason = &models.FeatureSupportReason{}
			}

			feat.Reason.IncompatibleFeatureIDs = incompatibleFeatureIDs
		}

		ret = append(ret, feat)
	}

	return ret, nil
}

// IsFeatureAvailable Get the support level of a given feature, cpuArchitecture is optional
// with default value of x86_64
func IsFeatureAvailable(featureId models.FeatureSupportLevelID, openshiftVersion string, cpuArchitecture *string) bool {
	filters := SupportLevelFilters{
		OpenshiftVersion: openshiftVersion,
		CPUArchitecture:  cpuArchitecture,
	}

	if cpuArchitecture == nil {
		filters.CPUArchitecture = swag.String(common.DefaultCPUArchitecture)
	}

	return GetSupportLevel(featureId, filters) != models.SupportLevelUnavailable
}

func isFeatureCompatible(openshiftVersion string, feature SupportLevelFeature, features ...SupportLevelFeature) *SupportLevelFeature {
	incompatibilities := feature.getIncompatibleFeatures(openshiftVersion)
	for _, f := range features {
		if slices.Contains(incompatibilities, f.getId()) {
			return &f
		}
	}

	return nil
}

// isFeaturesCompatibleWithFeatures Determine if feature is compatible with other activated features
func isFeaturesCompatibleWithFeatures(openshiftVersion string, activatedFeatures []SupportLevelFeature) error {
	for _, feature := range activatedFeatures {
		if incompatibleFeature := isFeatureCompatible(openshiftVersion, feature, activatedFeatures...); incompatibleFeature != nil {
			return fmt.Errorf("cannot use %s because it's not compatible with %s", feature.GetName(), (*incompatibleFeature).GetName())
		}
	}

	return nil
}

// isFeaturesCompatible Determine if feature is compatible with CPU architecture in a given openshift-version
func isFeaturesCompatible(openshiftVersion, cpuArchitecture string, activatedFeatures []SupportLevelFeature) error {
	for _, feature := range activatedFeatures {
		if !isFeatureCompatibleWithArchitecture(feature, openshiftVersion, cpuArchitecture) ||
			!IsFeatureAvailable(feature.getId(), openshiftVersion, swag.String(cpuArchitecture)) {
			return fmt.Errorf("cannot use %s because it's not compatible with the %s architecture "+
				"on version %s of OpenShift", feature.GetName(), cpuArchitecture, openshiftVersion)
		}
	}
	return nil
}
