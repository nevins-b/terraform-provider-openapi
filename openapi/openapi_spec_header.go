package openapi

import "github.com/dikhan/terraform-provider-openapi/openapi/terraformutils"

// SpecHeaderParameters groups a list of SpecHeaderParam
type SpecHeaderParameters []SpecHeaderParam

// SpecHeaderParam defines the properties for a Header Parameter
type SpecHeaderParam struct {
	Name          string
	TerraformName string
}

// GetHeaderTerraformConfigurationName returns the terraform compliant name of the header. If the header TerraformName
// field is populated it takes preference over the Name field.
func (h SpecHeaderParam) GetHeaderTerraformConfigurationName() string {
	if h.TerraformName != "" {
		return terraformutils.ConvertToTerraformCompliantName(h.TerraformName)
	}
	return terraformutils.ConvertToTerraformCompliantName(h.Name)
}
