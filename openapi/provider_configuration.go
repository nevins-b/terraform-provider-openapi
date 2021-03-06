package openapi

import (
	"fmt"
	"github.com/hashicorp/terraform/helper/schema"
)

// providerConfiguration contains all the configuration related to the OpenAPI provider. The configuration at the moment
// supports:
// - Headers: The headers map contains the header names as well as the values provided by the user in the terraform configuration
// file. These headers may be sent as part of the HTTP calls if the resource requires them (as specified in the swagger doc)
// - Security Definitions: The security definitions map contains the security definition names as well as the values provided by the user in the terraform configuration
// file. These headers may be sent as part of the HTTP calls if the resource requires them (as specified in the swagger doc)
type providerConfiguration struct {
	Headers                   map[string]string
	SecuritySchemaDefinitions map[string]specAPIKeyAuthenticator
}

// createProviderConfig returns a providerConfiguration populated with the values provided by the user in the provider's terraform
// configuration mapped to the corresponding
func newProviderConfiguration(headers SpecHeaderParameters, securitySchemaDefinitions *SpecSecurityDefinitions, data *schema.ResourceData) (*providerConfiguration, error) {
	providerConfiguration := &providerConfiguration{}
	providerConfiguration.Headers = map[string]string{}
	providerConfiguration.SecuritySchemaDefinitions = map[string]specAPIKeyAuthenticator{}

	if securitySchemaDefinitions != nil {
		for _, secDef := range *securitySchemaDefinitions {
			secDefTerraformCompliantName := secDef.getTerraformConfigurationName()
			if value, exists := data.GetOkExists(secDefTerraformCompliantName); exists {
				providerConfiguration.SecuritySchemaDefinitions[secDefTerraformCompliantName] = createAPIKeyAuthenticator(secDef, value.(string))
			} else {
				return nil, fmt.Errorf("security schema definition '%s' is missing the value, please make sure this value is provided in the terraform configuration", secDefTerraformCompliantName)
			}
		}
	}

	if headers != nil {
		for _, headerParam := range headers {
			headerTerraformCompliantName := headerParam.GetHeaderTerraformConfigurationName()
			if value, exists := data.GetOkExists(headerTerraformCompliantName); exists {
				providerConfiguration.Headers[headerTerraformCompliantName] = value.(string)
			} else {
				return nil, fmt.Errorf("header parameter '%s' is missing the value, please make sure this value is provided in the terraform configuration", headerTerraformCompliantName)
			}
		}
	}
	return providerConfiguration, nil
}

func (p *providerConfiguration) getAuthenticatorFor(s SpecSecurityScheme) specAPIKeyAuthenticator {
	securitySchemeConfigName := s.getTerraformConfigurationName()
	return p.SecuritySchemaDefinitions[securitySchemeConfigName]
}

func (p *providerConfiguration) getHeaderValueFor(s SpecHeaderParam) string {
	headerConfigName := s.GetHeaderTerraformConfigurationName()
	return p.Headers[headerConfigName]
}
