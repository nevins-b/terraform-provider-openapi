package openapi

import (
	"fmt"

	"github.com/go-openapi/spec"
)

type specV2Security struct {
	SecurityDefinitions spec.SecurityDefinitions
	GlobalSecurity      []map[string][]string
}

// GetAPIKeySecurityDefinitions returns a list of SpecSecurityDefinition after looping through the SecurityDefinitions
// and selecting only the SecurityDefinitions of type apiKey
func (s *specV2Security) GetAPIKeySecurityDefinitions() (*SpecSecurityDefinitions, error) {
	securityDefinitions := &SpecSecurityDefinitions{}
	for secDefName, secDef := range s.SecurityDefinitions {
		switch secDef.Type {
		case "apiKey":
			switch secDef.In {
			case "header":
				*securityDefinitions = append(*securityDefinitions, newAPIKeyHeaderSecurityDefinition(secDefName, secDef.Name))
			case "query":
				*securityDefinitions = append(*securityDefinitions, newAPIKeyQuerySecurityDefinition(secDefName, secDef.Name))
			default:
				return nil, fmt.Errorf("apiKey In value '%s' not supported, only 'header' and 'query' values are valid", secDef.In)
			}
		case "basic":
			*securityDefinitions = append(*securityDefinitions, newBasicAuthSecurityDefinition(secDefName))
		default:
			return nil, fmt.Errorf("'%s' not supported, only 'apiKey' and 'basic' values are valid", secDef.Type)
		}
	}
	return securityDefinitions, nil
}

// GetGlobalSecuritySchemes returns a list of SpecSecuritySchemes that have their corresponding SpecSecurityDefinition
func (s *specV2Security) GetGlobalSecuritySchemes() (SpecSecuritySchemes, error) {
	securitySchemes := createSecuritySchemes(s.GlobalSecurity)
	for _, securityScheme := range securitySchemes {
		secDef, err := s.GetAPIKeySecurityDefinitions()
		if err != nil {
			return SpecSecuritySchemes{}, nil
		}
		secDefFound := secDef.findSecurityDefinitionFor(securityScheme.Name)
		if secDefFound == nil {
			return nil, fmt.Errorf("global security scheme '%s' not found or not matching supported 'apiKey' type", securityScheme.Name)
		}
	}
	return securitySchemes, nil
}
