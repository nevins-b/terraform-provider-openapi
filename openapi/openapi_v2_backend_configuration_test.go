package openapi

import (
	"github.com/go-openapi/spec"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestNewOpenAPIBackendConfigurationV2(t *testing.T) {
	Convey("Given a swagger spec 2.0 and an openAPIDocumentURL", t, func() {
		spec := &spec.Swagger{
			SwaggerProps: spec.SwaggerProps{
				Swagger: "2.0",
			},
		}
		openAPIDocumentURL := "www.domain.com"
		Convey("When newOpenAPIBackendConfigurationV2 method is called", func() {
			specV2BackendConfiguration, err := newOpenAPIBackendConfigurationV2(spec, openAPIDocumentURL)
			Convey("Then the error returned should be  nil", func() {
				So(err, ShouldBeNil)
			})
			Convey("Then the providerClient should comply with SpecBackendConfiguration interface", func() {
				var _ SpecBackendConfiguration = specV2BackendConfiguration
			})
		})
	})

	Convey("Given a swagger spec that is not supported 3.0 and an openAPIDocumentURL", t, func() {
		spec := &spec.Swagger{
			SwaggerProps: spec.SwaggerProps{
				Swagger: "3.0",
			},
		}
		openAPIDocumentURL := "www.domain.com"
		Convey("When newOpenAPIBackendConfigurationV2 method is called", func() {
			_, err := newOpenAPIBackendConfigurationV2(spec, openAPIDocumentURL)
			Convey("Then the error returned should be NOT nil", func() {
				So(err, ShouldNotBeNil)
			})
			Convey("And the error message should be", func() {
				So(err.Error(), ShouldEqual, "swagger version '3.0' not supported, specV2BackendConfiguration only supports 2.0")
			})
		})
	})

	Convey("Given a swagger spec 2.0 and an empty openAPIDocumentURL", t, func() {
		spec := &spec.Swagger{
			SwaggerProps: spec.SwaggerProps{
				Swagger: "2.0",
			},
		}
		openAPIDocumentURL := ""
		Convey("When newOpenAPIBackendConfigurationV2 method is called", func() {
			_, err := newOpenAPIBackendConfigurationV2(spec, openAPIDocumentURL)
			Convey("Then the error returned should be NOT nil", func() {
				So(err, ShouldNotBeNil)
			})
			Convey("And the error message should be", func() {
				So(err.Error(), ShouldEqual, "missing mandatory parameter openAPIDocumentURL")
			})
		})
	})
}

func TestGetHost(t *testing.T) {
	Convey("Given a specV2BackendConfiguration with the host configured", t, func() {
		spec := &spec.Swagger{
			SwaggerProps: spec.SwaggerProps{
				Swagger: "2.0",
				Host:    "www.some-backend.com",
			},
		}
		openAPIDocumentURL := "www.domain.com"
		specV2BackendConfiguration, _ := newOpenAPIBackendConfigurationV2(spec, openAPIDocumentURL)
		Convey("When getHost method is called", func() {
			host, err := specV2BackendConfiguration.getHost()
			Convey("Then the error returned should be nil", func() {
				So(err, ShouldBeNil)
			})
			Convey("And the host should be correct", func() {
				So(host, ShouldEqual, "www.some-backend.com")
			})
		})
	})

	Convey("Given a specV2BackendConfiguration with the host not configured", t, func() {
		spec := &spec.Swagger{
			SwaggerProps: spec.SwaggerProps{
				Swagger: "2.0",
				Host:    "",
			},
		}
		openAPIDocumentURL := "www.domain.com"
		specV2BackendConfiguration, _ := newOpenAPIBackendConfigurationV2(spec, openAPIDocumentURL)
		Convey("When getHost method is called", func() {
			host, err := specV2BackendConfiguration.getHost()
			Convey("Then the error returned should be nil", func() {
				So(err, ShouldBeNil)
			})
			Convey("And the host should be the one where the swagger file is being served", func() {
				So(host, ShouldEqual, openAPIDocumentURL)
			})
		})
	})

	Convey("Given a specV2BackendConfiguration with the host not configured", t, func() {
		spec := &spec.Swagger{
			SwaggerProps: spec.SwaggerProps{
				Swagger: "2.0",
				Host:    "",
			},
		}
		specV2BackendConfiguration := specV2BackendConfiguration{spec: spec, openAPIDocumentURL: ""}
		Convey("When getHost method is called", func() {
			_, err := specV2BackendConfiguration.getHost()
			Convey("Then the error returned should NOT be nil", func() {
				So(err, ShouldNotBeNil)
			})
			Convey("And the error message should be", func() {
				So(err.Error(), ShouldEqual, "could not find valid host from URL provided: ''")
			})
		})
	})
}

func TestGetBasePath(t *testing.T) {
	Convey("Given a specV2BackendConfiguration with the basePath configured", t, func() {
		spec := &spec.Swagger{
			SwaggerProps: spec.SwaggerProps{
				Swagger:  "2.0",
				Host:     "www.some-backend.com",
				BasePath: "/api",
			},
		}
		openAPIDocumentURL := "www.domain.com"
		specV2BackendConfiguration, _ := newOpenAPIBackendConfigurationV2(spec, openAPIDocumentURL)
		Convey("When getBasePath method is called", func() {
			basePath := specV2BackendConfiguration.getBasePath()
			Convey("And the host should be correct", func() {
				So(basePath, ShouldEqual, "/api")
			})
		})
	})
}

func TestGetHTTPSchemes(t *testing.T) {
	Convey("Given a specV2BackendConfiguration with the getHTTPSchemes configured", t, func() {
		spec := &spec.Swagger{
			SwaggerProps: spec.SwaggerProps{
				Swagger:  "2.0",
				Host:     "www.some-backend.com",
				BasePath: "/api",
				Schemes:  []string{"http", "https"},
			},
		}
		openAPIDocumentURL := "www.domain.com"
		specV2BackendConfiguration, _ := newOpenAPIBackendConfigurationV2(spec, openAPIDocumentURL)
		Convey("When getHTTPSchemes method is called", func() {
			httpSchemes := specV2BackendConfiguration.getHTTPSchemes()
			Convey("And the host should be correct", func() {
				So(httpSchemes, ShouldContain, "http")
				So(httpSchemes, ShouldContain, "https")
			})
		})
	})
}
