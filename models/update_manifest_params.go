// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// UpdateManifestParams update manifest params
//
// swagger:model update-manifest-params
type UpdateManifestParams struct {

	// The file name for the manifest to modify.
	// Required: true
	// Pattern: ^[^\/]*\.(json|ya?ml(\.patch_?[a-zA-Z0-9_]*)?)$
	FileName string `json:"file_name"`

	// The folder for the manifest to modify.
	// Required: true
	// Enum: [manifests openshift]
	Folder string `json:"folder"`

	// The new base64 encoded manifest content.
	UpdatedContent *string `json:"updated_content,omitempty"`

	// The new file name for the manifest.
	// Pattern: ^[^\/]*\.(json|ya?ml(\.patch_?[a-zA-Z0-9_]*)?)$
	UpdatedFileName *string `json:"updated_file_name,omitempty"`

	// The new folder for the manifest. Manifests can be placed in 'manifests' or 'openshift' directories.
	// Enum: [manifests openshift]
	UpdatedFolder *string `json:"updated_folder,omitempty"`
}

// Validate validates this update manifest params
func (m *UpdateManifestParams) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateFileName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateFolder(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUpdatedFileName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUpdatedFolder(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *UpdateManifestParams) validateFileName(formats strfmt.Registry) error {

	if err := validate.RequiredString("file_name", "body", m.FileName); err != nil {
		return err
	}

	if err := validate.Pattern("file_name", "body", m.FileName, `^[^\/]*\.(json|ya?ml(\.patch_?[a-zA-Z0-9_]*)?)$`); err != nil {
		return err
	}

	return nil
}

var updateManifestParamsTypeFolderPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["manifests","openshift"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		updateManifestParamsTypeFolderPropEnum = append(updateManifestParamsTypeFolderPropEnum, v)
	}
}

const (

	// UpdateManifestParamsFolderManifests captures enum value "manifests"
	UpdateManifestParamsFolderManifests string = "manifests"

	// UpdateManifestParamsFolderOpenshift captures enum value "openshift"
	UpdateManifestParamsFolderOpenshift string = "openshift"
)

// prop value enum
func (m *UpdateManifestParams) validateFolderEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, updateManifestParamsTypeFolderPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *UpdateManifestParams) validateFolder(formats strfmt.Registry) error {

	if err := validate.RequiredString("folder", "body", m.Folder); err != nil {
		return err
	}

	// value enum
	if err := m.validateFolderEnum("folder", "body", m.Folder); err != nil {
		return err
	}

	return nil
}

func (m *UpdateManifestParams) validateUpdatedFileName(formats strfmt.Registry) error {
	if swag.IsZero(m.UpdatedFileName) { // not required
		return nil
	}

	if err := validate.Pattern("updated_file_name", "body", *m.UpdatedFileName, `^[^\/]*\.(json|ya?ml(\.patch_?[a-zA-Z0-9_]*)?)$`); err != nil {
		return err
	}

	return nil
}

var updateManifestParamsTypeUpdatedFolderPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["manifests","openshift"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		updateManifestParamsTypeUpdatedFolderPropEnum = append(updateManifestParamsTypeUpdatedFolderPropEnum, v)
	}
}

const (

	// UpdateManifestParamsUpdatedFolderManifests captures enum value "manifests"
	UpdateManifestParamsUpdatedFolderManifests string = "manifests"

	// UpdateManifestParamsUpdatedFolderOpenshift captures enum value "openshift"
	UpdateManifestParamsUpdatedFolderOpenshift string = "openshift"
)

// prop value enum
func (m *UpdateManifestParams) validateUpdatedFolderEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, updateManifestParamsTypeUpdatedFolderPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *UpdateManifestParams) validateUpdatedFolder(formats strfmt.Registry) error {
	if swag.IsZero(m.UpdatedFolder) { // not required
		return nil
	}

	// value enum
	if err := m.validateUpdatedFolderEnum("updated_folder", "body", *m.UpdatedFolder); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this update manifest params based on context it is used
func (m *UpdateManifestParams) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *UpdateManifestParams) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *UpdateManifestParams) UnmarshalBinary(b []byte) error {
	var res UpdateManifestParams
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
