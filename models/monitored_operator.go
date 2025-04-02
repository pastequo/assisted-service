// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
	"github.com/lib/pq"
)

// MonitoredOperator monitored operator
//
// swagger:model monitored-operator
type MonitoredOperator struct {

	// List of identifier of the bundles associated with the operator. Can be empty.
	Bundles pq.StringArray `json:"bundles" gorm:"type:text[]"`

	// The cluster that this operator is associated with.
	// Format: uuid
	ClusterID strfmt.UUID `json:"cluster_id,omitempty" gorm:"primaryKey"`

	// Wether the operator can't be installed without being required by another operator.
	DependencyOnly bool `json:"dependency_only,omitempty"`

	// Unique name of the operator.
	Name string `json:"name,omitempty" gorm:"primaryKey"`

	// Namespace where to deploy an operator. Only some operators require a namespace.
	Namespace string `json:"namespace,omitempty"`

	// operator type
	OperatorType OperatorType `json:"operator_type,omitempty"`

	// Blob of operator-dependent parameters that are required for installation.
	Properties string `json:"properties,omitempty" gorm:"type:text"`

	// status
	Status OperatorStatus `json:"status,omitempty"`

	// Detailed information about the operator state.
	StatusInfo string `json:"status_info,omitempty"`

	// Time at which the operator was last updated.
	// Format: date-time
	StatusUpdatedAt strfmt.DateTime `json:"status_updated_at,omitempty" gorm:"type:timestamp with time zone"`

	// The name of the subscription of the operator.
	SubscriptionName string `json:"subscription_name,omitempty"`

	// Positive number represents a timeout in seconds for the operator to be available.
	TimeoutSeconds int64 `json:"timeout_seconds,omitempty"`

	// Operator version
	Version string `json:"version,omitempty"`
}

// Validate validates this monitored operator
func (m *MonitoredOperator) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateClusterID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateOperatorType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateStatus(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateStatusUpdatedAt(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *MonitoredOperator) validateClusterID(formats strfmt.Registry) error {
	if swag.IsZero(m.ClusterID) { // not required
		return nil
	}

	if err := validate.FormatOf("cluster_id", "body", "uuid", m.ClusterID.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *MonitoredOperator) validateOperatorType(formats strfmt.Registry) error {
	if swag.IsZero(m.OperatorType) { // not required
		return nil
	}

	if err := m.OperatorType.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("operator_type")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("operator_type")
		}
		return err
	}

	return nil
}

func (m *MonitoredOperator) validateStatus(formats strfmt.Registry) error {
	if swag.IsZero(m.Status) { // not required
		return nil
	}

	if err := m.Status.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("status")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("status")
		}
		return err
	}

	return nil
}

func (m *MonitoredOperator) validateStatusUpdatedAt(formats strfmt.Registry) error {
	if swag.IsZero(m.StatusUpdatedAt) { // not required
		return nil
	}

	if err := validate.FormatOf("status_updated_at", "body", "date-time", m.StatusUpdatedAt.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this monitored operator based on the context it is used
func (m *MonitoredOperator) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateOperatorType(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateStatus(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *MonitoredOperator) contextValidateOperatorType(ctx context.Context, formats strfmt.Registry) error {

	if err := m.OperatorType.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("operator_type")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("operator_type")
		}
		return err
	}

	return nil
}

func (m *MonitoredOperator) contextValidateStatus(ctx context.Context, formats strfmt.Registry) error {

	if err := m.Status.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("status")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("status")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *MonitoredOperator) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *MonitoredOperator) UnmarshalBinary(b []byte) error {
	var res MonitoredOperator
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
