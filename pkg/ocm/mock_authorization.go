// Code generated by MockGen. DO NOT EDIT.
// Source: authorization.go

// Package ocm is a generated GoMock package.
package ocm

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
)

// MockOCMAuthorization is a mock of OCMAuthorization interface
type MockOCMAuthorization struct {
	ctrl     *gomock.Controller
	recorder *MockOCMAuthorizationMockRecorder
}

// MockOCMAuthorizationMockRecorder is the mock recorder for MockOCMAuthorization
type MockOCMAuthorizationMockRecorder struct {
	mock *MockOCMAuthorization
}

// NewMockOCMAuthorization creates a new mock instance
func NewMockOCMAuthorization(ctrl *gomock.Controller) *MockOCMAuthorization {
	mock := &MockOCMAuthorization{ctrl: ctrl}
	mock.recorder = &MockOCMAuthorizationMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockOCMAuthorization) EXPECT() *MockOCMAuthorizationMockRecorder {
	return m.recorder
}

// AccessReview mocks base method
func (m *MockOCMAuthorization) AccessReview(ctx context.Context, username, action, resourceType string) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AccessReview", ctx, username, action, resourceType)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AccessReview indicates an expected call of AccessReview
func (mr *MockOCMAuthorizationMockRecorder) AccessReview(ctx, username, action, resourceType interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AccessReview", reflect.TypeOf((*MockOCMAuthorization)(nil).AccessReview), ctx, username, action, resourceType)
}

// CapabilityReview mocks base method
func (m *MockOCMAuthorization) CapabilityReview(ctx context.Context, username, capabilityName, capabilityType string) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CapabilityReview", ctx, username, capabilityName, capabilityType)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CapabilityReview indicates an expected call of CapabilityReview
func (mr *MockOCMAuthorizationMockRecorder) CapabilityReview(ctx, username, capabilityName, capabilityType interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CapabilityReview", reflect.TypeOf((*MockOCMAuthorization)(nil).CapabilityReview), ctx, username, capabilityName, capabilityType)
}
