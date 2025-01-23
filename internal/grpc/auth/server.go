package auth

import (
	"context"
	"errors"
	"fmt"
	ssov1 "github.com/SamEkb/protos/gen/go/sso"
	"github.com/go-playground/validator/v10"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"sso/internal/services/auth"
)

type Auth interface {
	Login(ctx context.Context,
		email string,
		password string,
		appID int,
	) (token string, err error)
	RegisterNewUser(ctx context.Context,
		email string,
		password string,
	) (userID int64, err error)
	IsAdmin(ctx context.Context, userID int64) (bool, error)
}

type LoginRequestValidation struct {
	Email    string `validate:"required,email"`
	Password string `validate:"required,min=6"`
	AppId    int32  `validate:"required,gt=0"`
}

type RegisterRequestValidation struct {
	Email    string `validate:"required,email"`
	Password string `validate:"required,min=6,max=32"`
}

type IsAdminRequestValidation struct {
	UserId int64 `validate:"required,gt=0"`
}

type serverAPI struct {
	ssov1.UnimplementedAuthServer
	auth Auth
}

const internalServerError = "internal server error"

var validate = validator.New()

func RegisterServer(gRPC *grpc.Server, auth Auth) {
	ssov1.RegisterAuthServer(gRPC, &serverAPI{auth: auth})
}

func (s *serverAPI) Login(ctx context.Context, req *ssov1.LoginRequest) (*ssov1.LoginResponse, error) {
	data := LoginRequestValidation{
		Email:    req.GetEmail(),
		Password: req.GetPassword(),
		AppId:    req.GetAppId(),
	}
	if err := validate.Struct(data); err != nil {
		validationErrors := formatValidationErrors(err)
		return nil, status.Errorf(codes.InvalidArgument, "validation error: %v", validationErrors)
	}

	token, err := s.auth.Login(ctx, req.GetEmail(), req.GetPassword(), int(req.GetAppId()))
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			return nil, status.Error(codes.InvalidArgument, "invalid email or password")
		}
		return nil, status.Error(codes.Internal, internalServerError)
	}

	return &ssov1.LoginResponse{Token: token}, nil
}

func (s *serverAPI) Register(ctx context.Context, req *ssov1.RegisterRequest) (*ssov1.RegisterResponse, error) {
	data := RegisterRequestValidation{
		Email:    req.GetEmail(),
		Password: req.GetPassword(),
	}
	if err := validate.Struct(data); err != nil {
		validationErrors := formatValidationErrors(err)
		return nil, status.Errorf(codes.InvalidArgument, "validation error: %v", validationErrors)
	}

	userID, err := s.auth.RegisterNewUser(ctx, req.GetEmail(), req.GetPassword())
	if err != nil {
		if errors.Is(err, auth.ErrUserExists) {
			return nil, status.Error(codes.AlreadyExists, "user already exists")
		}
		return nil, status.Error(codes.Internal, internalServerError)
	}

	return &ssov1.RegisterResponse{UserId: userID}, nil
}

func (s *serverAPI) IsAdmin(ctx context.Context, req *ssov1.IsAdminRequest) (*ssov1.IsAdminResponse, error) {
	data := IsAdminRequestValidation{UserId: req.GetUserId()}
	if err := validate.Struct(data); err != nil {
		validationErrors := formatValidationErrors(err)
		return nil, status.Errorf(codes.InvalidArgument, "validation error: %v", validationErrors)
	}

	isAdmin, err := s.auth.IsAdmin(ctx, req.GetUserId())
	if err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}

		return nil, status.Error(codes.Internal, internalServerError)
	}

	return &ssov1.IsAdminResponse{IsAdmin: isAdmin}, nil
}

func formatValidationErrors(err error) []string {
	validationErrors, ok := err.(validator.ValidationErrors)
	if !ok {
		return []string{"Invalid validation error type"}
	}

	var errors []string
	for _, vErr := range validationErrors {
		field := vErr.Field()
		tag := vErr.Tag()
		errors = append(errors, fmt.Sprintf("Field '%s' failed validation: %s", field, tag))
	}
	return errors
}
