"""User profile-related Pydantic schemas."""

from pydantic import BaseModel, EmailStr, Field


class UserUpdate(BaseModel):
    """Schema for updating user profile."""

    email: EmailStr | None = Field(None, description="User email address")
    username: str | None = Field(None, min_length=3, max_length=100, description="Username")
    full_name: str | None = Field(None, max_length=255, description="Full name")


class PasswordChange(BaseModel):
    """Schema for changing user password."""

    current_password: str = Field(..., description="Current password")
    new_password: str = Field(..., min_length=8, description="New password (minimum 8 characters)")
