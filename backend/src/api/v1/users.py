"""User profile management API endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...db import User, get_db
from ...security import CurrentUser, hash_password, verify_password
from ..schemas.auth import UserResponse
from ..schemas.user import PasswordChange, UserUpdate

router = APIRouter()


@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(
    current_user: CurrentUser,
) -> User:
    """
    Get current user's profile information.

    Args:
        current_user: Current authenticated user (from JWT token)

    Returns:
        Current user object

    Raises:
        HTTPException: 401 if not authenticated
    """
    return current_user


@router.put("/me", response_model=UserResponse)
async def update_current_user_profile(
    user_update: UserUpdate,
    current_user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> User:
    """
    Update current user's profile information.

    Args:
        user_update: User profile update data
        current_user: Current authenticated user
        db: Database session

    Returns:
        Updated user object

    Raises:
        HTTPException: 400 if email/username already taken
    """
    # Check if email is being updated and if it's already taken
    if user_update.email is not None and user_update.email != current_user.email:
        result = await db.execute(select(User).where(User.email == user_update.email))
        if result.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered",
            )
        current_user.email = user_update.email

    # Check if username is being updated and if it's already taken
    if user_update.username is not None and user_update.username != current_user.username:
        result = await db.execute(select(User).where(User.username == user_update.username))
        if result.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already taken",
            )
        current_user.username = user_update.username

    # Update full_name if provided
    if user_update.full_name is not None:
        current_user.full_name = user_update.full_name

    # Commit changes
    await db.commit()
    await db.refresh(current_user)

    return current_user


@router.put("/me/password", status_code=status.HTTP_200_OK)
async def change_password(
    password_change: PasswordChange,
    current_user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, str]:
    """
    Change current user's password.

    Args:
        password_change: Password change data (current and new password)
        current_user: Current authenticated user
        db: Database session

    Returns:
        Success message

    Raises:
        HTTPException: 400 if current password is incorrect
    """
    # Verify current password
    if not verify_password(password_change.current_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )

    # Update password
    current_user.hashed_password = hash_password(password_change.new_password)

    # Commit changes
    await db.commit()

    return {"message": "Password updated successfully"}
