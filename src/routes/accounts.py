from datetime import datetime, timedelta, timezone
import jwt
from jwt import PyJWTError
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from fastapi import status
from fastapi.responses import JSONResponse

from config import get_jwt_auth_manager
from database import get_db, ActivationTokenModel, UserGroupModel, UserGroupEnum, RefreshTokenModel
from exceptions import TokenExpiredError
from schemas import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    MessageResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshResponseSchema,
    TokenRefreshRequestSchema
)
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password
from database.models.accounts import UserModel, PasswordResetTokenModel


router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

SECRET_KEY = "mysecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED
)
async def create_user(
        user: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    existing_user = (
        await db.execute(select(UserModel)
                         .where(UserModel.email == user.email))
    ).scalar_one_or_none()
    if existing_user:
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user.email} already exists."
        )

    user_group = (
        await db.execute(select(UserGroupModel)
                         .where(UserGroupModel.name == UserGroupEnum.USER))
    ).scalar_one_or_none()
    if not user_group:
        raise HTTPException(
            status_code=500,
            detail="Default user group not found"
        )

    db_user = UserModel(email=user.email, group_id=user_group.id)
    db_user.password = hash_password(user.password)

    try:
        db.add(db_user)
        await db.commit()
        await db.refresh(db_user)

        activate_token = ActivationTokenModel(
            user_id=db_user.id,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24)
        )
        db.add(activate_token)
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user creation."
        )

    return UserRegistrationResponseSchema(
        id=db_user.id,
        email=db_user.email
    )


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK
)
async def activate_user(
        payload: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    activation_token = (
        await db.execute(
            select(ActivationTokenModel)
            .options(selectinload(ActivationTokenModel.user))
            .join(UserModel)
            .where(
                UserModel.email == payload.email,
                ActivationTokenModel.token == payload.token
            )
        )
    ).scalar_one_or_none()
    if not activation_token:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    expires_at_aware = activation_token.expires_at
    if expires_at_aware.tzinfo is None:
        expires_at_aware = expires_at_aware.replace(tzinfo=timezone.utc)

    if expires_at_aware < datetime.now(timezone.utc):
        await db.delete(activation_token)
        await db.commit()
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    user = activation_token.user
    if user.is_active:
        await db.delete(activation_token)
        await db.commit()
        raise HTTPException(
            status_code=400,
            detail="User account is already active."
        )

    user.is_active = True
    await db.delete(activation_token)
    await db.commit()
    await db.refresh(user)

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"message": "User account activated successfully."}
    )


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema
)
async def reset_password(
        payload: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    user = (
        await db.execute(select(UserModel)
                         .where(UserModel.email == payload.email))
    ).scalar_one_or_none()

    if user and user.is_active:
        tokens = (
            await db.execute(select(PasswordResetTokenModel)
                             .where(PasswordResetTokenModel.user_id == user.id))
        ).scalars().all()
        for token in tokens:
            db.delete(token)

        new_token = PasswordResetTokenModel(
            user_id=user.id,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        db.add(new_token)
        await db.commit()

    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    status_code=200
)
async def change_password(
        payload: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(UserModel)
        .where(UserModel.email == payload.email)
    )
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=400,
            detail="Invalid email or token."
        )

    result = await db.execute(
        select(PasswordResetTokenModel)
        .where(PasswordResetTokenModel.user_id == user.id)
    )
    tokens = result.scalars().all()
    token_obj = next((t for t in tokens if t.token == payload.token), None)

    if not token_obj or (
            token_obj.expires_at.replace(tzinfo=timezone.utc
                                         ) < datetime.now(timezone.utc)):
        for token in tokens:
            await db.delete(token)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    try:
        user.password = payload.password
        for token in tokens:
            await db.delete(token)
        await db.commit()
        await db.refresh(user)
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while resetting the password."
        )

    return MessageResponseSchema(
        message="Password reset successfully."
    )


@router.post(
    "/login/", response_model=UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED
)
async def login(
        payload: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    user = (
        await db.execute(select(UserModel)
                         .where(UserModel.email == payload.email))
    ).scalar_one_or_none()
    if not user or not user.verify_password(payload.password):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password."
        )

    if not user.is_active:
        raise HTTPException(
            status_code=403,
            detail="User account is not activated."
        )

    access_token = jwt_manager.create_access_token(
        data={"user_id": user.id}
    )
    refresh_token_str = jwt_manager.create_refresh_token(
        data={"user_id": user.id}
    )

    refresh_token = RefreshTokenModel(
        user_id=user.id,
        token=refresh_token_str
    )
    try:
        db.add(refresh_token)
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while processing the request."
        )

    return UserLoginResponseSchema(
        access_token=access_token,
        refresh_token=refresh_token.token,
        token_type="bearer"
    )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=status.HTTP_200_OK
)
async def refresh_token(
        payload: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        token_data = jwt_manager.decode_refresh_token(
            payload.refresh_token
        )
        user_id = token_data.get("user_id")
    except TokenExpiredError:
        raise HTTPException(
            status_code=400,
            detail="Token has expired."
        )
    except PyJWTError:
        raise HTTPException(
            status_code=400,
            detail="Invalid refresh token."
        )

    refresh_token = (
        await db.execute(select(RefreshTokenModel)
                         .where(RefreshTokenModel.token == payload.refresh_token))
    ).scalar_one_or_none()
    if not refresh_token:
        raise HTTPException(
            status_code=401,
            detail="Refresh token not found."
        )

    user = (
        await db.execute(select(UserModel)
                         .where(UserModel.id == refresh_token.user_id))
    ).scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found."
        )

    access_token = jwt_manager.create_access_token(
        data={"user_id": user_id}
    )
    return TokenRefreshResponseSchema(
        access_token=access_token,
        token_type="bearer"
    )
