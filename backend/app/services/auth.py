from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2AuthorizationCodeBearer
from google.oauth2 import id_token
from google.auth.transport import requests
from sqlalchemy.orm import Session
import httpx
import logging

from app.core.config import settings
from app.core.database import get_db
from app.crud import crud_user
from app.schemas.auth import TokenData
from ..models.user import User
from app.schemas.token import TokenPayload

logger = logging.getLogger(__name__)

# OAuth2 scheme for token authentication
oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl=f"https://accounts.google.com/o/oauth2/v2/auth?client_id={settings.GOOGLE_CLIENT_ID}&response_type=code&scope=email profile&redirect_uri={settings.GOOGLE_REDIRECT_URI}",
    tokenUrl="https://oauth2.googleapis.com/token"
)

def create_access_token(
    subject: str,
    expires_delta: Optional[timedelta] = None
) -> str:
    """Create JWT access token
    
    Args:
        subject: Token subject (usually user ID)
        expires_delta: Optional token expiration time
        
    Returns:
        Encoded JWT token string
    """
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )
        
    to_encode = {
        "exp": expire, 
        "sub": str(subject),
        "type": "access_token"
    }
    
    encoded_jwt = jwt.encode(
        to_encode,
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM
    )
    
    return encoded_jwt

async def verify_google_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Verify Google OAuth token and return user information.
    """
    try:
        idinfo = id_token.verify_oauth2_token(
            token,
            requests.Request(),
            settings.GOOGLE_CLIENT_ID,
            clock_skew_in_seconds=10
        )

        if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            raise ValueError('Invalid issuer')

        # Verify email is verified
        if not idinfo.get('email_verified'):
            raise ValueError('Email not verified')

        return {
            'email': idinfo['email'],
            'name': idinfo.get('name'),
            'picture': idinfo.get('picture')
        }
    except Exception as e:
        print(f"Error verifying Google token: {e}")
        return None

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    """
    Get the current authenticated user from the JWT token.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception

    user = crud_user.get_user_by_email(db, email=token_data.email)
    if user is None:
        raise credentials_exception

    return user

async def get_google_oauth_token(code: str) -> Dict[str, Any]:
    """Exchange authorization code for OAuth token from Google
    
    Args:
        code: Authorization code from Google OAuth flow
        
    Returns:
        Dict containing access token and other OAuth details
        
    Raises:
        HTTPException: If token exchange fails
    """
    try:
        token_url = "https://oauth2.googleapis.com/token"
        data = {
            "code": code,
            "client_id": settings.GOOGLE_CLIENT_ID,
            "client_secret": settings.GOOGLE_CLIENT_SECRET,
            "redirect_uri": f"{settings.FRONTEND_URL}/auth/callback",
            "grant_type": "authorization_code"
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(token_url, data=data)
            response.raise_for_status()
            return response.json()
        
    except httpx.RequestError as e:
        logger.error(f"Failed to get Google OAuth token: {str(e)}")
        raise HTTPException(
            status_code=400,
            detail="Failed to validate Google OAuth token"
        )

async def get_google_user_info(access_token: str) -> Dict[str, Any]:
    """Get user info from Google using OAuth access token
    
    Args:
        access_token: Valid Google OAuth access token
        
    Returns:
        Dict containing user profile information
        
    Raises:
        HTTPException: If user info request fails
    """
    try:
        userinfo_url = "https://www.googleapis.com/oauth2/v2/userinfo"
        headers = {"Authorization": f"Bearer {access_token}"}
        
        async with httpx.AsyncClient() as client:
            response = await client.get(userinfo_url, headers=headers)
            response.raise_for_status()
            return response.json()
        
    except httpx.RequestError as e:
        logger.error(f"Failed to get Google user info: {str(e)}")
        raise HTTPException(
            status_code=400, 
            detail="Failed to get user info from Google"
        )

async def create_or_update_user(
    db: Session,
    email: str,
    name: str,
    profile_image: Optional[str] = None
) -> User:
    """Create a new user or update existing user from Google profile
    
    Args:
        db: Database session
        email: User's email address
        name: User's full name
        profile_image: URL to user's profile image
        
    Returns:
        Created or updated User model instance
        
    Raises:
        HTTPException: If database operation fails
    """
    try:
        user = db.query(User).filter(User.email == email).first()
        
        if not user:
            # Create new user with 10 free cards
            user = User(
                email=email,
                name=name,
                profile_image=profile_image,
                cards_remaining=10
            )
            db.add(user)
            logger.info(f"Created new user: {email}")
        else:
            # Update existing user
            user.name = name
            user.profile_image = profile_image
            logger.info(f"Updated existing user: {email}")
            
        db.commit()
        db.refresh(user)
        return user
        
    except Exception as e:
        db.rollback()
        logger.error(f"Database error in create_or_update_user: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Failed to create/update user"
        )