from typing import Generator, Optional
import jwt
from fastapi import Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
import logging

from app.core.database import SessionLocal
from app.core.config import settings
from app.models.user import User
from app.schemas.token import TokenPayload

logger = logging.getLogger(__name__)

def get_db() -> Generator[Session, None, None]:
    """Get database session
    
    Yields:
        SQLAlchemy Session object
        
    Raises:
        Exception: If database connection fails
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def get_current_user(
    request: Request,
    db: Session = Depends(get_db)
) -> Optional[User]:
    """Get current user from JWT token in cookies
    
    Args:
        request: FastAPI request object
        db: Database session
        
    Returns:
        User object if authenticated
        
    Raises:
        HTTPException: If token is invalid or user not found
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        token = request.cookies.get("access_token")
        if not token:
            raise credentials_exception
            
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )
        token_data = TokenPayload(**payload)
        
        if token_data.sub is None:
            raise credentials_exception
            
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"}
        )
    except jwt.JWTError:
        raise credentials_exception
        
    user = db.query(User).filter(User.id == token_data.sub).first()
    if not user:
        raise credentials_exception
        
    return user

async def get_current_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """Verify user is authenticated and active
    
    Args:
        current_user: User object from get_current_user
        
    Returns:
        User object if active
        
    Raises:
        HTTPException: If user is inactive
    """
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user"
        )
    return current_user

async def get_current_admin_user(
    current_user: User = Depends(get_current_active_user)
) -> User:
    """Verify user is an admin
    
    Args:
        current_user: User object from get_current_active_user
        
    Returns:
        User object if admin
        
    Raises:
        HTTPException: If user is not an admin
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return current_user

async def verify_paid_user(
    current_user: User = Depends(get_current_active_user)
) -> User:
    """Verify user has available cards
    
    Args:
        current_user: User object from get_current_active_user
        
    Returns:
        User object if has available cards
        
    Raises:
        HTTPException: If no cards remaining
    """
    if current_user.cards_remaining <= 0:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail="No cards remaining. Please purchase more cards."
        )
    return current_user