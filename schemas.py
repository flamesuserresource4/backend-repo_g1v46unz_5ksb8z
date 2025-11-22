"""
Database Schemas for HabitPilot SaaS

Each Pydantic model represents a collection in MongoDB.
Collection name is the lowercase of the class name.
"""
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List
from datetime import datetime

class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Email address")
    password_hash: str = Field(..., description="Password hash (bcrypt)")
    plan: str = Field("free", description="Subscription plan: free | pro")
    stripe_customer_id: Optional[str] = Field(None, description="Stripe customer ID")
    created_at: Optional[datetime] = None

class Habit(BaseModel):
    user_id: str = Field(..., description="Owner user _id as string")
    name: str = Field(..., description="Habit name")
    frequency: str = Field("daily", description="daily | weekly | custom")
    created_at: Optional[datetime] = None

class HabitLog(BaseModel):
    habit_id: str = Field(..., description="Habit _id as string")
    user_id: str = Field(..., description="Owner user _id as string")
    date: str = Field(..., description="ISO date, e.g., 2025-01-31")
    note: Optional[str] = None

class Subscription(BaseModel):
    user_id: str
    status: str = Field("inactive", description="active|inactive|canceled")
    plan: str = Field("free", description="free|pro")
    stripe_subscription_id: Optional[str] = None
    created_at: Optional[datetime] = None
