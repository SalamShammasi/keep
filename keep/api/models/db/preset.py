from uuid import UUID, uuid4
from typing import Optional
from pydantic import BaseModel
from sqlmodel import JSON, Column, Field, SQLModel


class Preset(SQLModel, table=True):
    # Unique ID for each preset
    id: UUID = Field(default_factory=uuid4, primary_key=True)

    tenant_id: str = Field(foreign_key="tenant.id", index=True)

    # keeping index=True for better search
    created_by: Optional[str] = Field(index=True, nullable=False)
    is_private: Optional[bool] = Field(default=False)
    name: str = Field(unique=True)
    options: list = Field(sa_column=Column(JSON))  # [{"label": "", "value": ""}]


class PresetDto(BaseModel, extra="ignore"):
    id: UUID
    name: str
    options: list = []
    created_by: Optional[str] = None
    is_private: Optional[bool] = Field(default=False)


class PresetOption(BaseModel, extra="ignore"):
    label: str
    value: str
