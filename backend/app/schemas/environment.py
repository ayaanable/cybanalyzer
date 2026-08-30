from __future__ import annotations
from typing import Any, Literal
from pydantic import BaseModel, Field, model_validator

NodeKind = Literal["asset", "identity", "special"]

class Node(BaseModel):
    id: str
    name: str
    type: str
    kind: NodeKind = "asset"
    description: str = ""
    criticality: int = Field(ge=1, le=10)
    properties: dict[str, Any] = Field(default_factory=dict)

class Relationship(BaseModel):
    id: str
    source: str
    target: str
    type: str
    difficulty: int = Field(default=5, ge=1, le=10, description="10 means easiest")
    description: str = ""
    properties: dict[str, Any] = Field(default_factory=dict)

class Vulnerability(BaseModel):
    id: str
    asset_id: str
    name: str
    description: str = ""
    severity: float = Field(ge=0, le=10)
    exploitability: int = Field(ge=1, le=10)
    allows_initial_access: bool = False
    allows_privilege_escalation: bool = False
    mitre_technique: str | None = None

class Environment(BaseModel):
    id: str = "local-demo"
    name: str
    nodes: list[Node]
    relationships: list[Relationship]
    vulnerabilities: list[Vulnerability]

    @model_validator(mode="after")
    def validate_references(self):
        ids = {node.id for node in self.nodes}
        if len(ids) != len(self.nodes): raise ValueError("Node IDs must be unique")
        missing = {r.source for r in self.relationships if r.source not in ids} | {r.target for r in self.relationships if r.target not in ids}
        if missing: raise ValueError(f"Relationships reference missing nodes: {', '.join(sorted(missing))}")
        bad_assets = {v.asset_id for v in self.vulnerabilities if v.asset_id not in ids}
        if bad_assets: raise ValueError(f"Vulnerabilities reference missing assets: {', '.join(sorted(bad_assets))}")
        return self

class AnalysisRequest(BaseModel):
    entry_point: str
    target: str | None = None
    max_depth: int = Field(default=7, ge=1, le=12)

class WhatIfRequest(AnalysisRequest):
    remove_type: Literal["vulnerability", "relationship", "node"]
    remove_id: str
