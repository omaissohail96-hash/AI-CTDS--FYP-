from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException

from src.api import deps

from src.services.mitre_mapping_service import MITREMappingService

router = APIRouter()


@router.get("/mappings")
async def get_mitre_mappings(
    _: deps.AuthContext = Depends(deps.require_permissions("scans:read")),
) -> List[Dict[str, Any]]:
    return MITREMappingService.list_mappings()


@router.get("/{technique_id}")
async def get_mitre_mapping(
    technique_id: str,
    _: deps.AuthContext = Depends(deps.require_permissions("scans:read")),
) -> Dict[str, Any]:
    mapping = MITREMappingService.get_mapping(technique_id)
    if not mapping:
        raise HTTPException(status_code=404, detail="MITRE technique not found")
    return mapping
