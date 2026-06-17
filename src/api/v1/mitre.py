from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException

from src.services.mitre_mapping_service import MITREMappingService

router = APIRouter()


@router.get("/mappings")
async def get_mitre_mappings() -> List[Dict[str, Any]]:
    return MITREMappingService.list_mappings()


@router.get("/{technique_id}")
async def get_mitre_mapping(technique_id: str) -> Dict[str, Any]:
    mapping = MITREMappingService.get_mapping(technique_id)
    if not mapping:
        raise HTTPException(status_code=404, detail="MITRE technique not found")
    return mapping
