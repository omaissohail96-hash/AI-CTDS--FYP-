from src.core.database import SessionLocal
from src.models.models import Role, Permission, RolePermission

ROLES = [
    "Super Admin",
    "Organization Admin",
    "SOC Manager",
    "Security Analyst",
    "Auditor",
    "Viewer",
    "API Client"
]

PERMISSIONS = [
    "scan:create",
    "scan:view",
    "alerts:view",
    "alerts:manage",
    "reports:download",
    "users:create",
    "users:delete",
    "settings:update",
    "apikey:create",
    "apikey:delete",
    "mfa:manage",
    "all" # Super admin wildcard
]

ROLE_MAP = {
    "Super Admin": ["all"],
    "Organization Admin": ["scan:create", "scan:view", "alerts:view", "alerts:manage", "reports:download", "users:create", "users:delete", "settings:update", "apikey:create", "apikey:delete", "mfa:manage"],
    "SOC Manager": ["scan:create", "scan:view", "alerts:view", "alerts:manage", "reports:download", "settings:update"],
    "Security Analyst": ["scan:create", "scan:view", "alerts:view", "alerts:manage"],
    "Auditor": ["scan:view", "alerts:view", "reports:download"],
    "Viewer": ["scan:view", "alerts:view"],
    "API Client": ["scan:create", "scan:view", "alerts:view", "reports:download"]
}

def seed_rbac():
    db = SessionLocal()
    
    try:
        # Create permissions
        perm_objs = {}
        for p in PERMISSIONS:
            perm = db.query(Permission).filter(Permission.name == p).first()
            if not perm:
                perm = Permission(name=p, description=f"Permission for {p}")
                db.add(perm)
                db.commit()
                db.refresh(perm)
            perm_objs[p] = perm

        # Create roles and mappings
        for r_name in ROLES:
            role = db.query(Role).filter(Role.name == r_name).first()
            if not role:
                role = Role(name=r_name, description=f"{r_name} Role")
                db.add(role)
                db.commit()
                db.refresh(role)
                
            # Create mappings
            allowed_perms = ROLE_MAP.get(r_name, [])
            for p_name in allowed_perms:
                perm_id = perm_objs[p_name].id
                mapping = db.query(RolePermission).filter(
                    RolePermission.role_id == role.id,
                    RolePermission.permission_id == perm_id
                ).first()
                if not mapping:
                    mapping = RolePermission(role_id=role.id, permission_id=perm_id)
                    db.add(mapping)
            db.commit()
            
        print("RBAC Database Seeding Completed Successfully.")
        
    except Exception as e:
        db.rollback()
        print(f"Failed to seed RBAC: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    seed_rbac()
