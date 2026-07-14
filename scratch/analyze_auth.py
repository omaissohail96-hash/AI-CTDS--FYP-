import ast
import os
from pathlib import Path

def analyze_file(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()
    
    tree = ast.parse(content)
    
    missing = []
    
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Check if it has a decorator starting with router.
            is_route = False
            for decorator in node.decorator_list:
                if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute):
                    if isinstance(decorator.func.value, ast.Name) and decorator.func.value.id == "router":
                        is_route = True
            
            if is_route:
                # Check for dependencies
                has_auth = False
                for arg in node.args.args + getattr(node.args, "kwonlyargs", []):
                    if arg.annotation and isinstance(arg.annotation, ast.Name) and arg.annotation.id == "User":
                        # Usually something like current_user: User = Depends(require_permissions(...))
                        has_auth = True
                    # Let's check the default value which is the Depends call
                
                # Check default values
                for default in node.args.defaults + getattr(node.args, "kw_defaults", []):
                    if default and isinstance(default, ast.Call) and getattr(default.func, "id", "") == "Depends":
                        dep_name = ""
                        if default.args:
                            dep_arg = default.args[0]
                            if isinstance(dep_arg, ast.Call):
                                if getattr(dep_arg.func, "id", "") in ["require_permissions", "RequirePermissions", "require_roles", "RequireRoles"]:
                                    has_auth = True
                            elif isinstance(dep_arg, ast.Name):
                                if getattr(dep_arg, "id", "") in ["get_current_user", "get_current_workspace"]:
                                    has_auth = True
                
                if not has_auth:
                    missing.append(node.name)
    
    return missing

api_dir = Path("c:/Users/Farooq/Desktop/Final_Year_Project/src/api/v1")
for root, _, files in os.walk(api_dir):
    for file in files:
        if file.endswith(".py") and not file.startswith("__"):
            filepath = os.path.join(root, file)
            missing = analyze_file(filepath)
            if missing:
                print(f"{os.path.relpath(filepath, api_dir)}: {missing}")
