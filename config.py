# config.py
import os

class Config:
    # libvirt接続
    LIBVIRT_URI = os.getenv('LIBVIRT_URI', 'qemu:///system')

    # ストレージ
    IMAGES_DIR = os.getenv('IMAGES_DIR', '/var/lib/libvirt/images')
    DEFAULT_BRIDGE = os.getenv('DEFAULT_BRIDGE', 'br0')

    # 認証（OIDC/JWT）
    OIDC_ISSUER = os.getenv('OIDC_ISSUER', '')            # 例: https://keycloak.example/realms/myrealm
    OIDC_AUDIENCE = os.getenv('OIDC_AUDIENCE', 'vmapp')
    OIDC_JWKS_URL = os.getenv('OIDC_JWKS_URL', '')        # 例: https://.../.well-known/jwks.json
    REQUIRE_AUTH = os.getenv('REQUIRE_AUTH', 'true').lower() == 'true'

    # RBAC（ロール名）
    ROLES_ADMIN = set(os.getenv('ROLES_ADMIN', 'admin').split(','))
    ROLES_OPERATOR = set(os.getenv('ROLES_OPERATOR', 'ops').split(','))
    ROLES_VIEWER = set(os.getenv('ROLES_VIEWER', 'viewer').split(','))

    # console URL base（Nginxの設定に合わせる）
    NOVNC_PUBLIC_BASE = os.getenv('NOVNC_PUBLIC_BASE', '/vnc')

    # セーフガード
    ALLOW_DISK_DELETE = os.getenv('ALLOW_DISK_DELETE', 'true').lower() == 'true'
